"""Reviewed JSON configuration for local tools, fixed HTTPS tools and Anthropic tasks.

Only credentials supplied by the host mapping are accessible. No manifest value is
Python code, an environment variable name, or a dynamically selected network host.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import re
import ssl
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any
from urllib.parse import urlencode, urlsplit

from .adapters.anthropic_tools import APPROVAL_REQUIRED, ToolBinding
from .architecture import ArchitectureGraph, CompiledArchitecture, TaskTransport
from .canonical import canonical_digest, canonical_json
from .egress import EgressRequest, PinnedSocketEgressBackend, canonical_network_destination
from .gateway import GatewayError
from .managed_runtime import build_managed_tools
from .models import ActorType, InvocationIntent, PolicyMode, SideEffect, ToolDefinition
from .orchestration import CallableTaskAdapter, TaskExecutionInput, TaskExecutionResult
from .provider_clients import openai_payload, openai_request
from .provider_policy import (
    MODEL_KINDS,
    PROVIDER_ENDPOINTS,
    ProviderCallError,
    call_with_policy,
    classify_error,
    provider_candidates,
    validate_provider_policy,
)
from .sdk import Interlock

RUNTIME_KEY = "interlock.runtime"
MAX_BYTES = 1_048_576
_PATH = re.compile(r"(?:arguments|input|dependencies)(?:\.[A-Za-z0-9_-]+){0,24}\Z")


def map_json(template: Any, context: Mapping[str, Any], *, _depth: int = 0,
             _validate_only: bool = False, _budget: list[int] | None = None) -> Any:
    """Copy JSON; the sole operator is an exact {$path: 'input.some.key'} object."""
    if _budget is None:
        _budget = [MAX_BYTES]
    _budget[0] -= 1
    if _budget[0] < 0:
        raise ValueError("JSON mapping exceeds 1 MiB")
    if _depth > 32:
        raise ValueError("JSON mapping exceeds 32 levels")
    if isinstance(template, dict):
        if "$path" in template:
            path = template["$path"]
            if len(template) != 1 or not isinstance(path, str) or not _PATH.fullmatch(path):
                raise ValueError("invalid JSON mapping path")
            if _validate_only:
                return None
            value: Any = context
            for part in path.split("."):
                if isinstance(value, Mapping) and part in value:
                    value = value[part]
                elif isinstance(value, list) and part.isdecimal() and int(part) < len(value):
                    value = value[int(part)]
                else:
                    raise ValueError(f"JSON mapping path is missing: {path}")
            encoded = canonical_json(value)
            _budget[0] -= len(encoded)
            if _budget[0] < 0:
                raise ValueError("JSON mapping exceeds 1 MiB")
            return json.loads(encoded)
        return {key: map_json(value, context, _depth=_depth + 1, _validate_only=_validate_only, _budget=_budget)
                for key, value in template.items()}
    if isinstance(template, list):
        return [map_json(value, context, _depth=_depth + 1, _validate_only=_validate_only, _budget=_budget)
                for value in template]
    if template is None or isinstance(template, (str, int, float, bool)):
        _budget[0] -= len(canonical_json(template))
        if _budget[0] < 0:
            raise ValueError("JSON mapping exceeds 1 MiB")
        return template
    raise ValueError("mapping must be JSON")


def _endpoint(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 33 for c in value):
        raise ValueError("endpoint must be a fixed HTTPS URL")
    parsed = urlsplit(value)
    canonical_network_destination(f"{parsed.scheme}://{parsed.netloc}")
    if parsed.query or parsed.fragment:
        raise ValueError("endpoint cannot contain a query or fragment")
    return value


def _config(node) -> dict[str, Any] | None:
    actor = node.actor
    value = node.annotations.get(RUNTIME_KEY)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("interlock.runtime must be an object")
    config = dict(value)
    kind = config.get("kind")
    common = {"kind", "purpose", "dataClasses", "credentialRef"}
    fields = {
        "JSON_TRANSFORM": common | {"template", "arguments"},
        "HTTP_JSON": common | {"endpoint", "method", "arguments"},
        "ANTHROPIC": common | {"model", "systemPrompt", "maxTokens", "maxSteps", "providerActorId", "toolActorIds",
                               "providerPolicy"},
        "OPENAI": common | {"model", "systemPrompt", "maxTokens", "maxSteps", "providerActorId", "toolActorIds",
                            "providerPolicy"},
    }
    if not isinstance(kind, str) or kind not in fields or set(config) - fields[kind]:
        raise ValueError("unsupported runtime kind or configuration field")
    if kind in MODEL_KINDS:
        if actor.type not in {ActorType.AGENT, ActorType.SUBAGENT}:
            raise ValueError("model runtime requires an agent")
        for key in ("model", "credentialRef", "providerActorId", "purpose"):
            if not isinstance(config.get(key), str) or not config[key].strip():
                raise ValueError(f"{key} is required")
        if "toolActorIds" in config:
            tool_ids = config["toolActorIds"]
            if (not isinstance(tool_ids, list) or not 1 <= len(tool_ids) <= 20
                    or any(not isinstance(item, str) or not item.strip() or len(item) > 256 for item in tool_ids)
                    or len(set(tool_ids)) != len(tool_ids)):
                raise ValueError("toolActorIds must contain 1 to 20 unique actor IDs up to 256 characters")
        if not isinstance(config.get("systemPrompt"), str) or len(config["systemPrompt"]) > 32000:
            raise ValueError("systemPrompt must be a string up to 32000 characters")
        for key, maximum in (("maxTokens", 8192), ("maxSteps", 20)):
            if type(config.get(key)) is not int or not 1 <= config[key] <= maximum:
                raise ValueError(f"{key} must be between 1 and {maximum}")
        validate_provider_policy(config)
    else:
        if actor.type != ActorType.TOOL:
            raise ValueError("tool runtime requires a TOOL actor")
        if not isinstance(config.get("purpose"), str) or not config["purpose"]:
            raise ValueError("purpose is required")
        if ((kind == "JSON_TRANSFORM" or config.get("method") == "GET")
                and SideEffect.READ not in actor.side_effects):
            raise ValueError("JSON transforms and HTTP GET require the READ side effect")
        if kind == "JSON_TRANSFORM" and "template" not in config:
            raise ValueError("JSON_TRANSFORM template is required")
        if kind == "JSON_TRANSFORM" and "credentialRef" in config:
            raise ValueError("JSON_TRANSFORM cannot use credentials")
        if kind == "HTTP_JSON":
            _endpoint(config.get("endpoint"))
            if not isinstance(config.get("method"), str) or config["method"] not in {"GET", "POST"}:
                raise ValueError("HTTP_JSON method must be GET or POST")
            if not actor.allowed_domains or urlsplit(config["endpoint"]).hostname not in actor.allowed_domains:
                raise ValueError("endpoint host must be in actor allowedDomains")
            if config["method"] == "POST" and not actor.side_effects & {
                SideEffect.EXTERNAL_WRITE, SideEffect.DESTRUCTIVE_WRITE, SideEffect.PAYMENT,
                SideEffect.PERMISSION_CHANGE,
            }:
                raise ValueError("HTTP POST requires a declared external side effect")
    classes = config.get("dataClasses")
    if (not isinstance(classes, list) or not classes
            or any(not isinstance(c, str) or c not in {f"D{i}" for i in range(1, 9)} for c in classes)):
        raise ValueError("dataClasses must be a nonempty list of D1..D8")
    if "credentialRef" in config and (not isinstance(config["credentialRef"], str) or not config["credentialRef"]):
        raise ValueError("credentialRef must be a host credential reference")
    for key in ("template", "arguments"):
        if key in config:
            map_json(config[key], {}, _validate_only=True)
    if not frozenset(classes) <= actor.data_access:
        raise ValueError("runtime dataClasses must be permitted by actor dataAccess")
    if len(canonical_json(config)) > MAX_BYTES:
        raise ValueError("runtime configuration is too large")
    return config


def configured_definition(node) -> ToolDefinition:
    actor = node.actor
    config = _config(node)
    if config is None or config["kind"] in MODEL_KINDS:
        raise ValueError(f"tool runtime is missing for {actor.id}")
    annotations = dict(node.annotations)
    annotations.pop("interlock.fixedDestinations", None)
    annotations.pop("readOnlyHint", None)
    annotations.pop("destructiveHint", None)
    if config["kind"] == "JSON_TRANSFORM" or config["method"] == "GET":
        annotations["readOnlyHint"] = True
    if config["kind"] == "HTTP_JSON":
        annotations["interlock.fixedDestinations"] = [config["endpoint"]]
    return ToolDefinition(
        server_id="interlock-configured", tool_name="tool_" + canonical_digest(actor.id).split(":")[1][:24],
        title=actor.id, description=f"Run the reviewed {config['kind']} configuration for {actor.id}.",
        input_schema=actor.input_schema, output_schema=actor.output_schema, annotations=annotations,
        endpoint=config.get("endpoint", ""), transport="https" if config["kind"] == "HTTP_JSON" else "local",
        publisher="interlock-configured-runtime", artifact_digest=canonical_digest(config),
    )


def prepare_runtime_graph(graph: ArchitectureGraph) -> ArchitectureGraph:
    nodes = []
    for node in graph.nodes:
        config = _config(node)
        if config is not None and node.actor.type == ActorType.TOOL:
            node = replace(node, actor=replace(node.actor, definition_digest=canonical_digest(
                configured_definition(node).canonical_value())))
        nodes.append(node)
    return replace(graph, nodes=tuple(nodes))


def _task_problems(graph, configs, task, credential_refs):
    actors = {node.id: node.actor for node in graph.nodes}
    problems = []
    config, source = configs.get(task.target_actor_id), configs.get(task.source_actor_id)
    if task.source_actor_id not in actors:
        problems.append("task source actor is missing")
    if task.transport != TaskTransport.LOCAL:
        problems.append("only LOCAL tasks are supported by this host")
    if not config or config["kind"] in MODEL_KINDS:
        problems.append("task requires a configured tool target")
    else:
        if task.purpose != config["purpose"] or task.data_classes != frozenset(config["dataClasses"]):
            problems.append("task purpose/dataClasses must match its reviewed tool runtime")
    invokes = [edge for edge in graph.edges if edge.source == task.source_actor_id
               and edge.target == task.target_actor_id and edge.relationship_id == "REL-05"]
    if len(invokes) != 1:
        problems.append("task requires one reviewed REL-05 source-to-tool edge")
    elif (task.purpose not in invokes[0].policy.allowed_purposes
          or not task.data_classes <= invokes[0].policy.allowed_data_classes
          or task.data_classes & invokes[0].policy.denied_data_classes):
        problems.append("tool policy must permit the task purpose and dataClasses")
    if task.max_attempts != 1 and (source or (config and config["kind"] == "HTTP_JSON"
                                            and config["method"] == "POST")):
        problems.append("set maxAttempts to 1 for model and HTTP POST tasks; retries can repeat committed side effects")
    if source:
        if source["kind"] not in MODEL_KINDS:
            problems.append("configured task source must be a supported model runtime")
        else:
            primary_policy = None
            for candidate in provider_candidates(source):
                kind = candidate["kind"]
                if kind == "ANTHROPIC" and importlib.util.find_spec("anthropic") is None:
                    problems.append("Anthropic SDK is unavailable; install the anthropic extra on this host")
                provider = actors.get(candidate["providerActorId"])
                edges = [edge for edge in graph.edges if edge.source == task.source_actor_id
                         and edge.target == candidate["providerActorId"] and edge.relationship_id == "REL-07"]
                hostname = urlsplit(PROVIDER_ENDPOINTS[kind]).hostname
                if (provider is None or provider.type != ActorType.EXTERNAL
                        or hostname not in provider.allowed_domains or len(edges) != 1):
                    problems.append(f"{kind} requires one REL-07 edge to an EXTERNAL {hostname} actor")
                else:
                    policy = edges[0].policy
                    if (policy.mode != PolicyMode.ENFORCE or source["purpose"] not in policy.allowed_purposes
                            or not set(source["dataClasses"]) <= policy.allowed_data_classes
                            or set(source["dataClasses"]) & policy.denied_data_classes
                            or not set(source["dataClasses"]) <= provider.data_access):
                        problems.append("model provider policy must enforce the model purpose and dataClasses")
                    # Routing may change the destination; it may not weaken any original control.
                    comparison = replace(policy, id="provider", version="1")
                    if primary_policy is not None and comparison != primary_policy:
                        problems.append("all provider candidates must preserve the primary REL-07 policy")
                    primary_policy = primary_policy or comparison
                if candidate["credentialRef"] not in credential_refs:
                    problems.append("host credential reference is unavailable for a model provider")
            classes = set(task.data_classes)
            for tool_id in source.get("toolActorIds", [task.target_actor_id]):
                tool_config = configs.get(tool_id)
                if not tool_config or tool_config["kind"] in MODEL_KINDS:
                    problems.append(f"model tool {tool_id} requires a configured TOOL actor")
                    continue
                classes.update(tool_config["dataClasses"])
                tool_edges = [edge for edge in graph.edges if edge.source == task.source_actor_id
                              and edge.target == tool_id and edge.relationship_id == "REL-05"]
                if len(tool_edges) != 1:
                    problems.append(f"model tool {tool_id} requires one reviewed REL-05 source-to-tool edge")
                elif (tool_config["purpose"] not in tool_edges[0].policy.allowed_purposes
                      or not set(tool_config["dataClasses"]) <= tool_edges[0].policy.allowed_data_classes
                      or set(tool_config["dataClasses"]) & tool_edges[0].policy.denied_data_classes):
                    problems.append(f"model tool {tool_id} policy must permit its runtime purpose and dataClasses")
                if tool_config.get("credentialRef") and tool_config["credentialRef"] not in credential_refs:
                    problems.append(f"host credential reference is unavailable for model tool {tool_id}")
            for dependency in graph.orchestration.tasks:
                if dependency.id in task.depends_on:
                    classes.update(dependency.data_classes)
                    dependency_model = configs.get(dependency.source_actor_id)
                    if dependency_model and dependency_model["kind"] in MODEL_KINDS:
                        classes.update(dependency_model["dataClasses"])
            if not classes <= set(source["dataClasses"]):
                problems.append("model dataClasses must include its task, selected tool and dependency dataClasses")
    for runtime in (config, source):
        if runtime and runtime.get("credentialRef") and runtime["credentialRef"] not in credential_refs:
            problems.append("host credential reference is unavailable")
    return problems


def runtime_status(graph: ArchitectureGraph, credential_refs=()) -> dict[str, Any]:
    nodes, configs = [], {}
    for node in graph.nodes:
        problems = []
        config = None
        try:
            config = _config(node)
            if config and config.get("credentialRef") and config["credentialRef"] not in credential_refs:
                problems.append("host credential reference is unavailable")
        except (ValueError, TypeError) as error:
            problems.append(str(error))
        configs[node.id] = config
        nodes.append({"actorId": node.id, "kind": config.get("kind") if config else None,
                      "configured": config is not None and not problems, "missing": config is None,
                      "problems": problems})
    tasks, shapes = [], {}
    if graph.orchestration:
        for task in graph.orchestration.tasks:
            problems = _task_problems(graph, configs, task, credential_refs)
            tasks.append({"taskId": task.id, "sourceActorId": task.source_actor_id,
                          "targetActorId": task.target_actor_id, "configured": not problems,
                          "missing": bool(problems), "problems": problems})
            actor = next((node.actor for node in graph.nodes if node.id == task.target_actor_id), None)
            config = configs.get(task.target_actor_id)
            if configs.get(task.source_actor_id):
                shapes[task.id] = {"type": "object", "properties": {"prompt": {"type": "string"}}}
            elif actor and (not config or "arguments" not in config):
                shapes[task.id] = dict(actor.input_schema)
    global_problems = [] if graph.orchestration else ["workflow is missing"]
    input_schema = {"type": "object", "properties": {}}
    if graph.orchestration and any(config and "arguments" in config for config in configs.values()):
        coordinator = next((node.actor for node in graph.nodes
                            if node.id == graph.orchestration.coordinator_actor_id), None)
        if coordinator:
            input_schema = dict(coordinator.input_schema) or input_schema
        else:
            global_problems.append("workflow coordinator actor is missing")
    if shapes:
        properties = dict(input_schema.get("properties", {}))
        task_schema = dict(properties.get("tasks", {"type": "object"}))
        task_schema["properties"] = {**task_schema.get("properties", {}), **shapes}
        properties["tasks"] = task_schema
        input_schema["properties"] = properties

    def example(schema):
        if "default" in schema:
            return schema["default"]
        if schema.get("enum"):
            return schema["enum"][0]
        return {"string": "", "number": 0, "integer": 0, "boolean": False, "array": []}.get(
            schema.get("type"), {key: example(value) for key, value in schema.get("properties", {}).items()})

    return {"ready": bool(tasks) and all(item["configured"] for item in tasks)
            and all(not item["problems"] for item in nodes) and not global_problems, "nodes": nodes, "tasks": tasks,
            "problems": global_problems,
            "credentialRefs": sorted(credential_refs), "runInputSchema": input_schema,
            "runInputExample": example(input_schema)}


def _request(endpoint: str, method: str, body: bytes | None, headers: Mapping[str, str], *,
             timeout: float = 20, backend=None, tls_context=None) -> tuple[int, dict[str, str], bytes]:
    """One pinned HTTPS request; no redirects, proxies, decompression or cookie state."""
    parsed = urlsplit(endpoint)
    origin = canonical_network_destination(f"https://{parsed.netloc}")
    backend = backend or PinnedSocketEgressBackend(connect_timeout_seconds=min(timeout, 20))
    digest = canonical_digest(endpoint)
    request = EgressRequest("runtime", "configured-http", origin, digest, digest, digest)
    evidence = backend.connect(request, origin)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout)
    raw = backend.take(evidence.connection_id)
    response = None
    try:
        secured = (tls_context or ssl.create_default_context()).wrap_socket(raw, server_hostname=parsed.hostname)
        connection.sock = secured
        connection.sock.settimeout(timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(method, path, body=body, headers=dict(headers))
        response = connection.getresponse()
        deadline = time.monotonic() + timeout
        content = bytearray()
        while len(content) <= MAX_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP response exceeded its deadline")
            if secured.fileno() != -1:
                secured.settimeout(remaining)
            chunk = response.read1(min(65536, MAX_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_BYTES:
            raise ValueError("HTTP response exceeds 1 MiB")
        if 300 <= response.status < 400:
            raise ValueError("HTTP redirects are forbidden")
        return response.status, dict(response.getheaders()), bytes(content)
    finally:
        if response is not None:
            response.close()
        connection.close()
        raw.close()


def http_json(config: Mapping[str, Any], arguments: Mapping[str, Any], credentials: Mapping[str, str], *,
              request=_request, timeout: float = 20, idempotency_key: str | None = None) -> Any:
    endpoint = _endpoint(config["endpoint"])
    body = canonical_json(arguments)
    if len(body) > MAX_BYTES:
        raise ValueError("HTTP request exceeds 1 MiB")
    headers = {"Accept": "application/json", "Content-Type": "application/json", "Accept-Encoding": "identity"}
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    if config.get("credentialRef"):
        headers["Authorization"] = "Bearer " + credentials[config["credentialRef"]]
    if config["method"] == "GET":
        if any(isinstance(v, (dict, list)) for v in arguments.values()):
            raise ValueError("GET arguments must be scalar query values")
        endpoint += "?" + urlencode({key: value if isinstance(value, str) else json.dumps(value)
                                     for key, value in arguments.items()})
        body = None
    status, response_headers, content = request(endpoint, config["method"], body, headers, timeout=timeout)
    if not 200 <= status < 300:
        raise ValueError(f"HTTP endpoint returned status {status}")
    content_type = next((v for k, v in response_headers.items() if k.lower() == "content-type"), "")
    if "application/json" not in content_type.lower():
        raise ValueError("HTTP endpoint must return application/json")
    return json.loads(content)


def _anthropic_client(key: str, *, timeout: float):
    import anthropic
    import httpx2

    class PinnedTransport(httpx2.BaseTransport):
        def handle_request(self, request):
            parsed = urlsplit(str(request.url))
            if (parsed.scheme != "https" or parsed.netloc != "api.anthropic.com"
                    or parsed.path != "/v1/messages" or request.method != "POST"):
                raise ValueError("model request must use the fixed Anthropic messages endpoint")
            body = request.read()
            if len(body) > MAX_BYTES:
                raise ValueError("model request exceeds 1 MiB")
            status, headers, content = _request(str(request.url), "POST", body, dict(request.headers), timeout=timeout)
            return httpx2.Response(status, headers=headers, content=content, request=request)

    return anthropic.Anthropic(
        api_key=key, base_url="https://api.anthropic.com", max_retries=0, timeout=timeout,
        http_client=anthropic.DefaultHttpxClient(transport=PinnedTransport(), trust_env=False, follow_redirects=False),
    )


def configurable_adapter_provider(ledger, run_store, credentialsMapping: Mapping[str, str], *,
                                  http_request=_request, anthropic_client_factory=_anthropic_client,
                                  model_http_request=_request):
    """Bind only the exact configured tasks in a promoted, digest-pinned bundle.

    Test injection is host-side; neither clients nor resolvers are manifest fields.
    A model task can call its explicitly selected reviewed tools, serially. The model's final answer is
    task output {'text': ...}; tool-call results remain in its guarded ledger trace.
    """
    credentials = dict(credentialsMapping)

    def provide(compiled: CompiledArchitecture):
        nodes = {node.id: node for node in compiled.graph.nodes}
        configs = {actor_id: _config(node) for actor_id, node in nodes.items()}
        definition = compiled.graph.orchestration
        if definition is None:
            raise ValueError("configured runtime requires a workflow")
        status = runtime_status(compiled.graph, credentials)
        if not status["ready"]:
            problems = status["problems"] + [problem for item in status["nodes"] + status["tasks"]
                                             for problem in item["problems"]]
            raise ValueError("; ".join(problems) or "configured workflow is not ready")

        def execute(value: TaskExecutionInput) -> TaskExecutionResult:
            from .effects import EffectJournal
            from .orchestration import TaskExecutionHeld

            task = value.task
            config = configs[task.target_actor_id]
            model = configs.get(task.source_actor_id)
            remaining = max(0.1, min(20, value.deadline_epoch - time.time()))
            run = run_store.get(tenant_id=value.tenant_id, run_id=value.run_id)
            pending = dict(run.tasks[task.id].pending_call or {})
            checkpoint = run.tasks[task.id].effect_checkpoint
            checkpoint_step = ((checkpoint or {}).get("invocation", {}).get("continuation") or {}).get("step", 0)
            pending_step = (pending.get("continuation") or {}).get("step", 0)
            if checkpoint and (not pending or checkpoint_step >= pending_step):
                pending = dict(checkpoint["invocation"])
                pending["requestId"] = canonical_digest(checkpoint["invocation"])
            request_id = pending.get("requestId")
            if request_id and f"{task.id}:{request_id}" in run.tasks:
                raise ValueError("task ID overlaps an invocation approval scope")
            approved_by = run.approvals.get(f"{task.id}:{request_id}") if request_id else None
            if not model and task.approval_required and approved_by is None:
                approved_by = run.approvals.get(task.id)
            effect_context = {}

            def make_tool(actor_id):
                actor = compiled.actors[actor_id]
                runtime = configs[actor_id]
                reviewed = configured_definition(nodes[actor_id])

                def connector(arguments):
                    if runtime["kind"] == "JSON_TRANSFORM":
                        return map_json(runtime["template"], {"arguments": arguments})
                    if effect_context.get("confirmed") is not None:
                        return effect_context["confirmed"]
                    return http_json(runtime, arguments, credentials, request=http_request, timeout=remaining,
                                     idempotency_key=effect_context.get("key"))

                def approve(arguments, _decision):
                    if pending and (dict(arguments) != pending.get("arguments")
                                    or pending.get("targetActorId") != actor_id
                                    or pending.get("toolName") != reviewed.tool_name
                                    or pending.get("definitionDigest") != actor.definition_digest):
                        return None
                    return approved_by

                binding = ToolBinding(
                    reviewed, connector, actor_id, runtime["purpose"],
                    classify=lambda _args: frozenset(runtime["dataClasses"]),
                    estimate_export=lambda args: (1, len(canonical_json(args))),
                    result_provenance=lambda _result: {"dataClasses": runtime["dataClasses"], "source": actor_id,
                                                       "definitionDigest": actor.definition_digest},
                )
                _, guarded = build_managed_tools(
                    compiled, bindings=[binding], tenant_id=value.tenant_id,
                    source_actor_id=task.source_actor_id, ledger=ledger, approver="reviewed-bundle",
                    approve=approve, trace_id=value.trace_id,
                )
                return guarded[0]

            tool_ids = model.get("toolActorIds", [task.target_actor_id]) if model else [task.target_actor_id]
            tools_by_id = {actor_id: make_tool(actor_id) for actor_id in tool_ids}
            tools_by_name = {tool.name: tool for tool in tools_by_id.values()}

            def invocation_for(tool, arguments, continuation):
                actor_id = next(actor_id for actor_id, candidate in tools_by_id.items() if candidate is tool)
                intent = tool._declared_intent(arguments)
                return {"sourceActorId": task.source_actor_id, "targetActorId": actor_id,
                        "toolName": tool.name, "definitionDigest": compiled.actors[actor_id].definition_digest,
                        "purpose": configs[actor_id]["purpose"], "dataClasses": sorted(intent.data_classes),
                        "destinations": list(intent.destinations), "arguments": dict(arguments),
                        "continuation": continuation}

            def dispatch_tool(tool, arguments, decision, continuation=None):
                invocation = invocation_for(tool, arguments, continuation)
                runtime = configs[invocation["targetActorId"]]
                if runtime["kind"] != "HTTP_JSON" or runtime["method"] != "POST":
                    return tool._execute_decision(arguments, decision)

                def send(key, confirmed):
                    effect_context.update(key=key, confirmed=confirmed)
                    try:
                        return json.loads(tool._execute_decision(arguments, decision))
                    finally:
                        effect_context.clear()

                output = EffectJournal(run_store, ledger).execute(value, invocation, send)
                return canonical_json(output).decode()

            def hold_if_needed(tool, arguments, continuation=None):
                decision = tool._decide(arguments)
                if not decision.permits_execution:
                    if set(decision.reason_codes) == {APPROVAL_REQUIRED}:
                        raise TaskExecutionHeld(invocation_for(tool, arguments, continuation))
                    raise ValueError("tool invocation blocked: " + ", ".join(decision.reason_codes))
                return decision

            context = {"input": dict(value.workflow_input), "dependencies": dict(value.dependency_outputs)}
            if not model:
                tool = tools_by_id[task.target_actor_id]
                if pending:
                    arguments = pending["arguments"]
                elif "arguments" in config:
                    arguments = map_json(config["arguments"], context)
                else:
                    arguments = value.workflow_input.get("tasks", {}).get(task.id)
                if not isinstance(arguments, Mapping):
                    raise ValueError(f"input.tasks.{task.id} must be an argument object")
                decision = hold_if_needed(tool, arguments)
                output = json.loads(dispatch_tool(tool, arguments, decision))
                if not isinstance(output, Mapping):
                    raise ValueError("workflow tool output must be a JSON object")
                return TaskExecutionResult(output=output, metadata={"bundleDigest": compiled.bundle_digest})

            model_context = {"input": value.workflow_input.get("tasks", {}).get(task.id, {}),
                             "dependencies": dict(value.dependency_outputs)}
            messages = [{"role": "user", "content": canonical_json(model_context).decode()}]
            start_step = 0
            if pending:
                continuation = pending["continuation"]
                if not isinstance(continuation, Mapping):
                    raise ValueError("pending model continuation is missing")
                messages = list(continuation["messages"])
                start_step = continuation["step"]
                tool = tools_by_id.get(pending.get("targetActorId"))
                if tool is None or pending.get("toolName") != tool.name:
                    raise ValueError("pending model tool is outside the reviewed selection")
                decision = hold_if_needed(tool, pending["arguments"], continuation)
                result = dispatch_tool(tool, pending["arguments"], decision, continuation)
                approved_by = None
                messages.append({"role": "user", "content": [{"type": "tool_result",
                    "tool_use_id": continuation["toolUseId"], "content": result}]})

            # Every retry and provider transition rechecks the complete classified payload.
            interlock = Interlock(ledger, bundle_digest=compiled.bundle_digest)
            source_actor = interlock.define_actor(compiled.actors[task.source_actor_id])
            providers = {}
            for candidate in provider_candidates(model):
                actor_id = candidate["providerActorId"]
                if actor_id in providers:
                    continue
                providers[actor_id] = interlock.define_actor(compiled.actors[actor_id])
                edge = next(edge for edge in compiled.graph.edges if edge.source == task.source_actor_id
                            and edge.target == actor_id and edge.relationship_id == "REL-07")
                interlock.connect(source_actor, providers[actor_id], compiled.links[edge.id])

            for step in range(start_step, model["maxSteps"]):
                def invoke(candidate, timeout):
                    tool_definitions = [tool.to_dict() for tool in tools_by_id.values()]
                    request = {"model": candidate["model"], "system": model["systemPrompt"],
                               "max_tokens": model["maxTokens"], "messages": messages,
                               "tools": tool_definitions,
                               "tool_choice": {"type": "auto", "disable_parallel_tool_use": True}}
                    if candidate["kind"] == "OPENAI":
                        request = openai_payload(candidate, messages=messages, tools=tool_definitions,
                                                 system=model["systemPrompt"], max_tokens=model["maxTokens"])
                    model_result = {}

                    def model_request(_arguments):
                        try:
                            if candidate["kind"] == "OPENAI":
                                response = openai_request(candidate, request=model_http_request, messages=messages,
                                    tools=tool_definitions, system=model["systemPrompt"], max_tokens=model["maxTokens"],
                                    key=credentials[candidate["credentialRef"]], timeout=timeout, payload=request)
                            else:
                                client = anthropic_client_factory(
                                    credentials[candidate["credentialRef"]], timeout=timeout)
                                try:
                                    runner = client.beta.messages.tool_runner(
                                        model=candidate["model"], system=model["systemPrompt"],
                                        max_tokens=model["maxTokens"],
                                        messages=messages, tools=list(tools_by_id.values()), max_iterations=1,
                                        tool_choice={"type": "auto", "disable_parallel_tool_use": True},
                                    )
                                    message = next(iter(runner))
                                    usage = getattr(message, "usage", None)
                                    response = {"content": [block.model_dump(mode="json", exclude_none=True)
                                                           for block in message.content],
                                                "stopReason": message.stop_reason,
                                                "usage": usage.model_dump(mode="json") if usage is not None else None}
                                finally:
                                    client.close()
                        except Exception as error:
                            # Sanitize before Interlock records connector failure strings.
                            raise classify_error(error) from None
                        model_result["response"] = response
                        return {"content": response["content"], "stopReason": response["stopReason"]}

                    try:
                        model_output = providers[candidate["providerActorId"]].wrap(model_request)(
                            request, source=source_actor, tenant_id=value.tenant_id, trace_id=value.trace_id,
                            intent=InvocationIntent(
                                purpose=model["purpose"], data_classes=frozenset(model["dataClasses"]),
                                destinations=(PROVIDER_ENDPOINTS[candidate["kind"]],),
                                estimated_side_effect=SideEffect.READ, estimated_record_count=1,
                                estimated_byte_count=len(canonical_json(request)),
                            ),
                        )
                    except GatewayError:
                        raise ProviderCallError("POLICY") from None
                    response = model_result["response"]
                    if model_output != {"content": response["content"], "stopReason": response["stopReason"]}:
                        raise ProviderCallError("POLICY")
                    return response

                def record(attempt):
                    ledger.append("PROVIDER_CALL_RECORDED", tenant_id=value.tenant_id, trace_id=value.trace_id,
                        source_actor_id=task.source_actor_id, target_actor_id=attempt["providerActorId"],
                        span_id=attempt["attemptId"], relationship_id="REL-07", relationship_type="SENDS",
                        payload={**attempt, "step": step, "bundleDigest": compiled.bundle_digest})

                response = call_with_policy(model, invoke, record, deadline_epoch=value.deadline_epoch)
                blocks = response["content"]
                calls = [block for block in blocks if block["type"] == "tool_use"]
                messages.append({"role": "assistant", "content": blocks})
                if not calls:
                    if response["stopReason"] != "end_turn":
                        raise ValueError("model stopped without completing its task")
                    return TaskExecutionResult(output={"text": "\n".join(
                        block["text"] for block in blocks if block["type"] == "text")},
                        metadata={"bundleDigest": compiled.bundle_digest})
                if len(calls) != 1 or calls[0]["name"] not in tools_by_name:
                    raise ValueError("model must request one selected reviewed tool per turn")
                call = calls[0]
                tool = tools_by_name[call["name"]]
                if not isinstance(call["input"], Mapping):
                    raise ValueError("model tool arguments must be a JSON object")
                continuation = {"messages": messages, "step": step + 1, "toolUseId": call["id"]}
                decision = hold_if_needed(tool, call["input"], continuation)
                result_block = {"type": "tool_result", "tool_use_id": call["id"]}
                try:
                    result_block["content"] = dispatch_tool(tool, call["input"], decision, continuation)
                except Exception as error:  # Match the SDK runner's tool-error response.
                    if getattr(error, "reason_code", "") == "RUN-EFFECT-UNCERTAIN":
                        raise
                    result_block.update(content=str(error), is_error=True)
                messages.append({"role": "user", "content": [result_block]})
            raise ValueError("model exceeded its configured maxSteps")

        return {TaskTransport.LOCAL: CallableTaskAdapter(execute)}

    return provide
