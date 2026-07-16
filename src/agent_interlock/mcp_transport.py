"""MCP JSON-RPC transport boundary backed by the Interlock policy gateway."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from .architecture import CompiledArchitecture
from .canonical import canonical_digest
from .gateway import GatewayError, InvocationBlocked, MCPToolGateway
from .models import (
    ActorType,
    CredentialClaims,
    DataSource,
    DefinitionState,
    Environment,
    InvocationIntent,
    PolicyDecisionRecord,
    SideEffect,
    ToolDefinition,
)
from .registry import ToolRevision
from .security import contains_secret, sanitize_secrets


MCP_PROTOCOL_VERSION = "2025-11-25"
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_INVALID_PARAMS = -32602
_JSONRPC_INTERNAL_ERROR = -32603
_INTERLOCK_BLOCKED = -32001
_INTERLOCK_NOT_CONFIGURED = -32002
_INTERLOCK_DOWNSTREAM_ERROR = -32003


ServerCaller = Callable[[Mapping[str, Any]], Mapping[str, Any] | None]


class MCPTransportError(GatewayError):
    """A protocol-safe error that can be serialized as a JSON-RPC error."""

    def __init__(
        self,
        code: int,
        message: str,
        *,
        reason_code: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.reason_code = reason_code
        self.data = dict(data or {})


class MCPArchitectureBindingError(GatewayError):
    """The compiled architecture cannot safely bind to an observed MCP Tool."""


class _DownstreamCallError(GatewayError):
    def __init__(self, response_error: Mapping[str, Any]):
        code = response_error.get("code", _INTERLOCK_DOWNSTREAM_ERROR)
        super().__init__(f"downstream tools/call failed with code {code}")
        self.response_error = response_error


@dataclass(frozen=True, slots=True)
class MCPServerProfile:
    tenant_id: str
    server_id: str
    endpoint: str
    transport: str = "streamable-http"
    publisher: str = ""
    artifact_digest: str = ""
    protocol_version: str = MCP_PROTOCOL_VERSION
    max_message_bytes: int = 1_048_576
    max_tools_per_page: int = 256
    max_list_pages: int = 32
    allowed_request_meta_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.server_id or not self.endpoint:
            raise ValueError("tenant_id, server_id, and endpoint are required")
        if self.transport not in {"streamable-http", "stdio"}:
            raise ValueError("transport must be streamable-http or stdio")
        if self.protocol_version != MCP_PROTOCOL_VERSION:
            raise ValueError(f"unsupported MCP protocol version: {self.protocol_version}")
        if self.max_message_bytes <= 0 or self.max_tools_per_page <= 0 or self.max_list_pages <= 0:
            raise ValueError("MCP transport limits must be positive")
        if any(not isinstance(key, str) or not key for key in self.allowed_request_meta_keys):
            raise ValueError("allowed_request_meta_keys must contain non-empty strings")


@dataclass(frozen=True, slots=True)
class MCPInvocationContext:
    """Trusted Host-side context. It is never derived from MCP Server content."""

    tenant_id: str
    source_actor_id: str
    purpose: str
    data_classes: frozenset[str] = frozenset({"D3"})
    destinations: tuple[str, ...] = ()
    estimated_side_effect: SideEffect = SideEffect.NONE
    taint_labels: frozenset[str] = frozenset()
    approval_id: str | None = None
    expected_audience: str = ""
    expected_resource: str = ""
    credential: CredentialClaims | None = None
    trace_id: str | None = None
    span_id: str | None = None
    idempotency_key: str | None = None
    environment: Environment = Environment.DEV
    data_source: DataSource = DataSource.PRODUCTION

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.source_actor_id or not self.purpose:
            raise ValueError("tenant_id, source_actor_id, and purpose are required")

    def intent(self) -> InvocationIntent:
        return InvocationIntent(
            purpose=self.purpose,
            data_classes=self.data_classes,
            destinations=self.destinations,
            estimated_side_effect=self.estimated_side_effect,
            taint_labels=self.taint_labels,
            approval_id=self.approval_id,
            expected_audience=self.expected_audience,
            expected_resource=self.expected_resource,
        )


class MCPTransportAdapter:
    """Intercept MCP Tool discovery and invocation before a concrete transport sends it."""

    def __init__(
        self,
        gateway: MCPToolGateway,
        profile: MCPServerProfile,
        call_server: ServerCaller,
    ) -> None:
        self.gateway = gateway
        self.profile = profile
        self._call_server = call_server
        self._observed_by_name: dict[str, str] = {}
        self._tool_actor_by_name: dict[str, str] = {}

    @property
    def observed_revisions(self) -> tuple[ToolRevision, ...]:
        return tuple(
            self.gateway.registry.get(revision_id)
            for _, revision_id in sorted(self._observed_by_name.items())
        )

    def handle_client_message(
        self,
        value: bytes | str | Mapping[str, Any],
        *,
        context: MCPInvocationContext | None = None,
    ) -> dict[str, Any] | None:
        """Handle one client-to-server MCP message and return one client response."""

        request_id: str | int | None = None
        try:
            request = self._parse_message(value)
            request_id = _request_id(request)
            method = request.get("method")
            if not isinstance(method, str) or not method:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "JSON-RPC request method is required",
                    reason_code="MCP-INVALID-REQUEST",
                )
            if method == "tools/list":
                self._require_request_id(request)
                return self._handle_tools_list(request)
            if method == "tools/call":
                self._require_request_id(request)
                if context is None:
                    raise MCPTransportError(
                        _INTERLOCK_NOT_CONFIGURED,
                        "trusted invocation context is required",
                        reason_code="INTERLOCK-TRUSTED-CONTEXT-MISSING",
                    )
                return self._handle_tools_call(request, context)
            if method.startswith("tools/"):
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "unsupported MCP Tool method",
                    reason_code="MCP-TOOL-METHOD-UNSUPPORTED",
                )
            response = self._send(request)
            return dict(response) if response is not None else None
        except InvocationBlocked as error:
            return _blocked_response(request_id, error.decision)
        except MCPTransportError as error:
            return _error_response(request_id, error)
        except _DownstreamCallError as error:
            clean, _ = sanitize_secrets(error.response_error)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": _INTERLOCK_DOWNSTREAM_ERROR,
                    "message": "downstream MCP Tool execution failed",
                    "data": {"downstream": clean},
                },
            }
        except GatewayError as error:
            return _error_response(
                request_id,
                MCPTransportError(
                    _INTERLOCK_NOT_CONFIGURED,
                    "Agent Interlock gateway rejected the request",
                    reason_code="INTERLOCK-GATEWAY-ERROR",
                    data={"detail": str(error)},
                ),
            )

    def handle_server_message(
        self, value: bytes | str | Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """Refresh definitions before forwarding a Tool list-changed notification."""

        message = self._parse_message(value)
        if message.get("method") == "notifications/tools/list_changed":
            self.refresh_definitions()
        return dict(message)

    def refresh_definitions(self) -> tuple[ToolRevision, ...]:
        """Read every tools/list page, detect removal/drift, and fail closed on malformed D1."""

        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_tools: set[str] = set()
        revisions: list[ToolRevision] = []
        for _ in range(self.profile.max_list_pages):
            request_id = f"interlock-discovery-{uuid.uuid4()}"
            params = {"cursor": cursor} if cursor else {}
            request = {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params}
            response = self._send(request)
            page, next_cursor = self._observe_tools_response(request_id, response)
            for revision in page:
                name = revision.definition.tool_name
                if name in seen_tools:
                    raise MCPTransportError(
                        _JSONRPC_INVALID_REQUEST,
                        "duplicate Tool name across tools/list pages",
                        reason_code="MCP-TOOLS-LIST-DUPLICATE",
                    )
                seen_tools.add(name)
                revisions.append(revision)
            if next_cursor is None:
                break
            if next_cursor in seen_cursors:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "tools/list pagination cursor repeated",
                    reason_code="MCP-TOOLS-LIST-CURSOR-LOOP",
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "tools/list exceeded the configured page limit",
                reason_code="MCP-TOOLS-LIST-PAGE-LIMIT",
            )

        removed = set(self._observed_by_name) - seen_tools
        for name in removed:
            previous = self.gateway.registry.get(self._observed_by_name[name])
            if previous.state in {DefinitionState.ACTIVE, DefinitionState.APPROVED}:
                self.gateway.registry.quarantine(previous.revision_id, "L1-M2-DEFINITION-REMOVED")
            del self._observed_by_name[name]
        return tuple(revisions)

    def bind_compiled_architecture(
        self,
        compiled: CompiledArchitecture,
        *,
        tool_bindings: Mapping[str, str],
        approver: str,
    ) -> tuple[ToolRevision, ...]:
        """Bind reviewed Architecture REL-05 links to exact observed Tool digests."""

        if not approver:
            raise MCPArchitectureBindingError("approver is required")
        prepared: list[tuple[str, str, ToolRevision, tuple[Any, ...]]] = []
        for tool_name, actor_id in tool_bindings.items():
            if tool_name not in self._observed_by_name:
                raise MCPArchitectureBindingError(f"Tool {tool_name!r} has not been observed")
            try:
                target = compiled.actors[actor_id]
            except KeyError as error:
                raise MCPArchitectureBindingError(f"unknown Tool actor {actor_id!r}") from error
            if target.type != ActorType.TOOL:
                raise MCPArchitectureBindingError(f"actor {actor_id!r} is not a TOOL")
            revision = self.gateway.registry.get(self._observed_by_name[tool_name])
            if target.definition_digest != revision.canonical_digest:
                raise MCPArchitectureBindingError(
                    f"definition digest mismatch for {tool_name!r}: architecture pin does not match observation"
                )
            if revision.state not in {
                DefinitionState.DISCOVERED,
                DefinitionState.APPROVED,
                DefinitionState.ACTIVE,
            }:
                raise MCPArchitectureBindingError(
                    f"Tool {tool_name!r} cannot activate from {revision.state.value}"
                )
            matching_edges = tuple(
                edge
                for edge in compiled.graph.edges
                if edge.relationship_id == "REL-05" and edge.target == actor_id
            )
            if not matching_edges:
                raise MCPArchitectureBindingError(f"Tool actor {actor_id!r} has no REL-05 edge")
            prepared.append((tool_name, actor_id, revision, matching_edges))

        activated: list[ToolRevision] = []
        for tool_name, actor_id, revision, matching_edges in prepared:
            if revision.state == DefinitionState.DISCOVERED:
                revision = self.gateway.registry.approve(revision.revision_id, approver)
            if revision.state == DefinitionState.APPROVED:
                revision = self.gateway.registry.activate(revision.revision_id)

            effective_target = self._effective_tool_actor(compiled, actor_id)
            self.gateway.register_actor(effective_target, tool_id=revision.tool_id)
            for edge in matching_edges:
                source = compiled.actors[edge.source]
                self.gateway.register_actor(source)
                self.gateway.connect(source.id, effective_target.id, compiled.links[edge.id])
            self._tool_actor_by_name[tool_name] = actor_id
            activated.append(revision)
        return tuple(activated)

    def _handle_tools_list(self, request: Mapping[str, Any]) -> dict[str, Any]:
        params = _params(request)
        unknown = set(params) - {"cursor", "_meta"}
        if unknown or ("cursor" in params and not isinstance(params["cursor"], str)):
            raise MCPTransportError(
                _JSONRPC_INVALID_PARAMS,
                "invalid tools/list parameters",
                reason_code="MCP-TOOLS-LIST-PARAMS-INVALID",
            )
        downstream_params: dict[str, Any] = {}
        if "cursor" in params:
            downstream_params["cursor"] = params["cursor"]
        approved_meta = self._approved_meta(params)
        if approved_meta:
            downstream_params["_meta"] = approved_meta
        downstream_request = dict(request)
        downstream_request["params"] = downstream_params
        response = self._send(downstream_request)
        revisions, next_cursor = self._observe_tools_response(request["id"], response)
        visible = []
        for observed in revisions:
            current = self.gateway.registry.get(observed.revision_id)
            active = self.gateway.registry.active_for(current.tool_id)
            if current.state == DefinitionState.ACTIVE and active and active.revision_id == current.revision_id:
                visible.append(_model_visible_tool(current.definition))
        result: dict[str, Any] = {"tools": visible}
        if next_cursor is not None:
            result["nextCursor"] = next_cursor
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    def _handle_tools_call(
        self, request: Mapping[str, Any], context: MCPInvocationContext
    ) -> dict[str, Any]:
        if context.tenant_id != self.profile.tenant_id:
            raise MCPTransportError(
                _INTERLOCK_NOT_CONFIGURED,
                "invocation tenant does not match the MCP Server binding",
                reason_code="INTERLOCK-TENANT-MISMATCH",
            )
        params = _params(request)
        unknown = set(params) - {"name", "arguments", "_meta"}
        name = params.get("name")
        arguments = params.get("arguments", {})
        if unknown or not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
            raise MCPTransportError(
                _JSONRPC_INVALID_PARAMS,
                "invalid tools/call Tool name or parameters",
                reason_code="MCP-TOOLS-CALL-PARAMS-INVALID",
            )
        if not isinstance(arguments, Mapping):
            raise MCPTransportError(
                _JSONRPC_INVALID_PARAMS,
                "tools/call arguments must be an object",
                reason_code="MCP-TOOLS-CALL-ARGUMENTS-INVALID",
            )
        approved_meta = self._approved_meta(params)

        self.refresh_definitions()
        revision_id = self._observed_by_name.get(name)
        if revision_id is None or name not in self._tool_actor_by_name:
            raise MCPTransportError(
                _INTERLOCK_NOT_CONFIGURED,
                "MCP Tool is not bound to a compiled architecture",
                reason_code="INTERLOCK-MCP-TOOL-NOT-BOUND",
            )
        revision = self.gateway.registry.get(revision_id)
        idempotency_key = context.idempotency_key or canonical_digest(
            {
                "serverId": self.profile.server_id,
                "sourceActorId": context.source_actor_id,
                "requestId": request["id"],
                "tool": name,
                "arguments": arguments,
            }
        )

        def connector(bound_arguments: Mapping[str, Any]) -> Mapping[str, Any]:
            downstream_params: dict[str, Any] = {"name": name, "arguments": dict(bound_arguments)}
            if approved_meta:
                downstream_params["_meta"] = approved_meta
            downstream_request = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "method": "tools/call",
                "params": downstream_params,
            }
            response = self._send(downstream_request)
            if response is None:
                raise MCPTransportError(
                    _INTERLOCK_DOWNSTREAM_ERROR,
                    "downstream MCP Server returned no response",
                    reason_code="MCP-DOWNSTREAM-RESPONSE-MISSING",
                )
            if "error" in response:
                error_value = response["error"]
                if not isinstance(error_value, Mapping):
                    error_value = {"code": _INTERLOCK_DOWNSTREAM_ERROR, "message": "invalid downstream error"}
                raise _DownstreamCallError(error_value)
            result = response.get("result")
            if not isinstance(result, Mapping) or not isinstance(result.get("content"), list):
                raise MCPTransportError(
                    _INTERLOCK_DOWNSTREAM_ERROR,
                    "downstream tools/call result is malformed",
                    reason_code="MCP-DOWNSTREAM-RESULT-INVALID",
                )
            if "structuredContent" in result and not isinstance(result["structuredContent"], Mapping):
                raise MCPTransportError(
                    _INTERLOCK_DOWNSTREAM_ERROR,
                    "structuredContent must be an object",
                    reason_code="MCP-DOWNSTREAM-RESULT-INVALID",
                )
            if "isError" in result and not isinstance(result["isError"], bool):
                raise MCPTransportError(
                    _INTERLOCK_DOWNSTREAM_ERROR,
                    "isError must be boolean",
                    reason_code="MCP-DOWNSTREAM-RESULT-INVALID",
                )
            return dict(result)

        result = self.gateway.invoke(
            tenant_id=context.tenant_id,
            source_actor_id=context.source_actor_id,
            revision_id=revision.revision_id,
            intent=context.intent(),
            arguments=dict(arguments),
            credential=context.credential,
            trace_id=context.trace_id,
            span_id=context.span_id,
            environment=context.environment,
            data_source=context.data_source,
            connector=connector,
            idempotency_key=idempotency_key,
        )
        if not isinstance(result.value, Mapping):
            raise MCPTransportError(
                _INTERLOCK_DOWNSTREAM_ERROR,
                "inspected MCP Tool result is malformed",
                reason_code="MCP-RESULT-GUARD-INVALID",
            )
        guarded_result = dict(result.value)
        meta = dict(guarded_result.get("_meta", {})) if isinstance(guarded_result.get("_meta"), Mapping) else {}
        meta["interlock"] = {
            "decisionId": result.decision.decision_id,
            "decision": result.decision.decision.value,
            "reasonCodes": list(result.decision.reason_codes),
            "labels": list(result.labels),
            "traceId": result.decision.trace_id,
        }
        guarded_result["_meta"] = meta
        return {"jsonrpc": "2.0", "id": request["id"], "result": guarded_result}

    def _observe_tools_response(
        self, request_id: str | int, response: Mapping[str, Any] | None
    ) -> tuple[tuple[ToolRevision, ...], str | None]:
        if response is None or response.get("id") != request_id:
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "tools/list response id does not match request",
                reason_code="MCP-DOWNSTREAM-RESPONSE-ID-MISMATCH",
            )
        if "error" in response:
            raise MCPTransportError(
                _INTERLOCK_DOWNSTREAM_ERROR,
                "downstream tools/list failed",
                reason_code="MCP-DOWNSTREAM-LIST-FAILED",
            )
        result = response.get("result")
        tools = result.get("tools") if isinstance(result, Mapping) else None
        if not isinstance(tools, list) or len(tools) > self.profile.max_tools_per_page:
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "tools/list result is malformed or too large",
                reason_code="MCP-TOOLS-LIST-INVALID",
            )
        names: set[str] = set()
        revisions: list[ToolRevision] = []
        for raw_tool in tools:
            definition = self._definition(raw_tool)
            if definition.tool_name in names:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "duplicate Tool name in tools/list",
                    reason_code="MCP-TOOLS-LIST-DUPLICATE",
                )
            names.add(definition.tool_name)
            revision = self.gateway.observe_definition(
                definition,
                tenant_id=self.profile.tenant_id,
                raw_definition=raw_tool,
            )
            self._observed_by_name[definition.tool_name] = revision.revision_id
            revisions.append(revision)
        next_cursor = result.get("nextCursor") if isinstance(result, Mapping) else None
        if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "tools/list nextCursor must be a non-empty string",
                reason_code="MCP-TOOLS-LIST-CURSOR-INVALID",
            )
        return tuple(revisions), next_cursor

    def _definition(self, raw_tool: Any) -> ToolDefinition:
        if not isinstance(raw_tool, Mapping):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "Tool definition must be an object",
                reason_code="MCP-TOOL-DEFINITION-INVALID",
            )
        name = raw_tool.get("name")
        input_schema = raw_tool.get("inputSchema")
        output_schema = raw_tool.get("outputSchema", {})
        if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "Tool name violates the MCP name profile",
                reason_code="MCP-TOOL-NAME-INVALID",
            )
        if not isinstance(input_schema, Mapping) or not isinstance(output_schema, Mapping):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "Tool schemas must be JSON objects",
                reason_code="MCP-TOOL-SCHEMA-INVALID",
            )
        title = raw_tool.get("title", "")
        description = raw_tool.get("description", "")
        annotations = raw_tool.get("annotations", {})
        if not isinstance(title, str) or not isinstance(description, str) or not isinstance(annotations, Mapping):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "Tool metadata has invalid types",
                reason_code="MCP-TOOL-DEFINITION-INVALID",
            )
        core = {"name", "title", "description", "inputSchema", "outputSchema", "annotations"}
        return ToolDefinition(
            server_id=self.profile.server_id,
            tool_name=name,
            title=title,
            description=description,
            input_schema=dict(input_schema),
            output_schema=dict(output_schema),
            annotations=dict(annotations),
            protocol_extensions={key: value for key, value in raw_tool.items() if key not in core},
            endpoint=self.profile.endpoint,
            transport=self.profile.transport,
            publisher=self.profile.publisher,
            artifact_digest=self.profile.artifact_digest,
        )

    def _effective_tool_actor(self, compiled: CompiledArchitecture, actor_id: str):
        target = compiled.actors[actor_id]
        domains = set(target.allowed_domains)
        for edge in compiled.graph.edges:
            if edge.relationship_id == "REL-07" and edge.source == actor_id:
                domains.update(compiled.actors[edge.target].allowed_domains)
        return replace(target, allowed_domains=frozenset(domains))

    def _approved_meta(self, params: Mapping[str, Any]) -> dict[str, Any]:
        raw_meta = params.get("_meta")
        if raw_meta is None:
            return {}
        if not isinstance(raw_meta, Mapping):
            raise MCPTransportError(
                _JSONRPC_INVALID_PARAMS,
                "request _meta must be an object",
                reason_code="MCP-REQUEST-META-INVALID",
            )
        denied = set(raw_meta) - self.profile.allowed_request_meta_keys
        if denied:
            raise MCPTransportError(
                _JSONRPC_INVALID_PARAMS,
                "request _meta contains keys that are not explicitly allowed",
                reason_code="INTERLOCK-MCP-META-DENIED",
            )
        if contains_secret(raw_meta):
            raise MCPTransportError(
                _INTERLOCK_BLOCKED,
                "request _meta contains credential-like data",
                reason_code="L1-M8-CREDENTIAL-DETECTED",
            )
        return dict(raw_meta)

    def _parse_message(self, value: bytes | str | Mapping[str, Any]) -> Mapping[str, Any]:
        if isinstance(value, bytes):
            if len(value) > self.profile.max_message_bytes:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "MCP message exceeds the configured size limit",
                    reason_code="MCP-MESSAGE-TOO-LARGE",
                )
            try:
                parsed = json.loads(value.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "MCP message is not valid UTF-8 JSON",
                    reason_code="MCP-INVALID-JSON",
                ) from error
        elif isinstance(value, str):
            encoded = value.encode("utf-8")
            if len(encoded) > self.profile.max_message_bytes:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "MCP message exceeds the configured size limit",
                    reason_code="MCP-MESSAGE-TOO-LARGE",
                )
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as error:
                raise MCPTransportError(
                    _JSONRPC_INVALID_REQUEST,
                    "MCP message is not valid JSON",
                    reason_code="MCP-INVALID-JSON",
                ) from error
        else:
            parsed = value
        if isinstance(parsed, list):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "JSON-RPC batching is not supported by MCP",
                reason_code="MCP-BATCH-NOT-SUPPORTED",
            )
        if not isinstance(parsed, Mapping) or parsed.get("jsonrpc") != "2.0":
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "MCP message must be a JSON-RPC 2.0 object",
                reason_code="MCP-INVALID-REQUEST",
            )
        try:
            size = len(json.dumps(parsed, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError) as error:
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "MCP message contains a non-JSON value",
                reason_code="MCP-INVALID-JSON",
            ) from error
        if size > self.profile.max_message_bytes:
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "MCP message exceeds the configured size limit",
                reason_code="MCP-MESSAGE-TOO-LARGE",
            )
        return parsed

    def _send(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        response = self._call_server(request)
        if response is None:
            return None
        parsed = self._parse_message(response)
        if "method" in parsed:
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "downstream returned a request where a response was expected",
                reason_code="MCP-DOWNSTREAM-RESPONSE-INVALID",
            )
        return parsed

    @staticmethod
    def _require_request_id(request: Mapping[str, Any]) -> None:
        if "id" not in request or not isinstance(request["id"], (str, int)) or isinstance(request["id"], bool):
            raise MCPTransportError(
                _JSONRPC_INVALID_REQUEST,
                "MCP Tool requests require a string or integer id",
                reason_code="MCP-REQUEST-ID-INVALID",
            )


def _params(request: Mapping[str, Any]) -> Mapping[str, Any]:
    params = request.get("params", {})
    if not isinstance(params, Mapping):
        raise MCPTransportError(
            _JSONRPC_INVALID_PARAMS,
            "request params must be an object",
            reason_code="MCP-PARAMS-INVALID",
        )
    return params


def _request_id(request: Mapping[str, Any]) -> str | int | None:
    value = request.get("id")
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return value
    return None


def _model_visible_tool(definition: ToolDefinition) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": definition.tool_name,
        "description": definition.description,
        "inputSchema": dict(definition.input_schema),
    }
    if definition.title:
        value["title"] = definition.title
    if definition.output_schema:
        value["outputSchema"] = dict(definition.output_schema)
    if definition.annotations:
        value["annotations"] = dict(definition.annotations)
    return value


def _blocked_response(request_id: str | int | None, decision: PolicyDecisionRecord) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": _INTERLOCK_BLOCKED,
            "message": "MCP Tool invocation blocked by Agent Interlock",
            "data": {
                "decisionId": decision.decision_id,
                "decision": decision.decision.value,
                "reasonCodes": list(decision.reason_codes),
                "traceId": decision.trace_id,
            },
        },
    }


def _error_response(request_id: str | int | None, error: MCPTransportError) -> dict[str, Any]:
    data = dict(error.data)
    if error.reason_code:
        data["reasonCode"] = error.reason_code
    clean, _ = sanitize_secrets(data)
    body: dict[str, Any] = {"code": error.code, "message": error.message}
    if clean:
        body["data"] = clean
    return {"jsonrpc": "2.0", "id": request_id, "error": body}
