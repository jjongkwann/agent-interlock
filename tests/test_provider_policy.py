"""Routing faults must preserve the reviewed data boundary and exact tool approval."""
import json
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from test_configurable_runtime import engine, graph

from agent_interlock.canonical import canonical_digest
from agent_interlock.configurable_runtime import (
    RUNTIME_KEY,
    configured_definition,
    prepare_runtime_graph,
    runtime_status,
)
from agent_interlock.models import PolicyMode
from agent_interlock.orchestration import WorkflowRunState
from agent_interlock.provider_clients import openai_request
from agent_interlock.provider_policy import ProviderCallError, call_with_policy, validate_provider_policy


def routed_graph(*, http=False):
    value = graph(model=True, http=http)
    source, tool, provider = value.nodes
    fallback = replace(provider, actor=replace(provider.actor, id="provider.openai",
                                               allowed_domains=frozenset({"api.openai.com"})))
    config = {**source.annotations[RUNTIME_KEY], "providerPolicy": {
        "maxAttempts": 2, "onError": {"RATE_LIMIT": "RETRY_THEN_FAILOVER", "SERVER": "FAILOVER"},
        "fallbacks": [{"kind": "OPENAI", "model": "fixture-openai", "credentialRef": "fixture",
                       "providerActorId": fallback.id}],
    }}
    return prepare_runtime_graph(replace(value,
        nodes=(replace(source, annotations={RUNTIME_KEY: config}), tool, provider, fallback),
        edges=(*value.edges, replace(value.edges[1], id="openai-inference", target=fallback.id))))


def completion(*, content="Done.", call=None):
    return json.dumps({"choices": [{"message": {"content": content,
        **({"tool_calls": [call]} if call else {})}, "finish_reason": "tool_calls" if call else "stop"}],
        "usage": {"prompt_tokens": 13, "completion_tokens": 7}}).encode()


class ProviderPolicyTests(unittest.TestCase):
    def test_bounded_retry_then_failover_records_errors_without_provider_content(self):
        value = routed_graph()
        calls, records = [], []
        config = value.nodes[0].annotations[RUNTIME_KEY]

        def invoke(candidate, timeout):
            calls.append((candidate["kind"], timeout))
            if candidate["kind"] == "ANTHROPIC":
                error = RuntimeError("secret-token-and-prompt-must-not-be-stored")
                error.status_code = 429
                raise error
            return {"content": [], "usage": {"input_tokens": 12, "output_tokens": 4}}

        response = call_with_policy(config, invoke, records.append, deadline_epoch=time.time() + 30)
        self.assertEqual([kind for kind, _ in calls], ["ANTHROPIC", "ANTHROPIC", "OPENAI"])
        self.assertEqual([record["action"] for record in records], ["RETRY", "FAILOVER", "COMPLETE"])
        self.assertEqual(records[0]["usage"]["status"], "UNKNOWN")
        self.assertEqual(records[2]["usage"]["inputCount"], 12)
        self.assertEqual(response["usage"]["output_tokens"], 4)
        self.assertTrue(all(record["latencyMs"] >= 0 for record in records))
        self.assertNotIn("secret-token", json.dumps(records))

    def test_terminal_error_never_routes_or_retries_and_deadline_bounds_delay(self):
        config = routed_graph().nodes[0].annotations[RUNTIME_KEY]
        for kind in ("AUTH", "POLICY", "UNKNOWN", "INVALID_RESPONSE"):
            records = []
            with self.subTest(kind=kind), self.assertRaisesRegex(ProviderCallError, kind):
                call_with_policy(config, lambda *_: (_ for _ in ()).throw(ProviderCallError(kind)),
                                 records.append, deadline_epoch=time.time() + 30)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["action"], "BLOCK")
        config = {**config, "providerPolicy": {**config["providerPolicy"], "retryDelaySeconds": 2}}
        records = []
        with self.assertRaises(ProviderCallError), patch("time.sleep") as sleep:
            call_with_policy(config, lambda *_: (_ for _ in ()).throw(ProviderCallError("RATE_LIMIT")),
                             records.append, deadline_epoch=time.time() + 0.1, sleep=sleep)
            sleep.assert_not_called()
        self.assertEqual(records[0]["action"], "BLOCK")

    def test_fallback_uses_its_own_bounded_policy(self):
        config = routed_graph().nodes[0].annotations[RUNTIME_KEY]
        fallback = {**config["providerPolicy"]["fallbacks"][0], "policy": {"maxAttempts": 1}}
        config = {**config, "providerPolicy": {**config["providerPolicy"], "fallbacks": [fallback]}}
        records = []
        with self.assertRaises(ProviderCallError):
            call_with_policy(config, lambda *_: (_ for _ in ()).throw(ProviderCallError("RATE_LIMIT")),
                             records.append, deadline_epoch=time.time() + 30)
        self.assertEqual([record["provider"] for record in records], ["ANTHROPIC", "ANTHROPIC", "OPENAI"])
        self.assertEqual([record["action"] for record in records], ["RETRY", "FAILOVER", "BLOCK"])
        for deadline in (float("nan"), float("inf"), True):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                call_with_policy(config, lambda *_: self.fail("network called"), records.append,
                                 deadline_epoch=deadline)

    def test_late_tool_proposal_is_rejected_and_returned_usage_is_preserved(self):
        config = routed_graph().nodes[0].annotations[RUNTIME_KEY]
        records, calls = [], []

        def late_response(*_):
            calls.append("network")
            return {"content": [{"type": "tool_use", "id": "late", "name": "write", "input": {}}],
                    "stopReason": "tool_use", "usage": {"input_tokens": 4, "output_tokens": 3}}

        with patch("agent_interlock.provider_policy.time.time", side_effect=[100, 100.02, 100.02]):
            with self.assertRaisesRegex(ProviderCallError, "TIMEOUT"):
                call_with_policy(config, late_response, records.append, deadline_epoch=100.01)
        self.assertEqual(calls, ["network"])
        self.assertEqual(records[0]["outcome"], "ERROR")
        self.assertEqual(records[0]["action"], "BLOCK")
        self.assertEqual(records[0]["usage"]["inputCount"], 4)

    def test_rejects_unknown_fallbacks_missing_credentials_and_weakened_policy(self):
        value = routed_graph()
        with patch("importlib.util.find_spec", return_value=object()):
            self.assertTrue(runtime_status(value, ("fixture",))["ready"])
            variants = [
                replace(value, nodes=value.nodes[:-1], edges=value.edges[:-1]),
                replace(value, edges=value.edges[:-1]),
                replace(value, edges=(*value.edges[:-1], replace(value.edges[-1], policy=replace(
                    value.edges[-1].policy, max_export_bytes=200000)))),
                replace(value, edges=(*value.edges[:-1], replace(value.edges[-1], policy=replace(
                    value.edges[-1].policy, mode=PolicyMode.SHADOW)))),
                replace(value, nodes=(*value.nodes[:-1], replace(value.nodes[-1], actor=replace(
                    value.nodes[-1].actor, data_access=frozenset({"D2"}))))),
            ]
            for candidate in variants:
                self.assertFalse(runtime_status(candidate, ("fixture",))["ready"])
            self.assertFalse(runtime_status(value, ())["ready"])
        for policy in ({"maxAttempts": 4}, {"onError": {"POLICY": "FAILOVER"}},
                       {"fallbacks": [{"kind": "CUSTOM"}]}, {"retryDelaySeconds": float("nan")}):
            with self.subTest(policy=policy), self.assertRaises((ValueError, KeyError)):
                validate_provider_policy({**value.nodes[0].annotations[RUNTIME_KEY], "providerPolicy": policy})

    def test_cross_provider_failover_rechecks_controls_and_holds_write_until_approval(self):
        value = routed_graph(http=True)
        tool_name = configured_definition(value.nodes[1]).tool_name
        model_calls, writes = [], []

        def anthropic(*_, **__):
            error = RuntimeError("api-key-and-prompt-must-not-leak")
            error.status_code = 503
            raise error

        def model_request(endpoint, method, body, headers, **_):
            model_calls.append(json.loads(body))
            self.assertEqual(endpoint, "https://api.openai.com/v1/chat/completions")
            self.assertEqual(method, "POST")
            self.assertEqual(headers["Authorization"], "Bearer test")
            if len(model_calls) == 1:
                return 200, {}, completion(content=None, call={"id": "call-write", "type": "function",
                    "function": {"name": tool_name, "arguments": '{"name":"Ada"}'}})
            return 200, {}, completion()

        def write(_, __, body, ___, **____):
            writes.append(json.loads(body))
            return 200, {"Content-Type": "application/json"}, body

        with patch("importlib.util.find_spec", return_value=object()):
            runner, store, ledger = engine(value, anthropic_client_factory=anthropic,
                                           model_http_request=model_request, http_request=write)
        held = runner.start(tenant_id="tenant", workflow_input={"tasks": {"transform": {"prompt": "Update Ada"}}})
        self.assertEqual(held.state, WorkflowRunState.WAITING_APPROVAL, held.to_dict())
        self.assertEqual(writes, [])
        pending = held.tasks["transform"].pending_call
        store.approve(tenant_id="tenant", run_id=held.id,
                      task_id="transform:" + pending["requestId"], approved_by="human")
        completed = runner.resume(tenant_id="tenant", run_id=held.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED, completed.to_dict())
        self.assertEqual(writes, [{"name": "Ada"}])
        self.assertEqual(model_calls[1]["messages"][-1]["role"], "tool")
        attempts = [event for event in ledger.all() if event.event_type == "PROVIDER_CALL_RECORDED"]
        self.assertEqual([event.payload["provider"] for event in attempts],
                         ["ANTHROPIC", "OPENAI", "ANTHROPIC", "OPENAI"])
        self.assertEqual(attempts[1].payload["usage"]["inputCount"], 13)
        controls = [event for event in ledger.all() if event.event_type == "CONTROL_EVALUATED"
                    and event.target_actor_id in {"provider", "provider.openai"}]
        self.assertEqual(len(controls), 4)
        outbound = [event.payload["argumentsHash"] for event in ledger.all()
                    if event.event_type == "INTERACTION_REQUESTED" and event.target_actor_id == "provider.openai"]
        self.assertEqual(outbound, [canonical_digest(body) for body in model_calls])
        serialized = json.dumps([event.to_dict() for event in ledger.all()])
        self.assertNotIn("api-key-and-prompt-must-not-leak", serialized)
        self.assertTrue(all(event.payload["workflowTaskId"] == "transform" for event in attempts))

    def test_actual_runtime_policy_block_stops_before_any_candidate_network(self):
        value = routed_graph()
        source = value.nodes[0]
        source = replace(source, annotations={RUNTIME_KEY: {**source.annotations[RUNTIME_KEY],
            "systemPrompt": "api_key=" + "a" * 48}})
        value = replace(value, nodes=(source, *value.nodes[1:]))
        network = []
        with patch("importlib.util.find_spec", return_value=object()):
            runner, _, ledger = engine(value,
                anthropic_client_factory=lambda *_args, **_kwargs: network.append("anthropic"),
                model_http_request=lambda *_args, **_kwargs: network.append("openai"))
        failed = runner.start(tenant_id="tenant", workflow_input={"tasks": {"transform": {"prompt": "Process"}}})
        self.assertEqual(failed.state, WorkflowRunState.FAILED)
        self.assertEqual(network, [])
        records = [event.payload for event in ledger.all() if event.event_type == "PROVIDER_CALL_RECORDED"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["errorKind"], "POLICY")

    def test_openai_wire_is_single_call_and_rejects_malformed_tool_arguments(self):
        candidate = {"kind": "OPENAI", "model": "fixture"}
        seen = []

        def request(*args, **kwargs):
            seen.append(args)
            return 200, {}, completion(call={"id": "call", "type": "function",
                "function": {"name": "tool", "arguments": "unparseable"}})

        with self.assertRaisesRegex(ProviderCallError, "INVALID_RESPONSE") as error:
            openai_request(candidate, request=request, messages=[{"role": "user", "content": "prompt"}],
                           tools=[], system="system", max_tokens=100, key="secret", timeout=2)
        self.assertEqual(len(seen), 1)
        self.assertEqual(error.exception.usage["prompt_tokens"], 13)

    def test_openai_refusal_empty_and_incomplete_turns_fail_closed(self):
        for message, finish in (({"content": None, "refusal": "I cannot perform this request."}, "stop"),
                                ({"content": None}, "stop"), ({"content": "  "}, "stop"),
                                ({"content": "Not finished"}, "length"),
                                ({"content": "No tool call"}, "tool_calls")):
            with self.subTest(message=message, finish=finish), self.assertRaisesRegex(
                    ProviderCallError, "INVALID_RESPONSE"):
                openai_request({"kind": "OPENAI", "model": "fixture"},
                    request=lambda *_args, **_kwargs: (200, {}, json.dumps({"choices": [{
                        "message": message, "finish_reason": finish}]}).encode()),
                    messages=[{"role": "user", "content": "prompt"}], tools=[],
                    system="system", max_tokens=100, key="secret", timeout=2)


if __name__ == "__main__":
    unittest.main()
