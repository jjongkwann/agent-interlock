"""``interlock verify``: the scenario matrix, the contract check, and the exit codes.

The fixture project under ``tests/fixtures/verify_project`` is a correct project, so every
scenario has to pass against it. The interesting tests are the ones that break it: a widened
domain allowlist has to make the destination scenario *fail*, and a schema that stops marking its
destination has to make the same scenario report NOT-APPLICABLE rather than quietly pass. A
verifier that cannot fail is not a verifier.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from agent_interlock import InMemoryLedger
from agent_interlock.__main__ import main
from agent_interlock.verify import (
    NOT_APPLICABLE,
    SCENARIOS,
    VerificationReport,
    VerifyError,
    canary_leaks,
    load_project,
    record_test_executed,
    run_scenario,
    run_verification,
)
from agent_interlock.verify_corpus import CANARY_CORPUS, RAG_RUNBOOK_SECRET

FIXTURE = Path(__file__).parent / "fixtures" / "verify_project" / "project.py"


def scenario(scenario_id: str):
    return next(item for item in SCENARIOS if item.id == scenario_id)


class VerifyFixtureProjectTests(unittest.TestCase):
    def test_every_scenario_passes_against_a_correct_project(self):
        report = run_verification(str(FIXTURE))

        self.assertTrue(report.passed, json.dumps(report.to_dict(), indent=2))
        self.assertEqual([result.id for result in report.results], [item.id for item in SCENARIOS])
        self.assertEqual([result.observed for result in report.results if result.observed == NOT_APPLICABLE], [])
        self.assertEqual(report.verified, len(SCENARIOS))
        self.assertEqual(report.not_applicable, 0)
        self.assertEqual(report.failed, 0)

    def test_each_scenario_reaches_the_control_it_names(self):
        report = run_verification(str(FIXTURE))
        observed = {result.id: result.observed for result in report.results}

        self.assertEqual(
            observed,
            {
                "VERIFY-M1-POISONED-DESCRIPTION": "QUARANTINE",
                "VERIFY-M2-DEFINITION-DRIFT": "QUARANTINE",
                "VERIFY-M3-CROSS-SERVER-REFERENCE": "QUARANTINE",
                "VERIFY-M8-CREDENTIAL-IN-RESULT": "REDACTED",
                "VERIFY-M9-UNDECLARED-DESTINATION": "BLOCK",
                "VERIFY-M9-VOLUME": "BLOCK",
                "VERIFY-SIDE-EFFECT-UNDECLARED": "BLOCK",
                "VERIFY-GOAL-HIJACK": "NO-UNDECLARED-TOOL",
                "VERIFY-MEMORY-POISONING": "BLOCK",
            },
        )
        evidence = {result.id: result.evidence for result in report.results}
        self.assertIn("L1-M1-METADATA-INSTRUCTION", evidence["VERIFY-M1-POISONED-DESCRIPTION"]["buildError"])
        self.assertIn("L1-M3-CROSS-SERVER-REFERENCE", evidence["VERIFY-M3-CROSS-SERVER-REFERENCE"]["buildError"])
        self.assertIn("L1-M2-DEFINITION-DRIFT", evidence["VERIFY-M2-DEFINITION-DRIFT"]["reasonCodes"])
        self.assertIn("D5_REDACTED", evidence["VERIFY-M8-CREDENTIAL-IN-RESULT"]["resultLabels"])
        self.assertFalse(evidence["VERIFY-M8-CREDENTIAL-IN-RESULT"]["canaryInResult"])
        self.assertIn("L1-M9-NEW-DESTINATION", evidence["VERIFY-M9-UNDECLARED-DESTINATION"]["reasonCodes"])
        self.assertEqual(evidence["VERIFY-M9-UNDECLARED-DESTINATION"]["connectorCalls"], 0)
        self.assertIn("L1-M9-VOLUME-EXCEEDED", evidence["VERIFY-M9-VOLUME"]["reasonCodes"])
        self.assertIn("L1-UNDECLARED-SIDE-EFFECT", evidence["VERIFY-SIDE-EFFECT-UNDECLARED"]["reasonCodes"])
        self.assertNotIn("exfiltrate_all", evidence["VERIFY-GOAL-HIJACK"]["declaredTools"])
        self.assertTrue(evidence["VERIFY-MEMORY-POISONING"]["redactedAtRead"])
        self.assertIn("L1-M8-CREDENTIAL-DETECTED", evidence["VERIFY-MEMORY-POISONING"]["reasonCodes"])

    def test_every_scenario_leaves_a_test_executed_event_and_no_canary_in_the_ledger(self):
        report = run_verification(str(FIXTURE))
        for result in report.results:
            self.assertGreaterEqual(result.evidence["ledgerEvents"], 1, result.id)
            self.assertNotIn("canaryLeaks", result.evidence, result.id)


class WeakenedProjectTests(unittest.TestCase):
    """The fixture, broken on purpose, one control at a time."""

    def test_a_widened_domain_allowlist_fails_the_destination_scenario(self):
        module = load_project(str(FIXTURE))
        manifest = json.loads(module.MANIFEST.read_text(encoding="utf-8"))
        for node in manifest["spec"]["nodes"]:
            if node["id"] == "tool.send-email":
                node["allowedDomains"] = ["customer.example", "attacker.invalid"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "architecture.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            module.MANIFEST = path
            result = run_scenario(module, scenario("VERIFY-M9-UNDECLARED-DESTINATION"))

        self.assertFalse(result.passed)
        self.assertEqual(result.observed, "ALLOW")
        self.assertEqual(result.evidence["connectorCalls"], 1)

    def test_an_unmarked_destination_property_is_reported_inapplicable_not_passed(self):
        module = load_project(str(FIXTURE))
        module.BINDINGS = tuple(
            replace(binding, definition=replace(binding.definition, input_schema=_unmarked(binding)))
            for binding in module.BINDINGS
        )
        result = run_scenario(module, scenario("VERIFY-M9-UNDECLARED-DESTINATION"))

        self.assertEqual(result.observed, NOT_APPLICABLE)
        self.assertTrue(result.passed)
        self.assertIn("no tool marks a destination property", result.evidence["reason"])

    def test_a_project_with_no_volume_cap_reports_the_control_disarmed(self):
        module = load_project(str(FIXTURE))
        module.MAX_EXPORT_RECORDS = 0
        result = run_scenario(module, scenario("VERIFY-M9-VOLUME"))

        self.assertEqual(result.observed, NOT_APPLICABLE)
        self.assertIn("max_export_records", result.evidence["reason"])

    def test_a_project_with_no_volume_cap_is_counted_not_applicable_not_verified(self):
        module = load_project(str(FIXTURE))
        module.MAX_EXPORT_RECORDS = 0
        results = tuple(run_scenario(module, item) for item in SCENARIOS)

        report = VerificationReport(str(FIXTURE), str(module.MANIFEST), results)
        self.assertTrue(report.passed)
        self.assertEqual(report.not_applicable, 1)
        self.assertEqual(report.failed, 0)
        self.assertEqual(report.verified, len(SCENARIOS) - 1)

        strict_report = VerificationReport(str(FIXTURE), str(module.MANIFEST), results, strict=True)
        self.assertFalse(strict_report.passed)
        self.assertEqual(strict_report.not_applicable, 0)
        self.assertEqual(strict_report.failed, 1)
        self.assertEqual(strict_report.verified, len(SCENARIOS) - 1)


def _unmarked(binding):
    schema = deepcopy(dict(binding.definition.input_schema))
    for value in schema.get("properties", {}).values():
        value.pop("format", None)
    return schema


class LoadProjectTests(unittest.TestCase):
    def test_a_module_missing_bindings_names_what_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "half_a_project.py"
            path.write_text(
                "from pathlib import Path\n"
                "MANIFEST = Path('architecture.json')\n"
                "TENANT_ID = 'tenant-a'\n"
                "SOURCE_ACTOR_ID = 'agent.support'\n"
                "def build(bindings=(), *, ledger=None):\n"
                "    return None, ()\n",
                encoding="utf-8",
            )
            with self.assertRaises(VerifyError) as caught:
                load_project(str(path))
        self.assertIn("BINDINGS", str(caught.exception))

    def test_a_missing_file_and_a_missing_module_both_raise_verify_error(self):
        with self.assertRaises(VerifyError):
            load_project("/nonexistent/project.py")
        with self.assertRaises(VerifyError):
            load_project("agent_interlock.not_a_module")

    def test_a_module_that_is_not_a_project_is_rejected_by_name(self):
        with self.assertRaises(VerifyError) as caught:
            load_project("agent_interlock.verify")
        self.assertIn("MANIFEST", str(caught.exception))

    def test_a_path_load_does_not_shadow_an_installed_module(self):
        module = load_project(str(FIXTURE))
        self.assertNotEqual(module.__name__, "project")
        self.assertEqual(module.TENANT_ID, "tenant-a")


class VerifyCLITests(unittest.TestCase):
    def test_a_clean_project_prints_the_report_and_exits_zero(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["verify", str(FIXTURE)])

        self.assertEqual(code, 0)
        report = json.loads(stream.getvalue())
        expected_keys = {"project", "manifest", "passed", "verified", "notApplicable", "failed", "results"}
        self.assertEqual(set(report), expected_keys)
        self.assertTrue(report["passed"])
        self.assertEqual(report["verified"], len(SCENARIOS))
        self.assertEqual(report["notApplicable"], 0)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(len(report["results"]), len(SCENARIOS))
        self.assertEqual(set(report["results"][0]), {"id", "expected", "observed", "passed", "evidence"})

    def test_out_writes_the_same_report_to_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "report.json"
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["verify", str(FIXTURE), "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8")), json.loads(stream.getvalue()))

    def test_an_unloadable_project_exits_two(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(io.StringIO()) as errors:
            code = main(["verify", "not.a.module"])

        self.assertEqual(code, 2)
        self.assertEqual(stream.getvalue(), "")
        self.assertEqual(json.loads(errors.getvalue())["error"]["code"], "INTERLOCK-VERIFY-PROJECT-INVALID")

    def test_a_failing_scenario_exits_one(self):
        module = load_project(str(FIXTURE))
        manifest = json.loads(module.MANIFEST.read_text(encoding="utf-8"))
        for node in manifest["spec"]["nodes"]:
            if node["id"] == "tool.send-email":
                node["allowedDomains"] = ["customer.example", "attacker.invalid"]
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "architecture.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            project_path = Path(directory) / "weak_project.py"
            project_path.write_text(
                f"from agent_interlock.verify import load_project\n"
                f"_source = load_project({str(FIXTURE)!r})\n"
                f"MANIFEST = {str(manifest_path)!r}\n"
                "import pathlib\n"
                "MANIFEST = pathlib.Path(MANIFEST)\n"
                "TENANT_ID = _source.TENANT_ID\n"
                "SOURCE_ACTOR_ID = _source.SOURCE_ACTOR_ID\n"
                "BINDINGS = _source.BINDINGS\n"
                "def build(bindings=BINDINGS, *, ledger=None):\n"
                "    _source.MANIFEST = MANIFEST\n"
                "    return _source.build(bindings, ledger=ledger)\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["verify", str(project_path)])

        self.assertEqual(code, 1)

    def test_strict_turns_a_not_applicable_scenario_into_a_failing_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            project_path = Path(directory) / "no_cap_project.py"
            project_path.write_text(
                f"from agent_interlock.verify import load_project\n"
                f"_source = load_project({str(FIXTURE)!r})\n"
                "MANIFEST = _source.MANIFEST\n"
                "TENANT_ID = _source.TENANT_ID\n"
                "SOURCE_ACTOR_ID = _source.SOURCE_ACTOR_ID\n"
                "BINDINGS = _source.BINDINGS\n"
                "def build(bindings=BINDINGS, *, ledger=None):\n"
                "    _source.MAX_EXPORT_RECORDS = 0\n"
                "    return _source.build(bindings, ledger=ledger)\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()) as lax_stream:
                lax_code = main(["verify", str(project_path)])
            with contextlib.redirect_stdout(io.StringIO()) as strict_stream:
                strict_code = main(["verify", str(project_path), "--strict"])

        self.assertEqual(lax_code, 0)
        self.assertEqual(json.loads(lax_stream.getvalue())["notApplicable"], 1)
        self.assertEqual(strict_code, 1)
        self.assertEqual(json.loads(strict_stream.getvalue())["failed"], 1)


class TestExecutedEventTests(unittest.TestCase):
    """The event shape docs/05 section 9 pins, now written by one function for both callers."""

    def test_the_payload_is_the_one_the_l1_matrix_writes(self):
        ledger = InMemoryLedger()
        record_test_executed(ledger, test_id="VERIFY-X", verdict="BLOCK", passed=True, tenant_id="tenant-a")

        event = list(ledger.all())[-1]
        self.assertEqual(event.event_type, "TEST_EXECUTED")
        self.assertEqual(event.payload, {"testId": "VERIFY-X", "verdict": "BLOCK", "passed": True})
        self.assertEqual(event.trace_id, "l1-sim-VERIFY-X")
        self.assertEqual(event.span_id, "test-VERIFY-X")
        self.assertEqual(event.source_actor_id, "l1-sim-runner")
        self.assertEqual(event.data_source, "SIMULATION")

    def test_canary_leaks_finds_a_marker_written_in_plaintext(self):
        ledger = InMemoryLedger()
        self.assertEqual(canary_leaks(ledger), ())
        record_test_executed(
            ledger,
            test_id=RAG_RUNBOOK_SECRET.value,
            verdict="BLOCK",
            passed=False,
            tenant_id="tenant-a",
        )
        self.assertEqual(canary_leaks(ledger), (RAG_RUNBOOK_SECRET.canary_id,))
        self.assertEqual(len(CANARY_CORPUS), 4)


if __name__ == "__main__":
    unittest.main()
