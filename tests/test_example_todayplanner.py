"""Real todayPlanner OAuth/API integration; optional sibling checkout dependency."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from examples.todayplanner.run import run_demo  # noqa: E402

PRODUCT = Path(os.environ.get("TODAYPLANNER_ROOT", ROOT.parent / "todayPlanner"))
AVAILABLE = bool(shutil.which("node") and (PRODUCT / "node_modules/tsx/dist/cli.mjs").is_file())


@unittest.skipUnless(AVAILABLE, "set TODAYPLANNER_ROOT to an installed todayPlanner checkout")
class TodayPlannerRecoveryTests(unittest.TestCase):
    def test_real_approved_schedule_change_recovers_without_unauthorized_or_duplicate_writes(self):
        with tempfile.TemporaryDirectory(prefix="interlock-product-test-") as temporary:
            report = run_demo(PRODUCT, Path(temporary))
            after, before = report["scenarios"]
            self.assertEqual(after["initialLookup"], "COMPLETED")
            self.assertEqual(after["effectGeneration"], 1)
            self.assertEqual(before["initialLookup"], "UNKNOWN")
            self.assertEqual(before["states"][2], "NOT_EXECUTED")
            self.assertEqual(before["effectGeneration"], 2)
            for scenario in report["scenarios"]:
                self.assertEqual(scenario["finalRevision"], scenario["initialRevision"] + 1)
                self.assertEqual(scenario["crossAccountLookup"], "UNKNOWN")
                self.assertFalse(scenario["duplicateReplayChangedState"])
                self.assertEqual(set(scenario["tasks"].values()), {"COMPLETED"})
                self.assertGreater(scenario["evidenceEvents"], 0)
            self.assertEqual(report["unapprovedDispatches"], 0)
            self.assertEqual(report["outOfPolicyDispatches"], 0)
            self.assertEqual(report["readOnlyWriteHTTP"], 403)
            self.assertEqual(report["foreignAccountWriteHTTP"], 404)
            self.assertNotIn('"token"', json.dumps(report))
            self.assertTrue((Path(temporary) / "runs.sqlite3").is_file())
            self.assertTrue((Path(temporary) / "ledger.sqlite3").is_file())


if __name__ == "__main__":
    unittest.main()
