"""Shared draft writes must not overwrite a concurrently edited revision."""

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_interlock.project_store import ProjectConflict, SQLiteProjectStore


class ProjectStoreTests(unittest.TestCase):
    def test_concurrent_revision_conflict_restart_and_tenant_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "projects.sqlite3"
            store = SQLiteProjectStore(path)
            manifest = {"metadata": {"id": "draft"}, "spec": {"nodes": []}}
            original = store.save("team", "draft", manifest, 0, "alice")
            self.assertEqual(original["revision"], 1)

            def save(subject):
                try:
                    return SQLiteProjectStore(path).save("team", "draft", manifest, 1, subject)
                except ProjectConflict:
                    return None

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(save, ["alice", "bob"]))
            winner, = [result for result in results if result]
            self.assertEqual(winner["revision"], 2)
            self.assertEqual(SQLiteProjectStore(path).get("team", "draft"), winner)
            self.assertIsNone(store.get("other", "draft"))
            self.assertEqual(store.list("other"), [])
            self.assertEqual(store.list("team")[0]["updatedBy"], winner["updatedBy"])
            for invalid in (None, {"metadata": []}, {"metadata": {"id": "other"}}):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    store.save("team", "draft", invalid, 2, "alice")
            self.assertEqual(store.get("team", "draft"), winner)


if __name__ == "__main__":
    unittest.main()
