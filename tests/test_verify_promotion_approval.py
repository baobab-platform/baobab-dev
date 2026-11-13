"""Negative controls for independent DEV-10 approval evidence."""
import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).resolve().parents[1] / "scripts/verify_promotion_approval.py"
spec = importlib.util.spec_from_file_location("verify_promotion_approval", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.approval = [{
            "state": "approved",
            "user": {"login": "security-reviewer"},
            "submitted_at": "2026-11-13T00:00:00Z",
            "environments": [{"name": "dev10-release-promotion"}],
        }]

    def verify(self, entries):
        return mod.attest(entries, run_id=42, attempt=2, actor="initiator", tag="v1.5.0-rc.5")

    def test_independent_approval(self):
        evidence = self.verify(self.approval)
        self.assertEqual(evidence["approval"]["reviewer"], "security-reviewer")
        self.assertEqual(evidence["run_attempt"], 2)

    def test_missing_self_rejected_wrong_environment_and_pending_fail(self):
        for entries in (
            [], {}, [{"state": "pending"}],
            [{**self.approval[0], "user": {"login": "INITIATOR"}}],
            [{**self.approval[0], "environments": [{"name": "staging"}]}],
            [{**self.approval[0], "state": "rejected"}],
            [{**self.approval[0], "submitted_at": None}],
        ):
            with self.subTest(entries=entries), self.assertRaises(mod.EvidenceError):
                self.verify(entries)


if __name__ == "__main__":
    unittest.main()
