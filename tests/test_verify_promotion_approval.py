"""Negative controls for independent DEV-10 approval evidence.

Fixtures use the actual GitHub workflow deployment-approvals API response
shape: approved reviews include user/state/comment/environments, no timestamp.
"""
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
            "user": {"login": "security-reviewer", "type": "User"},
            "comment": "Approved",
            "environments": [{"name": "dev10-release-promotion"}],
        }]

    def verify(self, entries):
        return mod.attest(entries, run_id=42, attempt=2, actor="initiator", tag="v1.5.0-rc.7")

    def test_independent_human_approval_without_unsupported_timestamp(self):
        evidence = self.verify(self.approval)
        self.assertEqual(evidence["approval"], {"reviewer": "security-reviewer"})
        self.assertEqual(evidence["run_id"], 42)
        self.assertEqual(evidence["run_attempt"], 2)
        self.assertEqual(evidence["initiator"], "initiator")
        self.assertEqual(evidence["tag"], "v1.5.0-rc.7")
        self.assertNotIn("submitted_at", evidence["approval"])

    def test_real_world_bot_wait_timer_and_independent_human_approval(self):
        wait_timer = {
            "state": "approved", "user": {"login": "github-actions[bot]", "type": "Bot"},
            "comment": "30 minute wait timer",
            "environments": [{"name": "dev10-release-promotion"}],
        }
        evidence = self.verify([wait_timer, {**self.approval[0], "user": {"login": "wekhason", "type": "User"}}])
        self.assertEqual(evidence["approval"]["reviewer"], "wekhason")

    def test_missing_self_bot_wrong_environment_and_pending_fail(self):
        wait_timer = {
            "state": "approved", "user": {"login": "github-actions[bot]", "type": "Bot"},
            "environments": [{"name": "dev10-release-promotion"}],
        }
        for entries in (
            [], {}, [{"state": "pending"}], [wait_timer],
            [{**self.approval[0], "user": {"login": "INITIATOR", "type": "User"}}],
            [{**self.approval[0], "user": {"login": "automated", "type": "Bot"}}],
            [{**self.approval[0], "user": {"login": "github-actions[bot]"}}],
            [{**self.approval[0], "environments": [{"name": "staging"}]}],
            [{**self.approval[0], "state": "rejected"}],
            [{**self.approval[0], "user": {}}],
            [{**self.approval[0], "user": {"login": "not a valid login"}}],
        ):
            with self.subTest(entries=entries), self.assertRaises(mod.EvidenceError):
                self.verify(entries)


if __name__ == "__main__":
    unittest.main()
