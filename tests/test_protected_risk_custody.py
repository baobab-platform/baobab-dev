"""Independent approval custody regression tests; no live GitHub credentials."""
import importlib.util
from pathlib import Path
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

spec = importlib.util.spec_from_file_location(
    "custody", Path(__file__).resolve().parents[1] / "scripts/verify_protected_risk_custody.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

URL = "https://github.com/baobab-platform/baobab-dev/pull/123"
SHA = "a" * 40


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.decision = {"prepared_by": "maker", "prepared_by_id": 1,
                         "approved_by": "checker", "approved_by_id": 2,
                         "approval_evidence": URL}
        self.pull = {"state": "closed", "merged_at": "2026-11-15T10:00:00Z",
                     "html_url": URL, "base": {"ref": "main"},
                     "head": {"sha": SHA}, "user": {"login": "maker", "id": 1}}
        self.reviews = [{"user": {"login": "checker", "id": 2}, "state": "APPROVED",
                         "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA}]
        self.files = [{"filename": "security/decisions/decision.json", "status": "added"}]

    def check(self):
        return mod.verify(self.decision, self.pull, self.reviews, self.files,
                          trusted_approver_ids={2}, contributor_custody=(1, {1}))

    def test_valid_independent_review(self):
        result = self.check()
        self.assertEqual(result["approval_id"], "github-review-1")
        self.assertEqual(result["approved_at"], "2026-11-15T09:00:00Z")
        self.assertEqual(result["approved_by_id"], 2)

    def test_numeric_identity_not_login_controls_approval(self):
        self.decision["approved_by"] = "renamed-checker"
        self.reviews[0]["user"]["login"] = "renamed-checker"
        self.check()

    def test_recorded_approver_id_must_match_review_id(self):
        self.decision["approved_by_id"] = 3
        with self.assertRaises(ValueError):
            self.check()

    def test_stale_review_denied(self):
        self.reviews[0]["commit_id"] = "b" * 40
        with self.assertRaises(ValueError):
            self.check()

    def test_approval_superseded_by_effective_review_state(self):
        for state in ("COMMENTED", "CHANGES_REQUESTED", "DISMISSED"):
            with self.subTest(state=state):
                self.reviews = [
                    {"user": {"login": "checker", "id": 2}, "state": "APPROVED",
                     "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA},
                    {"user": {"login": "checker", "id": 2}, "state": state,
                     "submitted_at": "2026-11-15T09:30:00Z", "commit_id": SHA},
                ]
                with self.assertRaises(ValueError):
                    self.check()

    def test_later_current_head_approval_restores_authority(self):
        self.reviews = [
            {"user": {"login": "checker", "id": 2}, "state": "COMMENTED",
             "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA},
            {"user": {"login": "checker", "id": 2}, "state": "APPROVED",
             "submitted_at": "2026-11-15T09:30:00Z", "commit_id": SHA},
        ]
        self.check()

    def test_untrusted_reviewer_denied(self):
        self.decision["approved_by_id"] = 3
        with self.assertRaises(ValueError):
            self.check()

    def test_self_approval_denied(self):
        self.decision["approved_by_id"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_unmerged_decision_denied(self):
        self.pull["merged_at"] = None
        with self.assertRaises(ValueError):
            self.check()

    def test_approval_must_modify_selected_decision(self):
        self.files = [{"filename": "security/decisions/unrelated.json", "status": "added"}]
        with self.assertRaises(ValueError):
            mod.verify(self.decision, self.pull, self.reviews, self.files,
                       trusted_approver_ids={2}, contributor_custody=(1, {1}),
                       decision_path="security/decisions/development/foundation.json")

    def test_approval_exact_decision_path(self):
        mod.verify(self.decision, self.pull, self.reviews, self.files,
                   trusted_approver_ids={2},
                   decision_path="security/decisions/decision.json",
                   contributor_custody=(1, {1}))

    def test_unrelated_pr_denied(self):
        self.files = [{"filename": "README.md", "status": "modified"}]
        with self.assertRaises(ValueError):
            self.check()


    def test_out_of_order_reviews_do_not_restore_stale_approval(self):
        self.reviews = [
            {"user": {"login": "checker", "id": 2}, "state": "CHANGES_REQUESTED",
             "submitted_at": "2026-11-15T10:00:00Z", "commit_id": SHA},
            {"user": {"login": "checker", "id": 2}, "state": "APPROVED",
             "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA},
        ]
        with self.assertRaises(ValueError):
            self.check()

if __name__ == "__main__":
    unittest.main()
