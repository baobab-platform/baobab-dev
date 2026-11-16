"""Independent approval custody regression tests; no live GitHub credentials."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "custody", Path(__file__).resolve().parents[1] / "scripts/verify_protected_risk_custody.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

URL = "https://github.com/baobab-platform/baobab-dev/pull/123"
SHA = "a" * 40


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.decision = {"prepared_by": "maker", "approved_by": "checker",
                         "approval_evidence": URL}
        self.pull = {"state": "closed", "merged_at": "2026-11-15T10:00:00Z",
                     "html_url": URL, "base": {"ref": "main"},
                     "head": {"sha": SHA}, "user": {"login": "maker", "databaseId": 1}}
        self.reviews = [{"user": {"login": "checker", "databaseId": 2}, "state": "APPROVED",
                         "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA}]
        self.files = [{"filename": "security/decisions/decision.json", "status": "added"}]

    def check(self):
        return mod.verify(self.decision, self.pull, self.reviews, self.files,
                          trusted_approvers=["checker"], contributor_custody=(1, {1}, {2}))

    def test_valid_independent_review(self):
        self.check()

    def test_stale_review_denied(self):
        self.reviews[0]["commit_id"] = "b" * 40
        with self.assertRaises(ValueError):
            self.check()

    def test_approval_superseded_by_effective_review_state(self):
        for state in ("COMMENTED", "CHANGES_REQUESTED", "DISMISSED"):
            with self.subTest(state=state):
                self.reviews = [
                    {"user": {"login": "checker"}, "state": "APPROVED",
                     "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA},
                    {"user": {"login": "checker"}, "state": state,
                     "submitted_at": "2026-11-15T09:30:00Z", "commit_id": SHA},
                ]
                with self.assertRaises(ValueError):
                    self.check()

    def test_later_current_head_approval_restores_authority(self):
        self.reviews = [
            {"user": {"login": "checker"}, "state": "COMMENTED",
             "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA},
            {"user": {"login": "checker"}, "state": "APPROVED",
             "submitted_at": "2026-11-15T09:30:00Z", "commit_id": SHA},
        ]
        self.check()

    def test_untrusted_reviewer_denied(self):
        self.decision["approved_by"] = "intruder"
        with self.assertRaises(ValueError):
            self.check()

    def test_self_approval_denied(self):
        self.decision["approved_by"] = "maker"
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
                       trusted_approvers=["checker"], contributor_custody=(1, {1}, {2}),
                       decision_path="security/decisions/development/foundation.json")

    def test_approval_exact_decision_path(self):
        mod.verify(self.decision, self.pull, self.reviews, self.files,
                   trusted_approvers=["checker"],
                   decision_path="security/decisions/decision.json")

    def test_unrelated_pr_denied(self):
        self.files = [{"filename": "README.md", "status": "modified"}]
        with self.assertRaises(ValueError):
            self.check()


    def test_out_of_order_reviews_do_not_restore_stale_approval(self):
        self.reviews = [
            {"user": {"login": "checker"}, "state": "CHANGES_REQUESTED",
             "submitted_at": "2026-11-15T10:00:00Z", "commit_id": SHA},
            {"user": {"login": "checker"}, "state": "APPROVED",
             "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA},
        ]
        with self.assertRaises(ValueError):
            self.check()

if __name__ == "__main__":
    unittest.main()
