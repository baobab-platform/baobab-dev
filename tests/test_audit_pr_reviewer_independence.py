"""Tests for the read-only live PR reviewer independence classifier."""
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "audit_pr_reviewer_independence", SCRIPTS / "audit_pr_reviewer_independence.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ReviewerAuditTests(unittest.TestCase):
    def test_author_is_not_independent(self):
        result = mod.classify_reviewer({"login": "maker", "id": 1, "type": "User"}, 1, {3})
        self.assertEqual(result["status"], "not-independent")
        self.assertEqual(result["reason"], "pull-request author")

    def test_commit_contributor_is_not_independent(self):
        result = mod.classify_reviewer({"login": "contributor", "id": 3, "type": "User"}, 1, {3})
        self.assertEqual(result["status"], "not-independent")
        self.assertEqual(result["reason"], "commit author, co-author, or committer")

    def test_login_rename_does_not_bypass_numeric_contributor_exclusion(self):
        result = mod.classify_reviewer({"login": "new-login", "id": 3, "type": "User"}, 1, {3})
        self.assertEqual(result["status"], "not-independent")
        self.assertEqual(result["reason"], "commit author, co-author, or committer")

    def test_non_contributor_human_is_independent(self):
        result = mod.classify_reviewer({"login": "reviewer", "id": 2, "type": "User"}, 1, {3})
        self.assertEqual(result["status"], "independent")

    def test_bot_is_not_a_human_approval_candidate(self):
        result = mod.classify_reviewer({"login": "automation", "id": 9, "type": "Bot"}, 1, {3})
        self.assertEqual(result["status"], "non-human-reviewer")

    def test_missing_numeric_identity_fails_closed(self):
        with self.assertRaises(mod.IndependenceError):
            mod.classify_reviewer({"login": "unknown", "type": "User"}, 1, {3})


if __name__ == "__main__":
    unittest.main()
