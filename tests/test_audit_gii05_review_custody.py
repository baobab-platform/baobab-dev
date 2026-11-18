"""GII-05 historical review custody negative controls; no network or writes."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/audit_gii05_review_custody.py"
spec = importlib.util.spec_from_file_location("gii05", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GII05Tests(unittest.TestCase):
    def fixture(self):
        return {
            "pr": 76, "head_sha": module.EXPECTED_HEAD,
            "author_id": 350241706,
            "contributor_ids": [350241706, 356890520, 10001],
            "trusted_reviewer_ids": [356890520, 356900102],
            "history_complete": True,
            "reviews": [
                {"review_id": 1, "reviewer_id": 356890520, "state": "APPROVED",
                 "commit_sha": module.EXPECTED_HEAD, "submitted_at": "2026-11-17T03:20:00Z"},
                {"review_id": 2, "reviewer_id": 356900102, "state": "APPROVED",
                 "commit_sha": module.EXPECTED_HEAD, "submitted_at": "2026-11-17T03:25:00Z"},
            ],
        }

    def test_contributor_approval_excluded_distinct_reviewer_eligible(self):
        result = module.qualify(self.fixture())
        self.assertEqual(result["eligible_reviewer_ids"], [356900102])
        self.assertIn(356890520, result["excluded_contributor_reviewer_ids"])

    def test_only_contributor_approval_fails(self):
        evidence = self.fixture()
        evidence["reviews"] = evidence["reviews"][:1]
        with self.assertRaises(module.QualificationError):
            module.qualify(evidence)

    def test_stale_and_changes_requested_override_approval(self):
        for state, sha in (("CHANGES_REQUESTED", module.EXPECTED_HEAD),
                           ("APPROVED", "a" * 40)):
            with self.subTest(state=state, sha=sha):
                evidence = self.fixture()
                evidence["reviews"].append({
                    "review_id": 3, "reviewer_id": 356900102, "state": state,
                    "commit_sha": sha, "submitted_at": "2026-11-17T03:30:00Z",
                })
                with self.assertRaises(module.QualificationError):
                    module.qualify(evidence)

    def test_incomplete_history_and_missing_numeric_id_refused(self):
        for mutation in ("history", "reviewer", "sha", "timestamp"):
            with self.subTest(mutation=mutation):
                evidence = self.fixture()
                if mutation == "history":
                    evidence["history_complete"] = False
                elif mutation == "reviewer":
                    evidence["reviews"][1]["reviewer_id"] = None
                elif mutation == "sha":
                    evidence["reviews"][1]["commit_sha"] = ""
                else:
                    evidence["reviews"][1]["submitted_at"] = "yesterday"
                with self.assertRaises(module.QualificationError):
                    module.qualify(evidence)

    def test_unknown_or_untrusted_actor_does_not_qualify(self):
        evidence = self.fixture()
        evidence["reviews"][1]["reviewer_id"] = 123456
        with self.assertRaises(module.QualificationError):
            module.qualify(evidence)


if __name__ == "__main__":
    unittest.main()
