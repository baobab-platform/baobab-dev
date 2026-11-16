"""Release eligibility regressions: RC iterations and GA digest reuse."""
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location("eligibility", Path(__file__).resolve().parents[1] / "scripts/release_eligibility.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ReleaseEligibilityTests(unittest.TestCase):
    tags = ["v1.5.0", "v1.5.1", "v1.5.2-rc.1"]
    def test_rc_iterations_with_changed_baseline(self):
        for n in (1, 2, 3):
            self.assertEqual(mod.decide(f"v1.5.2-rc.{n}", self.tags, True, True), "changed-toolchain")
    def test_unchanged_refused(self):
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.decide("v1.5.2-rc.2", self.tags, False, False)
    def test_unresolved_lock_refused(self):
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.decide("v1.5.2-rc.2", self.tags, True, False)
    def test_reviewed_maintenance(self):
        self.assertEqual(mod.decide("v1.5.2-rc.2", self.tags, False, False, True), "reviewed-maintenance")
    def test_ga_not_rebuilt(self):
        self.assertEqual(mod.decide("v1.5.2", self.tags, False, False), "qualified-RC-digest-reuse")
    def test_finalized_family_refused(self):
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.decide("v1.5.1-rc.2", self.tags, True, True)
    def test_bad_tag_refused(self):
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.decide("v1.5.2-beta.1", self.tags, True, True)
    def test_numeric_previous_ga(self):
        self.assertEqual(mod.previous_ga("v2.0.0", ["v1.9.0", "v1.10.0"]), "v1.10.0")
    def test_current_head_review_transitions(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        next_review_id = 0
        def review(state, sha=head):
            nonlocal next_review_id
            next_review_id += 1
            return {"id": next_review_id,
                    "user": {"login": "security-reviewer", "id": 200},
                    "state": state, "commit_id": sha,
                    "submitted_at": "2026-11-15T12:00:00Z"}
        mod.verify_current_approval(pr, [review("APPROVED")], "author")
        for sequence in (
            [review("APPROVED", "b" * 40)],
            [review("APPROVED"), review("COMMENTED")],
            [review("APPROVED"), review("CHANGES_REQUESTED")],
            [review("APPROVED"), review("DISMISSED")],
        ):
            with self.subTest(sequence=sequence), self.assertRaises(mod.ReleaseEligibilityError):
                mod.verify_current_approval(pr, sequence, "author")
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [review("APPROVED")], "security-reviewer")
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [review("APPROVED")] * 100, "author")
        missing_id = review("APPROVED")
        del missing_id["id"]
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [missing_id], "author")
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [review("APPROVED")], "author",
                                        trusted_approvers=["different-reviewer"])
    def test_out_of_order_reviews_do_not_restore_stale_approval(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        approval = {"id": 1, "user": {"login": "checker", "id": 201},
                    "state": "APPROVED", "commit_id": head,
                    "submitted_at": "2026-11-15T09:00:00Z"}
        superseding = {"id": 2, "user": {"login": "checker", "id": 201},
                       "state": "COMMENTED", "commit_id": head,
                       "submitted_at": "2026-11-15T10:00:00Z"}
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [superseding, approval], "maker")

if __name__ == "__main__":
    unittest.main()
