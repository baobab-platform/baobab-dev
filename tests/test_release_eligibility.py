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
        def review(state, sha=head):
            return {"user": {"login": "security-reviewer"}, "state": state,
                    "commit_id": sha, "submitted_at": "2026-11-15T12:00:00Z"}
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
if __name__ == "__main__":
    unittest.main()
