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
                    "user": {"login": "security-reviewer", "id": 200, "type": "User"},
                    "state": state, "commit_id": sha,
                    "submitted_at": "2026-11-15T12:00:00Z"}
        mod.verify_current_approval(pr, [review("APPROVED")], 100)
        for sequence in (
            [review("APPROVED", "b" * 40)],
            [review("APPROVED"), review("COMMENTED")],
            [review("APPROVED"), review("CHANGES_REQUESTED")],
            [review("APPROVED"), review("DISMISSED")],
        ):
            with self.subTest(sequence=sequence), self.assertRaises(mod.ReleaseEligibilityError):
                mod.verify_current_approval(pr, sequence, 100)
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [review("APPROVED")], 200)
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [review("APPROVED")] * 100, 100)
        missing_id = review("APPROVED")
        del missing_id["id"]
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [missing_id], 100)
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [review("APPROVED")], 100,
                                        trusted_approver_ids={999})
    def test_out_of_order_reviews_do_not_restore_stale_approval(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        approval = {"id": 1, "user": {"login": "checker", "id": 201, "type": "User"},
                    "state": "APPROVED", "commit_id": head,
                    "submitted_at": "2026-11-15T09:00:00Z"}
        superseding = {"id": 2, "user": {"login": "checker", "id": 201},
                       "state": "COMMENTED", "commit_id": head,
                       "submitted_at": "2026-11-15T10:00:00Z"}
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [superseding, approval], 100)

    def test_bot_reviews_are_ignored_but_other_non_user_types_fail_closed(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        bot = {"id": 1, "user": {"type": "Bot", "login": "automation[bot]"},
               "state": "APPROVED", "commit_id": head,
               "submitted_at": "2026-11-15T12:00:00Z"}
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [bot], 100)
        for account in (
            {"type": "App", "login": "review-app[bot]", "id": 201},
            {"type": "Organization", "login": "org", "id": 201},
            {"login": "untyped", "id": 201},
        ):
            review = dict(bot, id=2, user=account)
            with self.subTest(account=account), self.assertRaisesRegex(
                mod.ReleaseEligibilityError, "non-User or untyped"
            ):
                mod.verify_current_approval(pr, [review], 100)

    def test_typed_user_requires_positive_non_boolean_numeric_id(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        for user_id in (None, 0, -1, True, "201", 201.0):
            review = {"id": 1, "user": {"type": "User", "login": "reviewer", "id": user_id},
                      "state": "APPROVED", "commit_id": head,
                      "submitted_at": "2026-11-15T12:00:00Z"}
            with self.subTest(user_id=user_id), self.assertRaisesRegex(
                mod.ReleaseEligibilityError, "positive numeric GitHub user ID"
            ):
                mod.verify_current_approval(pr, [review], 100)

    def test_latest_review_is_selected_by_numeric_id_not_login(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        older = {"id": 1, "user": {"type": "User", "login": "old-login", "id": 201},
                 "state": "APPROVED", "commit_id": head,
                 "submitted_at": "2026-11-15T09:00:00Z"}
        newer = {"id": 2, "user": {"type": "User", "login": "renamed-login", "id": 201},
                 "state": "CHANGES_REQUESTED", "commit_id": head,
                 "submitted_at": "2026-11-15T10:00:00Z"}
        with self.assertRaisesRegex(mod.ReleaseEligibilityError, "no current trusted"):
            mod.verify_current_approval(pr, [older, newer], 100, {201})

    def test_review_order_uses_timezone_aware_instants(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        approval = {"id": 1, "user": {"type": "User", "login": "checker", "id": 201},
                    "state": "APPROVED", "commit_id": head,
                    "submitted_at": "2026-11-15T12:00:00+02:00"}
        later_change = {"id": 2, "user": {"type": "User", "login": "checker", "id": 201},
                        "state": "COMMENTED", "commit_id": head,
                        "submitted_at": "2026-11-15T10:30:00Z"}
        with self.assertRaisesRegex(mod.ReleaseEligibilityError, "no current trusted"):
            mod.verify_current_approval(pr, [approval, later_change], 100, {201})

    def test_review_timestamps_must_be_timezone_aware(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        review = {"id": 1, "user": {"type": "User", "login": "checker", "id": 201},
                  "state": "APPROVED", "commit_id": head,
                  "submitted_at": "2026-11-15T12:00:00"}
        with self.assertRaisesRegex(mod.ReleaseEligibilityError, "must include a timezone"):
            mod.verify_current_approval(pr, [review], 100)

    def test_trusted_reviewer_resolution_requires_typed_users_and_unique_ids(self):
        users = [
            {"type": "User", "login": "one", "id": 201},
            {"type": "User", "login": "two", "id": 201},
        ]
        from unittest.mock import patch
        with patch.object(mod, "run", side_effect=[__import__("json").dumps(users[0]),
                                                   __import__("json").dumps(users[1])]):
            with self.assertRaisesRegex(mod.ReleaseEligibilityError, "duplicate numeric"):
                mod.resolve_trusted_approvers(["one", "two"])
        for account in (
            {"type": "App", "login": "reviewer-app", "id": 201},
            {"type": "User", "login": "reviewer", "id": True},
            {"type": "User", "login": "different-login", "id": 201},
        ):
            with patch.object(mod, "run", return_value=__import__("json").dumps(account)):
                with self.subTest(account=account), self.assertRaises(mod.ReleaseEligibilityError):
                    mod.resolve_trusted_approvers(["reviewer"])

    def test_review_pages_are_flattened_and_malformed_history_fails_closed(self):
        pages = [[{"id": 1}], [{"id": 2}, {"id": 3}]]
        self.assertEqual(mod.flatten_review_pages(pages), [{"id": 1}, {"id": 2}, {"id": 3}])
        for invalid in ([], [{"id": 1}], [None]):
            with self.subTest(invalid=invalid), self.assertRaises(mod.ReleaseEligibilityError):
                mod.flatten_review_pages(invalid)

if __name__ == "__main__":
    unittest.main()
