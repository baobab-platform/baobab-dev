"""Release eligibility regressions: RC iterations and GA digest reuse."""
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import release_eligibility as mod

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
        superseding = {"id": 2, "user": {"type": "User", "login": "checker", "id": 201},
                       "state": "COMMENTED", "commit_id": head,
                       "submitted_at": "2026-11-15T10:00:00Z"}
        with self.assertRaises(mod.ReleaseEligibilityError):
            mod.verify_current_approval(pr, [superseding, approval], 100)

    def test_bot_reviews_are_ignored_but_other_non_user_types_fail_closed(self):
        head = "a" * 40
        pr = {"head": {"sha": head}}
        bot = {"id": 1, "user": {"type": "Bot", "login": "automation[bot]", "id": 1009},
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

    def test_release_source_requires_exact_premerge_independent_approval_and_input_bytes(self):
        head, merge = "a" * 40, "b" * 40
        pr = {
            "number": 75, "head": {"sha": head}, "state": "closed", "merged": True,
            "merged_at": "2026-11-15T11:00:00Z", "merge_commit_sha": merge,
            "base": {"ref": "main", "repo": {"full_name": mod.REPOSITORY}},
            "user": {"id": 100, "type": "User"},
        }
        review = {
            "id": 1, "user": {"id": 201, "type": "User", "login": "checker"},
            "state": "APPROVED", "commit_id": head, "submitted_at": "2026-11-15T09:00:00Z",
        }
        approved = b"reviewed"
        for association, item, contributors, merged_bytes, diagnostic in (
            ([pr], review, {100, 19864447}, approved, None),
            ([], review, {100}, approved, "exact merge"),
            ([pr, pr], review, {100}, approved, "exact merge"),
            ([pr], dict(review, commit_id="c" * 40), {100}, approved, "current trusted"),
            ([pr], dict(review, submitted_at="2026-11-15T12:00:00Z"), {100}, approved, "current trusted"),
            ([pr], review, {100, 201}, approved, "independent of all PR contributors"),
            ([pr], review, {100}, b"removed checksum", "differs from the exact reviewed bytes"),
        ):
            with (self.subTest(diagnostic=diagnostic, review=item),
                  patch.object(mod, "paginated", side_effect=[association, [item]]) as pages,
                  patch.object(mod, "api_request", return_value=(200, pr)),
                  patch.object(mod, "collect_pr", return_value=(100, contributors)),
                  patch.object(mod, "contents_bytes",
                               side_effect=lambda _, _path, ref: approved if ref == head else merged_bytes)):
                if diagnostic:
                    with self.assertRaisesRegex(mod.ReleaseEligibilityError, diagnostic):
                        mod.reviewed_source("read-token", merge, {201})
                else:
                    result = mod.reviewed_source("read-token", merge, {201})
                    self.assertEqual(result["source_sha"], merge)
                    self.assertEqual(result["pr_head_sha"], head)
                    self.assertEqual(result["approvals"], [{"review_id": 1, "reviewer_id": 201}])
                    self.assertEqual(result["input_sha256"], {
                        file: hashlib.sha256(approved).hexdigest() for file in (mod.MANIFEST, *mod.GENERATED)
                    })
                    root = f"/repos/{mod.REPOSITORY}"
                    self.assertEqual(pages.call_args_list, [
                        call("read-token", f"{root}/commits/{merge}/pulls"),
                        call("read-token", f"{root}/pulls/75/reviews"),
                    ])

    def test_maintenance_joins_rest_author_and_complete_contributor_custody(self):
        head = "a" * 40
        merge = "b" * 40
        pr = {
            "head": {"sha": head}, "state": "closed", "merged": True,
            "merged_at": "2026-11-15T11:00:00Z", "merge_commit_sha": merge,
            "base": {"ref": "main", "repo": {"full_name": mod.REPOSITORY}},
            "user": {"id": 100, "type": "User"},
        }
        reviews = [{
            "id": 1, "user": {"id": 201, "type": "User", "login": "checker"},
            "state": "APPROVED", "commit_id": head, "submitted_at": "2026-11-15T09:00:00Z",
        }]
        decision = {
            "release_family": "v1.5.2", "previous_ga": "v1.5.1", "review_pr": 77,
            "reason": "Reviewed security rebuild using the same toolchain pins.",
        }
        env = {"GH_TOKEN": "test-token", "GITHUB_REPOSITORY": mod.REPOSITORY,
               "DEV10_SECURITY_APPROVER_LOGINS": "checker"}
        declaration = json.dumps(decision).encode()
        files = [{"filename": mod.EXCEPTION.as_posix(), "status": "added"}]
        for author, contributors, file_bytes, diagnostic in (
            (100, {100, 19864447}, declaration, None),
            (755, {100}, declaration, "numeric PR author identity differs"),
            (100, {100, 201, 19864447}, declaration, "independent of PR contributors"),
            (100, {100, 19864447}, b"{}", "differs from the exact reviewed bytes"),
        ):
            with (self.subTest(author=author, contributors=contributors),
                  patch.dict(os.environ, env),
                  patch.object(mod.EXCEPTION.__class__, "is_file", return_value=True),
                  patch.object(mod.EXCEPTION.__class__, "read_bytes", return_value=declaration),
                  patch.object(mod, "run", side_effect=[".devcontainer/docker/Dockerfile", ""]) as git,
                  patch.object(mod, "api_request", return_value=(200, pr)),
                  patch.object(mod, "paginated", side_effect=[reviews, files]) as pages,
                  patch.object(mod, "contents_bytes", return_value=file_bytes),
                  patch.object(mod, "resolve_trusted_reviewers", return_value={201: "checker"}),
                  patch.object(mod, "collect_pr", return_value=(author, contributors)) as custody):
                if diagnostic:
                    with self.assertRaisesRegex(mod.ReleaseEligibilityError, diagnostic):
                        mod.maintenance("v1.5.2", "v1.5.1")
                else:
                    self.assertTrue(mod.maintenance("v1.5.2", "v1.5.1"))
                git.assert_called_with("git", "merge-base", "--is-ancestor", merge, "HEAD")
                endpoint = f"/repos/{mod.REPOSITORY}/pulls/77"
                self.assertEqual(pages.call_args_list, [
                    call("test-token", endpoint + "/reviews"), call("test-token", endpoint + "/files"),
                ])
                if file_bytes == declaration:
                    custody.assert_called_once_with("test-token", 77, head)
                else:
                    custody.assert_not_called()

if __name__ == "__main__":
    unittest.main()
