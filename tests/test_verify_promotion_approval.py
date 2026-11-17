"""Negative controls for immutable DEV-10 release approval identity evidence."""
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
            "user": {"login": "security-reviewer", "id": 9001, "type": "User"},
            "comment": "Approved",
            "environments": [{"name": "dev10-release-promotion"}],
        }]

    def verify(self, entries, **overrides):
        args = {
            "run_id": 42, "attempt": 2,
            "actor": "initiator", "actor_id": 1001,
            "triggering_actor": "rerunner", "triggering_actor_id": 1002,
            "tag": "v1.5.0-rc.7",
        }
        args.update(overrides)
        return mod.attest(entries, **args)

    def test_independent_human_approval_records_immutable_ids(self):
        evidence = self.verify(self.approval)
        self.assertEqual(evidence["approval"], {
            "reviewer_logins": ["security-reviewer"], "reviewer_id": 9001,
        })
        self.assertEqual(evidence["initiator"], {"id": 1001, "login": "initiator"})
        self.assertEqual(evidence["triggering_actor"], {"id": 1002, "login": "rerunner"})
        self.assertEqual(evidence["schema"], "dev10.promotion-approval.v2")
        self.assertEqual(evidence["run_id"], 42)
        self.assertEqual(evidence["run_attempt"], 2)
        self.assertEqual(evidence["tag"], "v1.5.0-rc.7")
        self.assertNotIn("submitted_at", evidence["approval"])

    def test_excludes_original_actor_by_numeric_id_despite_login_rename(self):
        self_approval = [{
            **self.approval[0],
            "user": {"login": "renamed-account", "id": 1001, "type": "User"},
        }]
        with self.assertRaisesRegex(mod.EvidenceError, "no independent human-approved"):
            self.verify(self_approval)

    def test_excludes_rerun_triggering_actor_by_numeric_id(self):
        rerun_approval = [{
            **self.approval[0],
            "user": {"login": "rerunner", "id": 1002, "type": "User"},
        }]
        with self.assertRaisesRegex(mod.EvidenceError, "no independent human-approved"):
            self.verify(rerun_approval)

    def test_real_world_bot_wait_timer_and_independent_human_approval(self):
        wait_timer = {
            "state": "approved",
            "user": {"login": "github-actions[bot]", "id": 15368, "type": "Bot"},
            "comment": "30 minute wait timer",
            "environments": [{"name": "dev10-release-promotion"}],
        }
        evidence = self.verify([wait_timer, self.approval[0]])
        self.assertEqual(evidence["approval"]["reviewer_id"], 9001)

    def test_missing_self_bot_wrong_environment_and_pending_fail(self):
        wait_timer = {
            "state": "approved", "user": {"login": "github-actions[bot]", "id": 15368, "type": "Bot"},
            "environments": [{"name": "dev10-release-promotion"}],
        }
        for entries in (
            [], {}, [{"state": "pending"}], [wait_timer],
            [{**self.approval[0], "user": {"login": "automated", "id": 9002, "type": "Bot"}}],
            [{**self.approval[0], "environments": [{"name": "staging"}]}],
            [{**self.approval[0], "state": "rejected"}],
        ):
            with self.subTest(entries=entries), self.assertRaises(mod.EvidenceError):
                self.verify(entries)

    def test_mixed_approved_and_rejected_protected_reviews_fail_closed(self):
        rejected = {
            **self.approval[0],
            "state": "rejected",
            "user": {"login": "another-reviewer", "id": 9002, "type": "User"},
        }
        for entries in (
            [self.approval[0], rejected],
            [rejected, self.approval[0]],
        ):
            with self.subTest(entries=entries), self.assertRaisesRegex(
                mod.EvidenceError, "includes a rejection"
            ):
                self.verify(entries)

    def test_rejection_for_unrelated_environment_is_not_release_evidence(self):
        unrelated = {
            **self.approval[0],
            "state": "rejected",
            "environments": [{"name": "unrelated-staging"}],
        }
        evidence = self.verify([unrelated, self.approval[0]])
        self.assertEqual(evidence["approval"]["reviewer_id"], 9001)

    def test_all_independent_numeric_reviewers_are_preserved(self):
        second = {
            **self.approval[0],
            "user": {"login": "another-reviewer", "id": 9002, "type": "User"},
        }
        evidence = self.verify([second, self.approval[0]])
        self.assertEqual(evidence["eligible_approvals"], [
            {"reviewer_id": 9001, "reviewer_logins": ["security-reviewer"]},
            {"reviewer_id": 9002, "reviewer_logins": ["another-reviewer"]},
        ])
        self.assertEqual(evidence["approval"], evidence["eligible_approvals"][0])

    def test_duplicate_review_records_do_not_duplicate_identity(self):
        evidence = self.verify([self.approval[0], self.approval[0]])
        self.assertEqual(len(evidence["eligible_approvals"]), 1)

    def test_missing_or_invalid_reviewer_identity_fails_closed(self):
        invalid_users = (
            {"login": "security-reviewer", "type": "User"},
            {"login": "security-reviewer", "id": 0, "type": "User"},
            {"login": "security-reviewer", "id": True, "type": "User"},
            {"login": "security-reviewer", "id": 9001},
            {"login": "not a valid login", "id": 9001, "type": "User"},
            None,
        )
        for user in invalid_users:
            entry = {**self.approval[0], "user": user}
            with self.subTest(user=user), self.assertRaises(mod.EvidenceError):
                self.verify([entry])

    def test_malformed_review_and_environment_evidence_fail_closed(self):
        for entries in (
            [None],
            [{"state": "unknown", "environments": []}],
            [{"state": "approved", "environments": "dev10-release-promotion"}],
            [{"state": "approved", "environments": [None]}],
        ):
            with self.subTest(entries=entries), self.assertRaises(mod.EvidenceError):
                self.verify(entries)

    def test_actor_identity_inputs_must_be_positive_numeric_ids(self):
        for field in ("actor_id", "triggering_actor_id"):
            with self.subTest(field=field), self.assertRaises(mod.EvidenceError):
                self.verify(self.approval, **{field: True})

    def test_login_rename_is_display_metadata_for_the_same_numeric_reviewer(self):
        renamed = {
            **self.approval[0],
            "user": {"login": "renamed-reviewer", "id": 9001, "type": "User"},
        }
        evidence = self.verify([self.approval[0], renamed])
        self.assertEqual(evidence["approval"], {
            "reviewer_id": 9001,
            "reviewer_logins": ["renamed-reviewer", "security-reviewer"],
        })


class WorkflowWiringTests(unittest.TestCase):
    def test_release_workflow_passes_original_and_triggering_numeric_actor_ids(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml").read_text()
        self.assertIn("ORIGINAL_ACTOR_ID: ${{ github.actor_id }}", workflow)
        self.assertIn("TRIGGERING_ACTOR_LOGIN: ${{ github.triggering_actor }}", workflow)
        self.assertIn('TRIGGERING_ACTOR_ID="$(gh api "users/$TRIGGERING_ACTOR_LOGIN" --jq .id)"', workflow)
        self.assertIn('--actor-id "$ORIGINAL_ACTOR_ID"', workflow)
        self.assertIn('--triggering-actor-id "$TRIGGERING_ACTOR_ID"', workflow)
        self.assertNotIn('--actor "$GITHUB_ACTOR" --tag "$RELEASE_TAG"', workflow)

    def test_approval_capture_remains_inside_protected_release_environment(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml").read_text()
        release_job = workflow.split("name: Capture independent deployment approval evidence", 1)[0]
        self.assertIn("name: dev10-release-promotion", release_job)
        self.assertIn("verify_release_environment.py", release_job)
        self.assertIn("deployment-branch-policies", release_job)


if __name__ == "__main__":
    unittest.main()
