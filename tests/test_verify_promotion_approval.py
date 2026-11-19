"""Negative controls for immutable DEV-10 release approval identity evidence."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_promotion_approval as mod


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

    def test_independent_typed_user_approval_records_immutable_ids(self):
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
        with self.assertRaisesRegex(mod.EvidenceError, "no independent eligible"):
            self.verify(self_approval)

    def test_excludes_rerun_triggering_actor_by_numeric_id(self):
        rerun_approval = [{
            **self.approval[0],
            "user": {"login": "rerunner", "id": 1002, "type": "User"},
        }]
        with self.assertRaisesRegex(mod.EvidenceError, "no independent eligible"):
            self.verify(rerun_approval)

    def test_same_original_and_triggering_numeric_id_cannot_evade_self_review(self):
        # Reruns retain the original actor's privileges. Different login
        # aliases must not turn one immutable account into an independent actor.
        same_identity = [{
            **self.approval[0],
            "user": {"login": "renamed-initiator", "id": 1001, "type": "User"},
        }]
        with self.assertRaisesRegex(mod.EvidenceError, "no independent eligible"):
            self.verify(
                same_identity,
                actor="original-login", actor_id=1001,
                triggering_actor="renamed-login", triggering_actor_id=1001,
            )

    def test_v2_evidence_contract_is_explicit_and_does_not_emit_v1_shape(self):
        evidence = self.verify(self.approval)
        self.assertEqual(set(evidence), {
            "schema", "environment", "run_id", "run_attempt", "tag",
            "initiator", "triggering_actor", "approval", "eligible_approvals",
        })
        self.assertEqual(evidence["schema"], "dev10.promotion-approval.v2")
        self.assertIsInstance(evidence["initiator"], dict)
        self.assertEqual(set(evidence["initiator"]), {"id", "login"})
        self.assertEqual(set(evidence["triggering_actor"]), {"id", "login"})
        self.assertEqual(set(evidence["approval"]), {"reviewer_id", "reviewer_logins"})
        self.assertNotIn("reviewer", evidence["approval"])
        self.assertNotIn("submitted_at", evidence["approval"])

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

    def test_known_service_user_and_conflicting_types_cannot_supply_promotion_approval(self):
        approval, = self.approval
        service = dict(approval, user={"login": "renamed-service", "type": "User", "id": 19864447})
        bot = dict(approval, user={"login": "automation[bot]", "type": "Bot", "id": 9001})
        with self.assertRaisesRegex(mod.EvidenceError, "no independent eligible"):
            self.verify([service])
        with self.assertRaisesRegex(mod.EvidenceError, "conflicting account type"):
            self.verify([approval, bot])

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
    def setUp(self):
        self.sha = "a" * 40
        self.run = {
            "id": 42, "run_attempt": 1, "path": ".github/workflows/publish.yml",
            "head_sha": self.sha, "head_branch": "v1.5.2-rc.1", "event": "push",
            "repository": {"full_name": mod.REPOSITORY},
            "actor": {"type": "User", "id": 1001, "login": "renamed-original"},
            "triggering_actor": {"type": "User", "id": 1001, "login": "renamed-original"},
        }
        self.reviews = [{
            "state": "approved", "environments": [{"name": mod.ENVIRONMENT}],
            "user": {"type": "User", "id": 9001, "login": "reviewer"},
        }]

    def qualifier(self):
        return mod.collect_run_approval(
            "test-token", run_id=42, attempt=1, head_sha=self.sha,
            actor="original", actor_id=1001, tag="v1.5.2-rc.1", eligible_ids={9001},
        )

    def test_release_workflow_passes_exact_run_attempt_and_immutable_source(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text()
        before, after = workflow.split("name: Capture independent deployment approval evidence", 1)
        step = after.split("\n      - name:", 1)[0]
        self.assertIn("name: dev10-release-promotion", before)
        self.assertIn("verify_release_environment.py", before)
        self.assertIn("ORIGINAL_ACTOR_ID: ${{ github.actor_id }}", step)
        self.assertIn(' --attempt "$GITHUB_RUN_ATTEMPT"', step)
        self.assertIn('--head-sha "$GITHUB_SHA"', step)
        self.assertIn('--actor-id "$ORIGINAL_ACTOR_ID"', step)

    def test_exact_run_attempt_ids_and_protected_approval_are_read_by_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "approval.json"
            environment = Path(tmp) / "environment.json"
            environment.write_text(json.dumps({
                "environment": mod.ENVIRONMENT, "release_tag": "v1.5.2-rc.1",
                "reviewer_ids": [9001],
            }))
            args = [
                "verify_promotion_approval.py", "--run-id", "42", "--attempt", "1",
                "--head-sha", self.sha, "--actor", "original", "--actor-id", "1001",
                "--tag", "v1.5.2-rc.1", "--output", str(path),
                "--environment-evidence", str(environment), "--contributors", "[5000]",
            ]
            with (patch.object(sys, "argv", args),
                  patch.dict(os.environ, {"GITHUB_TOKEN": "test-token", "GITHUB_REPOSITORY": mod.REPOSITORY}),
                  patch.object(mod, "rest_request", side_effect=[(200, self.run), (200, self.reviews)]) as api):
                self.assertEqual(mod.main(), 0)
            endpoint = f"/repos/{mod.REPOSITORY}/actions/runs/42"
            self.assertEqual(api.call_args_list, [
                call("test-token", "GET", endpoint + "/attempts/1"),
                call("test-token", "GET", endpoint + "/approvals"),
            ])
            receipt = json.loads(path.read_text())
        self.assertEqual(receipt["schema"], "dev10.promotion-approval.v2")
        self.assertEqual(receipt["initiator"], {"id": 1001, "login": "original"})
        self.assertEqual(receipt["triggering_actor"], {"id": 1001, "login": "renamed-original"})
        self.assertEqual(receipt["approval"], {"reviewer_id": 9001, "reviewer_logins": ["reviewer"]})

    def test_unrelated_run_and_untyped_or_conflicting_actors_fail_before_review_lookup(self):
        for changes in (
            {"id": 43}, {"run_attempt": 2}, {"event": "pull_request"}, {"head_sha": "b" * 40},
            {"head_branch": "v1.5.2-rc.2"}, {"actor": {"id": 1002, "type": "User"}},
            {"triggering_actor": {"id": 1002, "type": "Bot"}},
            {"triggering_actor": {"id": "1002", "type": "User"}},
            {"triggering_actor": {"id": 19864447, "type": "User", "login": "web-flow"}},
        ):
            with (self.subTest(changes=changes),
                  patch.object(mod, "rest_request", return_value=(200, self.run | changes)) as api,
                  self.assertRaises(ValueError)):
                self.qualifier()
            api.assert_called_once()

    def test_rerun_cannot_reuse_approval_from_the_first_attempt(self):
        with patch.object(mod, "rest_request") as api:
            with self.assertRaisesRegex(mod.EvidenceError, "no attempt binding"):
                mod.collect_run_approval(
                    "test-token", run_id=42, attempt=2, head_sha=self.sha, actor="original",
                    actor_id=1001, tag="v1.5.2-rc.1", eligible_ids={9001},
                )
            api.assert_not_called()

    def test_configured_reviewer_appointment_is_required(self):
        self.reviews[0]["user"] = {"type": "User", "id": 7777, "login": "unappointed"}
        with patch.object(mod, "rest_request", side_effect=[(200, self.run), (200, self.reviews)]):
            with self.assertRaisesRegex(mod.EvidenceError, "no independent eligible"):
                self.qualifier()


if __name__ == "__main__":
    unittest.main()
