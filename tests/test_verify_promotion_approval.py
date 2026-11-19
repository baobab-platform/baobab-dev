"""Negative controls for immutable DEV-10 release approval identity evidence."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from textwrap import dedent
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
        with self.assertRaisesRegex(mod.EvidenceError, "no independent human-approved"):
            self.verify(self_approval)

    def test_excludes_rerun_triggering_actor_by_numeric_id(self):
        rerun_approval = [{
            **self.approval[0],
            "user": {"login": "rerunner", "id": 1002, "type": "User"},
        }]
        with self.assertRaisesRegex(mod.EvidenceError, "no independent human-approved"):
            self.verify(rerun_approval)

    def test_same_original_and_triggering_numeric_id_cannot_evade_self_review(self):
        # Reruns retain the original actor's privileges. Different login
        # aliases must not turn one immutable account into an independent actor.
        same_identity = [{
            **self.approval[0],
            "user": {"login": "renamed-initiator", "id": 1001, "type": "User"},
        }]
        with self.assertRaisesRegex(mod.EvidenceError, "no independent human-approved"):
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
        self.assertIn('TRIGGERING_ACTOR_ID="$(gh api "users/$TRIGGERING_ACTOR_LOGIN"', workflow)
        self.assertIn('select(.type == "User" and (.id | type) == "number" and .id > 0)', workflow)
        self.assertIn('[[ "$TRIGGERING_ACTOR_ID" =~ ^[1-9][0-9]*$ ]]', workflow)
        self.assertIn('--actor-id "$ORIGINAL_ACTOR_ID"', workflow)
        self.assertIn('--triggering-actor-id "$TRIGGERING_ACTOR_ID"', workflow)
        self.assertNotIn('--actor "$GITHUB_ACTOR" --tag "$RELEASE_TAG"', workflow)

    def test_approval_capture_remains_inside_protected_release_environment(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml").read_text()
        release_job = workflow.split("name: Capture independent deployment approval evidence", 1)[0]
        self.assertIn("name: dev10-release-promotion", release_job)
        self.assertIn("verify_release_environment.py", release_job)
        self.assertIn("deployment-branch-policies", release_job)

    def test_triggering_actor_resolution_rejects_non_user_and_invalid_numeric_ids(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml").read_text()
        self.assertIn('select(.type == "User" and (.id | type) == "number" and .id > 0) | .id', workflow)
        self.assertIn('[[ "$TRIGGERING_ACTOR_ID" =~ ^[1-9][0-9]*$ ]]', workflow)
        self.assertIn('ORIGINAL_ACTOR_ID: ${{ github.actor_id }}', workflow)
        self.assertIn('set -euo pipefail', workflow)

    @unittest.skipUnless(shutil.which("jq"), "workflow identity fixture needs jq")
    def test_capture_step_validates_live_response_shape_and_cli_contract(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/publish.yml").read_text()
        capture = workflow.split("name: Capture independent deployment approval evidence", 1)[1]
        script = dedent(capture.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
        stub = dedent('''\
            #!/usr/bin/env bash
            set -euo pipefail
            case "$2" in
              user/1001) printf '%s' "$ORIGINAL_RESPONSE" | jq -r "$4" ;;
              users/rerunner) printf '%s' "$TRIGGER_RESPONSE" | jq -r "$4" ;;
              repos/baobab-platform/baobab-dev/actions/runs/42/approvals)
                printf '%s' '[{"state":"approved","user":{"login":"reviewer","id":9001,"type":"User"},"environments":[{"name":"dev10-release-promotion"}],"comment":"UNTRUSTED COMMENT"}]' ;;
              *) exit 3 ;;
            esac
        ''')
        original = {"type": "User", "id": 1001}
        trigger = {"type": "User", "id": 1002}
        for initial, rerun in (
            (original, trigger),
            ({**original, "type": "Bot"}, trigger),
            ({**original, "id": 1002}, trigger),
            (original, {**trigger, "type": "Bot"}),
            (original, {**trigger, "id": "1002"}),
        ):
            with self.subTest(initial=initial, rerun=rerun), tempfile.TemporaryDirectory() as tmp:
                gh = Path(tmp) / "gh"
                gh.write_text(stub)
                gh.chmod(0o755)
                (Path(tmp) / "python3").symlink_to(sys.executable)
                result = subprocess.run(
                    ["bash", "-c", script], cwd=root, capture_output=True, text=True,
                    env={
                        **os.environ, "PATH": f"{tmp}:{os.environ['PATH']}", "RUNNER_TEMP": tmp,
                        "GITHUB_REPOSITORY": "baobab-platform/baobab-dev", "GITHUB_RUN_ID": "42",
                        "GITHUB_RUN_ATTEMPT": "2", "RELEASE_TAG": "v1.5.2-rc.1",
                        "ORIGINAL_ACTOR_LOGIN": "renamed-orig", "ORIGINAL_ACTOR_ID": "1001",
                        "TRIGGERING_ACTOR_LOGIN": "rerunner", "ORIGINAL_RESPONSE": json.dumps(initial),
                        "TRIGGER_RESPONSE": json.dumps(rerun),
                    },
                )
                output = Path(tmp) / "r5-promotion-evidence/approval.json"
                if initial != original or rerun != trigger:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(output.exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence = json.loads(output.read_text())
                self.assertEqual(evidence["schema"], "dev10.promotion-approval.v2")
                self.assertEqual(evidence["initiator"], {"id": 1001, "login": "renamed-orig"})
                self.assertEqual(evidence["triggering_actor"]["id"], 1002)
                self.assertEqual(evidence["approval"], {"reviewer_id": 9001, "reviewer_logins": ["reviewer"]})
                self.assertEqual(evidence["run_attempt"], 2)
                self.assertNotIn("UNTRUSTED COMMENT", output.read_text())


if __name__ == "__main__":
    unittest.main()
