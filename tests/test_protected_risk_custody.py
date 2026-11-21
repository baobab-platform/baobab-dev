"""Verify that read-only workflows use the same exact merged custody as provisioning."""
import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_protected_risk_policy as provisioner
import verify_protected_risk_custody as reader

URL = "https://github.com/baobab-platform/baobab-dev/pull/123"
SHA = "a" * 40
MERGE = "b" * 40
DECISION_PATH = "security/decisions/development/foundation.json"


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.decision = {"prepared_by": "maker", "prepared_by_id": 1, "approval_evidence": URL}
        repo = {"full_name": reader.REPOSITORY}
        self.pull = {
            "state": "closed", "merged": True, "merged_at": "2026-11-15T10:00:00Z",
            "base": {"ref": "main", "repo": repo}, "head": {"sha": SHA, "repo": repo},
            "user": {"login": "maker", "id": 1, "type": "User"}, "merge_commit_sha": MERGE,
        }
        self.reviews = [{
            "id": 1, "user": {"login": "checker", "id": 2, "type": "User"},
            "state": "APPROVED", "submitted_at": "2026-11-15T09:00:00Z", "commit_id": SHA,
        }]
        self.owner = [{
            "id": 8, "user": {"id": provisioner.OWNER_USER_ID, "type": "User"},
            "body": "Owner concurrence is hereby recorded for the new reusable policy.",
            "created_at": "2026-11-15T09:00:00Z", "updated_at": "2026-11-15T09:00:00Z",
        }]
        self.files = [{"filename": DECISION_PATH, "status": "added"}]

    def check_custody(self, contributors=None, *, raw_policy=None):
        if raw_policy is None:
            raw_policy = json.dumps(self.decision).encode()
        content = base64.b64encode(raw_policy).decode()
        blob = {"type": "file", "encoding": "base64", "content": content}
        comparison = {"status": "ahead", "merge_base_commit": {"sha": self.pull["merge_commit_sha"]}}
        reviewer = {"login": "Checker", "type": "User", "id": 2}
        evidence = [reviewer, self.pull, self.files, blob, blob, blob, comparison, self.owner, self.reviews]
        author = self.decision["prepared_by_id"]
        number = self.decision["approval_evidence"].rsplit("/", 1)[1]
        with (patch.object(reader, "api_request", return_value=(200, self.pull)) as first_read,
              patch.object(provisioner, "api_request", side_effect=[(200, row) for row in evidence]) as api,
              patch.object(provisioner, "collect_pr", return_value=(author, contributors or {author})),
              patch.object(provisioner, "provision_variable") as write):
            try:
                return reader.verify_read_custody("token", self.decision, DECISION_PATH, ["checker"])
            finally:
                first_read.assert_called_once_with("token", "GET", f"/repos/baobab-platform/baobab-dev/pulls/{number}")
                self.assertTrue(all(request.args[1] == "GET" for request in api.call_args_list))
                write.assert_not_called()

    def test_readonly_receipt_includes_typed_reviewer_and_owner_custody(self):
        self.reviews[0]["user"]["login"] = "renamed-reviewer"
        result = self.check_custody()
        self.assertEqual(result["approval_id"], "github-review-1")
        self.assertEqual(result["approved_by_id"], 2)
        self.assertEqual(result["approval_pr_head"], SHA)
        self.assertEqual(result["owner_comment_id"], 8)
        self.assertEqual(result["status"], "approval_custody_verified")

    def test_historical_readback_requires_exact_head_bytes_and_comment(self):
        raw = (Path(__file__).resolve().parents[1] / DECISION_PATH).read_bytes()
        self.decision = json.loads(raw)
        self.pull["head"]["sha"] = self.reviews[0]["commit_id"] = provisioner.HISTORICAL_HEAD
        self.pull["merge_commit_sha"] = provisioner.HISTORICAL_MERGE
        self.pull["user"]["id"] = self.decision["prepared_by_id"]
        self.owner[0]["id"] = provisioner.HISTORICAL_OWNER_COMMENT_ID
        self.owner[0]["user"]["id"] = provisioner.HISTORICAL_OWNER_ID

        result = self.check_custody(raw_policy=raw)
        self.assertEqual(result["owner_id"], provisioner.HISTORICAL_OWNER_ID)
        self.assertEqual(result["owner_comment_id"], provisioner.HISTORICAL_OWNER_COMMENT_ID)
        with self.assertRaisesRegex(provisioner.ProvisioningError, "owner concurrence"):
            self.check_custody(raw_policy=raw + b"\n")
        self.owner[0]["id"] += 1
        with self.assertRaisesRegex(provisioner.ProvisioningError, "historical decision owner comment"):
            self.check_custody(raw_policy=raw)
        self.owner[0]["id"] = provisioner.HISTORICAL_OWNER_COMMENT_ID
        self.pull["head"]["sha"] = self.reviews[0]["commit_id"] = SHA
        with self.assertRaisesRegex(provisioner.ProvisioningError, "owner concurrence"):
            self.check_custody(raw_policy=raw)

    def test_historical_owner_cannot_concur_on_new_decision(self):
        self.owner[0]["user"]["id"] = provisioner.HISTORICAL_OWNER_ID
        with self.assertRaisesRegex(provisioner.ProvisioningError, "owner concurrence"):
            self.check_custody()

    def test_reviewer_contribution_refuses_readback(self):
        with self.assertRaisesRegex(provisioner.ProvisioningError, "trusted independent"):
            self.check_custody({1, 2})

    def test_readback_without_owner_concurrence_fails_closed(self):
        self.owner = []
        with self.assertRaisesRegex(provisioner.ProvisioningError, "owner concurrence"):
            self.check_custody()

    def test_stale_or_superseded_approval_refuses_readback(self):
        approval, = self.reviews
        for reviews in (
            [dict(approval, commit_id="c" * 40)],
            [approval, dict(approval, id=2, state="DISMISSED", submitted_at="2026-11-15T09:30:00Z")],
        ):
            self.reviews = reviews
            with self.subTest(reviews=reviews), self.assertRaises(provisioner.ProvisioningError):
                self.check_custody()

    def test_approval_must_modify_the_exact_decision_path(self):
        self.files = [{"filename": "security/decisions/unrelated.json", "status": "modified"}]
        with self.assertRaisesRegex(provisioner.ProvisioningError, "protected decision file"):
            self.check_custody()


if __name__ == "__main__":
    unittest.main()
