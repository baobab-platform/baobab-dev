"""Tests for the read-only live PR reviewer independence classifier."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from email.message import Message
from unittest.mock import MagicMock, patch

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


class HistoricalCustodyTests(unittest.TestCase):
    def setUp(self):
        self.reviews = [
            {"id": 5932308846, "state": "APPROVED", "commit_id": mod.HISTORICAL_HEAD,
             "submitted_at": "2026-11-17T03:27:00Z",
             "user": {"id": 356890520, "login": "sknabusiu", "type": "User"}},
            {"id": 5932308847, "state": "APPROVED", "commit_id": mod.HISTORICAL_HEAD,
             "submitted_at": "2026-11-17T03:28:08Z",
             "user": {"id": 356900102, "login": "sdnabusiu", "type": "User"}},
        ]

    def corroborate(self, reviews, *, head=mod.HISTORICAL_HEAD):
        pull = {"merged": True, "head": {"sha": head}, "commits": 94,
                "merged_at": "2026-11-17T03:36:58Z",
                "user": {"id": 350241706, "login": "wekhason", "type": "User"}}
        service_commit = {
            "author": {"user": {"__typename": "User", "databaseId": 356890520}},
            "committer": {"user": None, "name": "GitHub", "email": "noreply@github.com",
                          "date": "2026-11-17T01:29:58Z"},
        }
        owner = {"id": 6924572973, "user": {"id": 49340314, "type": "User"},
                 "body": "Owner concurrence is hereby recorded for the new reusable policy.",
                 "created_at": "2026-11-16T17:56:59Z", "updated_at": "2026-11-16T17:56:59Z"}
        contributors = {mod.GITHUB_WEB_FLOW_ID, 350241706, 356890520}
        with (patch.object(mod, "api_request", return_value=(200, pull)),
              patch.object(mod, "collect_pr", return_value=(350241706, contributors)),
              patch.object(mod, "_fetch_commit_records", return_value=[service_commit]),
              patch.object(mod, "_rest_commit_committer_user_id", return_value=mod.GITHUB_WEB_FLOW_ID),
              patch.object(mod, "paginated", side_effect=[reviews, [owner]])):
            return mod.historical_custody("read-only-fixture")

    def test_historical_collision_preserves_distinct_exact_head_approval(self):
        receipt = self.corroborate(self.reviews)
        self.assertEqual(receipt["approval_id"], "github-review-5932308847")
        self.assertEqual(receipt["approved_by_id"], 356900102)
        self.assertEqual(receipt["approved_head"], mod.HISTORICAL_HEAD)
        self.assertEqual(receipt["owner_comment_id"], 6924572973)
        self.assertIn(356890520, receipt["contributor_ids"])

    def test_historical_witness_refuses_changed_head_or_ineligible_review(self):
        with self.assertRaisesRegex(mod.IndependenceError, "historical PR #76 metadata"):
            self.corroborate(self.reviews, head="a" * 40)
        revoked = dict(self.reviews[1], id=5932308848, state="CHANGES_REQUESTED",
                       submitted_at="2026-11-17T03:29:00Z")
        stale = dict(self.reviews[1], commit_id="a" * 40)
        for reviews in (self.reviews[:1], self.reviews + [revoked], [self.reviews[0], stale]):
            with self.subTest(reviews=reviews), self.assertRaisesRegex(mod.ProvisioningError, "no current-head"):
                self.corroborate(reviews)


class CustodyReceiptTests(unittest.TestCase):
    def test_only_allowlisted_response_metadata_is_retained(self):
        from github_api_transport import rest_request, trace_requests

        headers = Message()
        headers["x-github-request-id"] = "BABC:A31:BC12:DE23"
        headers["x-ratelimit-resource"] = "core"
        headers["x-ratelimit-remaining"] = "49"
        headers["x-ratelimit-reset"] = "arbitrary-secret"
        headers["secret"] = "arbitrary-secret"
        response = MagicMock(status=200, headers=headers)
        response.read.return_value = b'{"message":"another-secret"}'
        response.__enter__.return_value = response
        with patch("github_api_transport.open_github", return_value=response):
            with trace_requests() as observed:
                rest_request("secret-token", "GET", "/user")
            rest_request("secret-token", "GET", "/user")
        self.assertEqual(observed, [{
            "operation": "GitHub API GET", "http_status": 200,
            "request_id": "BABC:A31:BC12:DE23", "rate_limit_resource": "core",
            "rate_limit_remaining": 49,
        }])

    def test_cli_writes_receipt_with_exact_run_and_attempt(self):
        evidence = {"pull_request": 76, "head_sha": mod.HISTORICAL_HEAD, "commit_count": 94}
        env = {"GITHUB_TOKEN": "test-token", "GITHUB_RUN_ID": "10922", "GITHUB_RUN_ATTEMPT": "2"}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "custody.json"
            with (patch.object(sys, "argv", ["audit", "--historical", "--output", str(output)]),
                  patch.dict(os.environ, env),
                  patch.object(mod, "historical_custody", return_value=evidence.copy()) as historical,
                  redirect_stdout(io.StringIO())):
                mod.main()
            historical.assert_called_once_with("test-token")
            receipt = json.loads(output.read_text())
        self.assertEqual(receipt["head_sha"], mod.HISTORICAL_HEAD)
        self.assertEqual(receipt["run_id"], 10922)
        self.assertEqual(receipt["run_attempt"], 2)
        self.assertEqual(receipt["api_requests"], [])


if __name__ == "__main__":
    unittest.main()
