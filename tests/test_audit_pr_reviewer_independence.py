"""Tests for the read-only live PR reviewer independence classifier."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
from subprocess import CompletedProcess
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

    def test_cli_writes_receipt_with_exact_checkout_run_and_attempt(self):
        evidence = {"pull_request": 76, "head_sha": mod.HISTORICAL_HEAD, "commit_count": 94}
        checkout = "c" * 40
        env = {"GITHUB_TOKEN": "test-token", "GITHUB_RUN_ID": "10922", "GITHUB_RUN_ATTEMPT": "2",
               "GITHUB_SHA": checkout}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "custody.json"
            with (patch.object(sys, "argv", ["audit", "--historical", "--output", str(output)]),
                  patch.dict(os.environ, env),
                  patch.object(mod, "historical_custody", return_value=evidence.copy()) as historical,
                  patch.object(mod.subprocess, "run", return_value=CompletedProcess([], 0, stdout=checkout + "\n")),
                  redirect_stdout(io.StringIO())):
                mod.main()
            historical.assert_called_once_with("test-token")
            receipt = json.loads(output.read_text())
        self.assertEqual(receipt["head_sha"], mod.HISTORICAL_HEAD)
        self.assertEqual(receipt["run_id"], 10922)
        self.assertEqual(receipt["run_attempt"], 2)
        self.assertEqual(receipt["checkout_sha"], checkout)
        self.assertEqual(receipt["api_requests"], [])

    def test_cli_refuses_receipt_for_changed_checkout(self):
        env = {"GITHUB_TOKEN": "test-token", "GITHUB_RUN_ID": "10922", "GITHUB_RUN_ATTEMPT": "2",
               "GITHUB_SHA": "a" * 40}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "custody.json"
            err = io.StringIO()
            with (patch.object(sys, "argv", ["audit", "--historical", "--output", str(output)]),
                  patch.dict(os.environ, env), patch.object(mod, "historical_custody", return_value={}),
                  patch.object(mod.subprocess, "run", return_value=CompletedProcess([], 0, stdout="b" * 40)),
                  redirect_stderr(err), self.assertRaises(SystemExit)):
                mod.main()
            self.assertFalse(output.exists())
        self.assertIn("checkout differs from the Actions workflow SHA", err.getvalue())


if __name__ == "__main__":
    unittest.main()
