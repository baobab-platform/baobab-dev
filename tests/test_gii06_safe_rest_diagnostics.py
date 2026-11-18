"""GII-06: HTTP diagnostics must never echo arbitrary API bodies or transport details."""
import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import custody_independence as custody


class SafeDiagnosticsTests(unittest.TestCase):
    def error(self, status, body, request_id="ABC123-DEF"):
        headers = Message()
        headers["x-github-request-id"] = request_id
        return urllib.error.HTTPError(
            "https://api.github.com/graphql", status, "untrusted status text",
            headers, io.BytesIO(body),
        )

    def test_known_message_and_request_id(self):
        msg = custody._http_error_summary(self.error(
            403, b'{"message":"Resource not accessible by integration"}'), "REST lookup")
        self.assertIn("REST lookup HTTP 403", msg)
        self.assertIn("Resource not accessible by integration", msg)
        self.assertIn("ABC123-DEF", msg)

    def test_arbitrary_api_message_never_logged(self):
        secret = "unrecognized error containing sensitive-account-information"
        msg = custody._http_error_summary(self.error(
            422, json.dumps({"message": secret}).encode()), "REST lookup")
        self.assertNotIn(secret, msg)
        self.assertIn("unrecognized GitHub error", msg)

    def test_request_id_rejects_untrusted_content(self):
        msg = custody._http_error_summary(self.error(
            500, b'{"message":"Internal Server Error"}', "id\nsecret=abc"))
        self.assertNotIn("secret=abc", msg)

    def test_invalid_json_and_oversize_are_bounded(self):
        for body in (b'not-json-secret', b"x" * 1_048_577):
            with self.subTest(length=len(body)):
                msg = custody._http_error_summary(self.error(503, body))
                self.assertNotIn("not-json-secret", msg)
                self.assertLess(len(msg), 220)

    def test_transport_reason_is_not_exposed(self):
        expected = {"name": "GitHub", "email": "noreply@github.com",
                    "date": "2026-11-17T01:29:58Z"}
        with patch.object(custody, "open_github", side_effect=urllib.error.URLError(
            "token=very-secret-transport-value"
        )):
            with self.assertRaisesRegex(custody.CustodyError, "transport failure") as err:
                custody._rest_commit_committer_user_id("token", "d" * 40, expected)
        self.assertNotIn("very-secret", str(err.exception))


if __name__ == "__main__":
    unittest.main()
