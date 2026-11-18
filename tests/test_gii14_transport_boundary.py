"""GII-14 transport invariants and GII-13 negative authorization boundaries."""
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import github_api_transport as transport


class TransportBoundaryTests(unittest.TestCase):
    def test_rejects_cross_origin_and_credential_urls(self):
        urls = (
            "http://api.github.com/graphql",
            "https://evil.example/graphql",
            "https://api.github.com.evil.example/graphql",
            "https://user:secret@api.github.com/graphql",
            "https://api.github.com:8443/graphql",
            "https://api.github.com@evil.example/graphql",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                transport._validate_api_url(url)

    def test_same_origin_url_accepted(self):
        parsed = transport._validate_api_url("https://api.github.com/repos/x/y")
        self.assertEqual(parsed.hostname, "api.github.com")

    def test_redirect_to_different_origin_refused(self):
        req = urllib.request.Request(
            "https://api.github.com/repos/x/y",
            headers={"Authorization": "Bearer secret"},
        )
        handler = transport._SameHostRedirect()
        for url in ("https://evil.example/steal", "http://api.github.com/steal"):
            with self.subTest(url=url), self.assertRaises(urllib.error.HTTPError):
                handler.redirect_request(req, None, 302, "Found", {}, url)

    def test_oversize_response_refused(self):
        class Response:
            def read(self, n):
                self_size = transport.MAX_RESPONSE_BYTES + 1
                self.assertEqual(n, self_size)
                return b"x" * self_size
        # Verify that the bounded transport rejects the sentinel byte.
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            transport.read_bounded(type("Response", (), {
                "read": lambda _self, n: b"x" * n
            })())

    def test_open_github_checks_url_before_network(self):
        request = urllib.request.Request("https://evil.example/private")
        with patch.object(transport._OPENER, "open") as opener:
            with self.assertRaises(ValueError):
                transport.open_github(request)
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
