"""Exercise GII-12 observations and GII-14 transport refusals offline."""
from pathlib import Path
import sys
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_github_governance as audit
import github_api_transport as transport


class TransportBoundaryTests(unittest.TestCase):
    def test_rejects_invalid_api_urls_before_network(self):
        urls = (
            "http://api.github.com/graphql",
            "https://example.invalid/graphql",
            "https://api.github.com.example.invalid/graphql",
            "https://user:fixture@api.github.com/graphql",
            "https://api.github.com:8443/graphql",
            "https://api.github.com@example.invalid/graphql",
        )
        for url in urls:
            with self.subTest(url=url), patch.object(transport._OPENER, "open") as opener:
                with self.assertRaises(transport.GitHubAPIError):
                    transport.open_github(urllib.request.Request(url))
                opener.assert_not_called()

    def test_ordinary_https_github_api_origin_is_accepted(self):
        parsed = transport._validate_api_url("https://api.github.com/repos/owner/repo")
        self.assertEqual(parsed.hostname, "api.github.com")

    def test_refuses_off_origin_and_downgraded_redirects(self):
        request = urllib.request.Request(
            "https://api.github.com/repos/owner/repo",
            headers={"Authorization": "Bearer fixture"},
        )
        handler = transport._SameHostRedirect()
        for url in ("https://example.invalid/graphql", "http://api.github.com/graphql"):
            with self.subTest(url=url), self.assertRaises(urllib.error.HTTPError):
                handler.redirect_request(request, None, 302, "Found", {}, url)

    def test_oversized_response_is_read_only_through_the_sentinel_byte(self):
        response = Mock()
        limit = transport.MAX_RESPONSE_BYTES
        response.read.return_value = b"x" * (limit + 1)
        with self.assertRaisesRegex(transport.GitHubAPIError, "1 MiB"):
            transport.read_bounded(response)
        response.read.assert_called_once_with(limit + 1)


class GovernanceEvidenceTests(unittest.TestCase):
    def test_records_observed_absence_and_unverified_admin_data_separately(self):
        base = f"/repos/{audit.REPOSITORY}"
        index = [{"id": 71, "target": "tag", "enforcement": "active"}]
        tag = {**index[0], "conditions": {
            "ref_name": {"include": ["refs/tags/refs/tags/v*"], "exclude": []},
        }}
        environments = {f"/environments/{name}": (403, None) for name in audit.ENVIRONMENTS}
        values = {
            "/branches/main": (200, {"name": "main", "protected": False, "commit": {"sha": "a" * 40}}),
            "/rules/branches/main": (200, []),
            "/branches/main/protection": (403, None),
            "/rulesets?includes_parents=true&per_page=100": (200, index),
            "/rulesets/71": (200, tag),
            **environments,
        }

        def get(token, method, path, *, allowed_status):
            self.assertEqual((token, method, allowed_status), ("fixture", "GET", (403, 404)))
            self.assertTrue(path.startswith(base + "/"))
            return values[path.removeprefix(base)]

        with patch.object(audit, "rest_request", side_effect=get):
            observed = audit.observe_governance("fixture")

        self.assertIs(observed["main"]["protected"], False)
        self.assertEqual(observed["main"]["protection_http_status"], 403)
        self.assertEqual(observed["main"]["release_gate"]["status"], "refused")
        self.assertEqual(observed["tags"]["release_gate"]["status"], "refused")
        self.assertEqual(observed["tags"]["rulesets"], [
            {"id": 71, "matches_release_namespace": False, "bypass_actor_count": None},
        ])
        self.assertTrue(all(value["status"] == "unverified" for value in observed["environments"].values()))

    def test_failed_reads_cannot_establish_protection(self):
        with patch.object(audit, "rest_request", return_value=(403, None)):
            observed = audit.observe_governance("fixture")
        self.assertIsNone(observed["main"]["protected"])
        self.assertEqual(observed["main"]["release_gate"]["status"], "unverified")
        self.assertEqual(observed["tags"]["status"], "unverified")

    def test_visible_environment_reports_only_control_observations(self):
        name = audit.ENVIRONMENTS[-1]
        payload = {"name": name, "can_admins_bypass": False, "unrelated": "fixture",
                   "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True}]}
        self.assertEqual(audit.read_environment(lambda _: (200, payload), name), {
            "http_status": 200, "status": "observed", "review_rule_count": 1,
            "prevent_self_review": True, "can_admins_bypass": False,
        })


if __name__ == "__main__":
    unittest.main()
