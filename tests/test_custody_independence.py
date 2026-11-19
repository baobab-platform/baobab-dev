"""Regression tests for complete DEV-10 GitHub commit-custody enumeration."""
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import custody_independence as custody


HEAD = "a" * 40


def commit(oid, author=10, committer=11, authors=(10,)):
    return {
        "commit": {
            "oid": oid,
            "author": {"user": {"__typename": "User", "databaseId": author}},
            "committer": {"user": {"__typename": "User", "databaseId": committer}},
            "authors": {
                "totalCount": len(authors),
                "pageInfo": {"hasNextPage": False},
                "nodes": [{"user": {"__typename": "User", "databaseId": item}} for item in authors],
            },
        }
    }


def page(nodes, *, has_next=False, cursor=None, total=None):
    return {
        "repository": {
            "pullRequest": {
                "headRefOid": HEAD,
                "author": {"__typename": "User", "databaseId": 1},
                "commits": {
                    "totalCount": len(nodes) if total is None else total,
                    "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                    "nodes": nodes,
                },
            }
        }
    }


class CompleteHistoryTests(unittest.TestCase):
    def test_collect_pr_uses_exact_local_oids_for_large_histories(self):
        first = commit(HEAD)["commit"]
        second = commit("b" * 40)["commit"]
        second["committer"] = {
            "name": "GitHub", "email": "noreply@github.com",
            "date": "2026-11-17T01:29:58Z", "user": None,
        }
        with patch.object(custody, "_pull_request_metadata", side_effect=[(1, 2), (1, 2)]), patch.object(custody, "_fetch_commit_records", return_value=[first, second]) as fetch, patch.object(custody, "_rest_commit_committer_user_id", return_value=19864447) as rest:
            author, contributors = custody.collect_pr("token", 74, HEAD, [HEAD, "b" * 40])
        self.assertEqual(author, 1)
        self.assertEqual(contributors, {10, 11, 19864447})
        fetch.assert_called_once_with("token", [HEAD, "b" * 40])
        rest.assert_called_once()

    def test_collect_pr_rejects_invalid_local_commit_ranges(self):
        invalid_ranges = ([HEAD], ["b" * 40, "c" * 40], [HEAD, "not-a-sha"], [HEAD, HEAD])
        for oids in invalid_ranges:
            with self.subTest(oids=oids), patch.object(custody, "_pull_request_metadata", return_value=(1, 2)), self.assertRaisesRegex(custody.CustodyError, "local commit range"):
                custody.collect_pr("token", 74, HEAD, oids)

    def test_fetch_commit_records_uses_exact_sha_object_queries(self):
        records = {"c0": commit(HEAD)["commit"], "c1": commit("b" * 40)["commit"]}
        with patch.object(custody, "_graphql", return_value={"repository": records}) as graphql:
            result = custody._fetch_commit_records("token", [HEAD, "b" * 40])
        self.assertEqual([item["oid"] for item in result], [HEAD, "b" * 40])
        query = graphql.call_args.args[1]
        self.assertIn("object(expression: $oid0)", query)
        self.assertIn("object(expression: $oid1)", query)

    def test_collects_authors_coauthors_and_committers_across_all_pages(self):
        responses = [
            page([commit("b" * 40, authors=(10, 12))],
                 has_next=True, cursor="cursor-1", total=2),
            page([commit(HEAD, author=13, committer=14, authors=(13,))],
                 total=2),
        ]
        with patch.object(custody, "_graphql", side_effect=responses) as graphql:
            author, contributors = custody.collect_pr("token", 76, HEAD)
        self.assertEqual(author, 1)
        self.assertEqual(contributors, {10, 11, 12, 13, 14})
        self.assertEqual(graphql.call_count, 2)
        self.assertEqual(graphql.call_args_list[1].args[2]["after"], "cursor-1")

    def test_queries_pull_request_author_with_user_inline_fragment(self):
        with patch.object(custody, "_graphql", return_value=page([commit(HEAD)])) as graphql:
            custody.collect_pr("token", 76, HEAD)
        query = graphql.call_args.args[1]
        self.assertIn("author {", query)
        self.assertIn("__typename", query)
        self.assertIn("... on User { databaseId }", query)
        pr_author_selection = query.split(
            "pullRequest(number: $number) {", 1
        )[1].split("commits(", 1)[0]
        self.assertNotIn("user { databaseId }", pr_author_selection)
        self.assertNotIn("author { databaseId }", pr_author_selection)

    def test_rejects_null_pull_request_author(self):
        response = page([commit(HEAD)])
        response["repository"]["pullRequest"]["author"] = None
        with patch.object(custody, "_graphql", return_value=response):
            with self.assertRaisesRegex(custody.CustodyError, "identity is missing"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_non_user_pull_request_author_actors(self):
        for typename in ("Bot", "Organization", "Mannequin", "EnterpriseUserAccount"):
            response = page([commit(HEAD)])
            response["repository"]["pullRequest"]["author"] = {
                "__typename": typename, "databaseId": 1,
            }
            with self.subTest(typename=typename), patch.object(
                custody, "_graphql", return_value=response
            ), self.assertRaisesRegex(custody.CustodyError, "not a concrete GitHub User"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_missing_or_invalid_pull_request_author_numeric_id(self):
        for user_id in (None, 0, -1, True, "1", 1.0):
            response = page([commit(HEAD)])
            response["repository"]["pullRequest"]["author"] = {
                "__typename": "User", "databaseId": user_id,
            }
            with self.subTest(user_id=user_id), patch.object(
                custody, "_graphql", return_value=response
            ), self.assertRaisesRegex(custody.CustodyError, "immutable numeric GitHub user ID"):
                custody.collect_pr("token", 76, HEAD)

    @unittest.skipUnless(
        all(os.environ.get(name) for name in (
            "GH_TOKEN", "DEV10_GRAPHQL_INTEGRATION_PR_NUMBER",
            "DEV10_GRAPHQL_INTEGRATION_EXPECTED_HEAD",
        )),
        "live GitHub GraphQL validation is enabled only by the DEV-10 PR workflow",
    )
    def test_live_github_graphql_schema_and_author_response(self):
        author_id, commit_count = custody._pull_request_metadata(
            os.environ["GH_TOKEN"],
            int(os.environ["DEV10_GRAPHQL_INTEGRATION_PR_NUMBER"]),
            os.environ["DEV10_GRAPHQL_INTEGRATION_EXPECTED_HEAD"],
        )
        self.assertGreater(author_id, 0)
        self.assertGreater(commit_count, 0)

    def test_rest_fallback_resolves_exact_sha_with_metadata_corroboration(self):
        oid = "d" * 40
        payload = {
            "sha": oid,
            "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}},
            "committer": {"type": "User", "id": 19864447, "login": "web-flow"},
        }
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(payload).encode("utf-8")
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch("github_api_transport.open_github", return_value=opener) as open_github:
            user_id = custody._rest_commit_committer_user_id("token", oid, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})
        self.assertEqual(user_id, 19864447)
        request = open_github.call_args.args[0]
        self.assertEqual(request.full_url, f"https://api.github.com/repos/baobab-platform/baobab-dev/commits/{oid}")

    def test_rest_fallback_rejects_a_different_commit_sha(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps({
            "sha": "e" * 40,
            "committer": {"type": "User", "id": 19864447},
        }).encode("utf-8")
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch("github_api_transport.open_github", return_value=opener):
            with self.assertRaisesRegex(custody.CustodyError, "different commit SHA"):
                custody._rest_commit_committer_user_id("token", "d" * 40, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})

    def test_rest_fallback_rejects_name_email_and_timestamp_mismatches(self):
        oid = "d" * 40
        raw = {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}
        for key, value in (("name", "Other"), ("email", "other@example.invalid"),
                           ("date", "2026-11-17T01:29:59Z"), ("date", "2026-11-17T01:29:58")):
            response = MagicMock()
            response.status = 200
            response.read.return_value = json.dumps({
                "sha": oid, "commit": {"committer": raw},
                "committer": {"type": "User", "id": 19864447, "login": "web-flow"},
            }).encode("utf-8")
            expected = dict(raw)
            expected[key] = value
            opener = MagicMock()
            opener.__enter__.return_value = response
            with self.subTest(field=key, value=value), patch(
                "github_api_transport.open_github", return_value=opener
            ), self.assertRaisesRegex(custody.CustodyError, "metadata disagree"):
                custody._rest_commit_committer_user_id("token", oid, expected)

    def test_rest_fallback_accepts_equivalent_timezone_spellings(self):
        oid = "d" * 40
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps({
            "sha": oid,
            "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com",
                                      "date": "2026-11-17T01:29:58Z"}},
            "committer": {"type": "User", "id": 19864447, "login": "web-flow"},
        }).encode("utf-8")
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch("github_api_transport.open_github", return_value=opener):
            self.assertEqual(custody._rest_commit_committer_user_id(
                "token", oid, {"name": "GitHub", "email": "noreply@github.com",
                               "date": "2026-11-17T03:29:58+02:00"}), 19864447)

    def test_rest_fallback_rejects_non_user_and_invalid_numeric_ids(self):
        for actor, expected in (
            ({"type": "Bot", "id": 19864447}, "not a linked GitHub User"),
            ({"type": "User", "id": True}, "no immutable numeric"),
            ({"type": "User", "id": 0}, "no immutable numeric"),
        ):
            response = MagicMock()
            response.status = 200
            response.read.return_value = json.dumps({
                "sha": "d" * 40,
                "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}},
                "committer": actor,
            }).encode("utf-8")
            opener = MagicMock()
            opener.__enter__.return_value = response
            with self.subTest(actor=actor), patch(
                "github_api_transport.open_github", return_value=opener
            ), self.assertRaisesRegex(custody.CustodyError, expected):
                custody._rest_commit_committer_user_id("token", "d" * 40, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})

    def test_rest_http_error_reports_status_request_id_and_safe_message(self):
        import io
        from email.message import Message
        headers = Message()
        headers["x-github-request-id"] = "ABC1:2DEF:3456:789A:B12C"
        body = json.dumps({
            "message": "Resource not accessible by integration",
            "documentation_url": "https://example.invalid/private",
            "secret": "must-not-be-disclosed",
        }).encode()
        error = urllib.error.HTTPError(
            "https://api.github.com/repos/baobab-platform/baobab-dev/commits/" + "d" * 40,
            403, "Forbidden", headers, io.BytesIO(body),
        )
        with patch("github_api_transport.open_github", side_effect=error):
            with self.assertRaisesRegex(
                custody.CustodyError, "HTTP 403.*ABC1:2DEF:3456:789A:B12C"
            ) as caught:
                custody._rest_commit_committer_user_id("token", "d" * 40, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})
        self.assertIn("Resource not accessible by integration", str(caught.exception))
        self.assertNotIn("documentation_url", str(caught.exception))
        self.assertNotIn("must-not-be-disclosed", str(caught.exception))
        self.assertNotIn("Forbidden", str(caught.exception))

    def test_collect_pr_adds_rest_reconciled_committer_to_contributor_set(self):
        oid = HEAD
        item = commit(oid)
        committer = {
            "name": "GitHub", "email": "noreply@github.com",
            "date": "2026-11-17T01:29:58Z", "user": None,
        }
        item["commit"]["committer"] = committer
        with patch.object(custody, "_graphql", return_value=page([item])), \
             patch.object(custody, "_rest_commit_committer_user_id",
                          return_value=19864447) as reconcile:
            author_id, contributors = custody.collect_pr("token", 76, HEAD)
        self.assertEqual(author_id, 1)
        self.assertEqual(contributors, {10, 19864447})
        reconcile.assert_called_once_with("token", oid, committer)

    def test_collect_pr_fails_closed_when_rest_committer_resolution_fails(self):
        oid = "d" * 40
        item = commit(oid)
        item["commit"]["committer"] = {
            "name": "GitHub", "email": "noreply@github.com",
            "date": "2026-11-17T01:29:58Z", "user": None,
        }
        with patch.object(custody, "_graphql", return_value=page([item])), \
             patch.object(custody, "_rest_commit_committer_user_id",
                          side_effect=custody.CustodyError("REST lookup unavailable")):
            with self.assertRaisesRegex(custody.CustodyError, "REST lookup unavailable"):
                custody.collect_pr("token", 76, HEAD)

    def test_rest_fallback_invalid_json_is_sanitized(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"not-json-secret"
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch("github_api_transport.open_github", return_value=opener):
            with self.assertRaisesRegex(custody.CustodyError, "invalid JSON") as caught:
                custody._rest_commit_committer_user_id(
                    "token", "d" * 40,
                    {"name": "GitHub", "email": "noreply@github.com",
                     "date": "2026-11-17T01:29:58Z"},
                )
        self.assertNotIn("not-json-secret", str(caught.exception))

    def test_rest_fallback_transport_and_timeout_fail_closed(self):
        graphql_committer = {
            "name": "GitHub", "email": "noreply@github.com",
            "date": "2026-11-17T01:29:58Z",
        }
        with patch(
            "github_api_transport.open_github", side_effect=urllib.error.URLError("temporary DNS failure")
        ):
            with self.assertRaisesRegex(custody.CustodyError, "transport failed"):
                custody._rest_commit_committer_user_id("token", "d" * 40, graphql_committer)
        with patch("github_api_transport.open_github", side_effect=TimeoutError()):
            with self.assertRaisesRegex(custody.CustodyError, "timed out"):
                custody._rest_commit_committer_user_id("token", "d" * 40, graphql_committer)

    def test_rejects_incomplete_commit_count(self):
        with patch.object(custody, "_graphql", return_value=page(
            [commit("b" * 40)], total=2
        )):
            with self.assertRaisesRegex(custody.CustodyError, "history is incomplete"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_unresolved_author_or_committer(self):
        missing = commit("b" * 40)
        missing["commit"]["committer"]["user"] = None
        with patch.object(custody, "_graphql", return_value=page([missing])):
            with self.assertRaisesRegex(custody.CustodyError, "not linked"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_incomplete_coauthor_connection(self):
        incomplete = commit("b" * 40)
        incomplete["commit"]["authors"]["totalCount"] = 2
        with patch.object(custody, "_graphql", return_value=page([incomplete])):
            with self.assertRaisesRegex(custody.CustodyError, "incomplete"):
                custody.collect_pr("token", 76, HEAD)

    def test_only_an_explicit_null_committer_link_can_use_rest(self):
        for link in ([], "User", {"__typename": "Bot", "databaseId": 11}, {}):
            item = commit(HEAD)
            item["commit"]["committer"]["user"] = link
            with self.subTest(link=link), patch.object(
                custody, "_graphql", return_value=page([item])
            ), patch.object(custody, "_rest_commit_committer_user_id") as fallback:
                with self.assertRaises(custody.CustodyError):
                    custody.collect_pr("token", 76, HEAD)
                fallback.assert_not_called()
        item = commit(HEAD)
        del item["commit"]["committer"]["user"]
        with patch.object(custody, "_graphql", return_value=page([item])), patch.object(
            custody, "_rest_commit_committer_user_id"
        ) as fallback:
            with self.assertRaisesRegex(custody.CustodyError, "link evidence is missing"):
                custody.collect_pr("token", 76, HEAD)
            fallback.assert_not_called()

    def test_missing_coauthor_pagination_state_and_missing_expected_head_are_rejected(self):
        item = commit(HEAD)
        item["commit"]["authors"]["pageInfo"] = {}
        with patch.object(custody, "_graphql", return_value=page([item])):
            with self.assertRaisesRegex(custody.CustodyError, "co-author history is incomplete"):
                custody.collect_pr("token", 76, HEAD)
        with patch.object(custody, "_graphql", return_value=page([commit("b" * 40)])):
            with self.assertRaisesRegex(custody.CustodyError, "omits the expected PR head"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_head_change_during_enumeration(self):
        changed = page([commit("b" * 40)])
        changed["repository"]["pullRequest"]["headRefOid"] = "d" * 40
        with patch.object(custody, "_graphql", return_value=changed):
            with self.assertRaisesRegex(custody.CustodyError, "head changed"):
                custody.collect_pr("token", 76, HEAD)


class ReviewerIndependenceTests(unittest.TestCase):
    def test_accepts_trusted_reviewer_outside_author_and_contributors(self):
        custody.require_independent(20, {20, 21}, 1, {10, 11})

    def test_rejects_untrusted_reviewer(self):
        with self.assertRaisesRegex(custody.CustodyError, "not in the trusted"):
            custody.require_independent(20, {21}, 1, {10, 11})

    def test_rejects_author_or_commit_contributor(self):
        for reviewer in (1, 10):
            with self.subTest(reviewer=reviewer), self.assertRaisesRegex(
                custody.CustodyError, "not independent"
            ):
                custody.require_independent(reviewer, {reviewer}, 1, {10, 11})


if __name__ == "__main__":
    unittest.main()
