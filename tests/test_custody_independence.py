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
            "author": {"user": {"databaseId": author}},
            "committer": {"user": {"databaseId": committer}},
            "authors": {
                "totalCount": len(authors),
                "pageInfo": {"hasNextPage": False},
                "nodes": [{"user": {"databaseId": item}} for item in authors],
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
    def test_collects_authors_coauthors_and_committers_across_all_pages(self):
        responses = [
            page([commit("b" * 40, authors=(10, 12))],
                 has_next=True, cursor="cursor-1", total=2),
            page([commit("c" * 40, author=13, committer=14, authors=(13,))],
                 total=2),
        ]
        with patch.object(custody, "_graphql", side_effect=responses) as graphql:
            author, contributors = custody.collect_pr("token", 76, HEAD)
        self.assertEqual(author, 1)
        self.assertEqual(contributors, {10, 11, 12, 13, 14})
        self.assertEqual(graphql.call_count, 2)
        self.assertEqual(graphql.call_args_list[1].args[2]["after"], "cursor-1")

    def test_queries_pull_request_author_with_user_inline_fragment(self):
        with patch.object(custody, "_graphql", return_value=page([commit("b" * 40)])) as graphql:
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
        response = page([commit("b" * 40)])
        response["repository"]["pullRequest"]["author"] = None
        with patch.object(custody, "_graphql", return_value=response):
            with self.assertRaisesRegex(custody.CustodyError, "identity is missing"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_non_user_pull_request_author_actors(self):
        for typename in ("Bot", "Organization", "Mannequin", "EnterpriseUserAccount"):
            response = page([commit("b" * 40)])
            response["repository"]["pullRequest"]["author"] = {
                "__typename": typename, "databaseId": 1,
            }
            with self.subTest(typename=typename), patch.object(
                custody, "_graphql", return_value=response
            ), self.assertRaisesRegex(custody.CustodyError, "not a concrete GitHub User"):
                custody.collect_pr("token", 76, HEAD)

    def test_rejects_missing_or_invalid_pull_request_author_numeric_id(self):
        for user_id in (None, 0, -1, True, "1", 1.0):
            response = page([commit("b" * 40)])
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
        author_id, contributors = custody.collect_pr(
            os.environ["GH_TOKEN"],
            int(os.environ["DEV10_GRAPHQL_INTEGRATION_PR_NUMBER"]),
            os.environ["DEV10_GRAPHQL_INTEGRATION_EXPECTED_HEAD"],
        )
        self.assertGreater(author_id, 0)
        self.assertTrue(contributors)

    @unittest.skipUnless(
        os.environ.get("GH_TOKEN"),
        "live exact-SHA service-committer validation requires GH_TOKEN",
    )
    def test_live_exact_sha_reconciles_service_committer_from_decision_history(self):
        data = custody._graphql(
            os.environ["GH_TOKEN"],
            """
            query($owner: String!, $name: String!, $number: Int!) {
              repository(owner: $owner, name: $name) {
                pullRequest(number: $number) {
                  commits(first: 100) {
                    totalCount
                    pageInfo { hasNextPage }
                    nodes {
                      commit {
                        oid
                        committer { name email date user { databaseId login } }
                      }
                    }
                  }
                }
              }
            }
            """,
            {"owner": "baobab-platform", "name": "baobab-dev", "number": 76},
        )
        repository = data.get("repository")
        pull = repository.get("pullRequest") if isinstance(repository, dict) else None
        commits = pull.get("commits") if isinstance(pull, dict) else None
        self.assertIsInstance(commits, dict)
        nodes = commits.get("nodes")
        self.assertIsInstance(nodes, list)
        self.assertEqual(commits.get("totalCount"), len(nodes))
        self.assertFalse(commits.get("pageInfo", {}).get("hasNextPage"))
        candidates = []
        for item in nodes:
            commit_object = item.get("commit") if isinstance(item, dict) else None
            actor = commit_object.get("committer") if isinstance(commit_object, dict) else None
            if (isinstance(actor, dict) and actor.get("name") == "GitHub"
                    and actor.get("email") == "noreply@github.com"):
                candidates.append((commit_object.get("oid"), actor))
        self.assertTrue(candidates, "PR #76 history no longer contains a GitHub service committer fixture")
        oid, actor = candidates[0]
        self.assertEqual(len(oid), 40)
        rest_user_id = custody._rest_commit_committer_user_id(
            os.environ["GH_TOKEN"], oid, actor
        )
        self.assertGreater(rest_user_id, 0)
        graphql_user = actor.get("user")
        if isinstance(graphql_user, dict):
            self.assertEqual(rest_user_id, graphql_user.get("databaseId"))

    def test_rest_fallback_resolves_exact_sha_with_metadata_corroboration(self):
        oid = "d" * 40
        payload = {
            "sha": oid,
            "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}},
            "committer": {"type": "User", "id": 19864447, "login": "web-flow"},
        }
        response = MagicMock()
        response.read.return_value = json.dumps(payload).encode("utf-8")
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch.object(custody, "open_github", return_value=opener) as open_github:
            user_id = custody._rest_commit_committer_user_id("token", oid, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})
        self.assertEqual(user_id, 19864447)
        request = open_github.call_args.args[0]
        self.assertEqual(request.full_url, f"https://api.github.com/repos/baobab-platform/baobab-dev/commits/{oid}")

    def test_rest_fallback_rejects_a_different_commit_sha(self):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "sha": "e" * 40,
            "committer": {"type": "User", "id": 19864447},
        }).encode("utf-8")
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch.object(custody, "open_github", return_value=opener):
            with self.assertRaisesRegex(custody.CustodyError, "different commit SHA"):
                custody._rest_commit_committer_user_id("token", "d" * 40, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})

    def test_rest_fallback_rejects_name_email_and_timestamp_mismatches(self):
        oid = "d" * 40
        raw = {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}
        for key, value in (("name", "Other"), ("email", "other@example.invalid"),
                           ("date", "2026-11-17T01:29:59Z"), ("date", "2026-11-17T01:29:58")):
            response = MagicMock()
            response.read.return_value = json.dumps({
                "sha": oid, "commit": {"committer": raw},
                "committer": {"type": "User", "id": 19864447, "login": "web-flow"},
            }).encode("utf-8")
            expected = dict(raw)
            expected[key] = value
            opener = MagicMock()
            opener.__enter__.return_value = response
            with self.subTest(field=key, value=value), patch.object(
                custody, "open_github", return_value=opener
            ), self.assertRaisesRegex(custody.CustodyError, "metadata disagree"):
                custody._rest_commit_committer_user_id("token", oid, expected)

    def test_rest_fallback_accepts_equivalent_timezone_spellings(self):
        oid = "d" * 40
        response = MagicMock()
        response.read.return_value = json.dumps({
            "sha": oid,
            "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com",
                                      "date": "2026-11-17T01:29:58Z"}},
            "committer": {"type": "User", "id": 19864447, "login": "web-flow"},
        }).encode("utf-8")
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch.object(custody, "open_github", return_value=opener):
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
            response.read.return_value = json.dumps({
                "sha": "d" * 40,
                "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}},
                "committer": actor,
            }).encode("utf-8")
            opener = MagicMock()
            opener.__enter__.return_value = response
            with self.subTest(actor=actor), patch.object(
                custody, "open_github", return_value=opener
            ), self.assertRaisesRegex(custody.CustodyError, expected):
                custody._rest_commit_committer_user_id("token", "d" * 40, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})

    def test_rest_http_error_reports_status_and_request_id_without_body(self):
        from email.message import Message
        headers = Message()
        headers["x-github-request-id"] = "ABC123-DEF456"
        error = urllib.error.HTTPError(
            "https://api.github.com/repos/baobab-platform/baobab-dev/commits/" + "d" * 40,
            403, "Forbidden", headers, None,
        )
        with patch.object(custody, "open_github", side_effect=error):
            with self.assertRaisesRegex(
                custody.CustodyError, "HTTP 403.*ABC123-DEF456"
            ) as caught:
                custody._rest_commit_committer_user_id("token", "d" * 40, {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"})
        self.assertNotIn("Forbidden", str(caught.exception))

    def test_collect_pr_adds_rest_reconciled_committer_to_contributor_set(self):
        oid = "d" * 40
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
        response.read.return_value = b"not-json-secret"
        opener = MagicMock()
        opener.__enter__.return_value = response
        with patch.object(custody, "open_github", return_value=opener):
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
        with patch.object(
            custody, "open_github", side_effect=urllib.error.URLError("temporary DNS failure")
        ):
            with self.assertRaisesRegex(custody.CustodyError, "transport failure"):
                custody._rest_commit_committer_user_id("token", "d" * 40, graphql_committer)
        with patch.object(custody, "open_github", side_effect=TimeoutError()):
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
