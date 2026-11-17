"""Regression tests for complete DEV-10 GitHub commit-custody enumeration."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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
                "author": {"databaseId": 1},
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
        self.assertIsNone(graphql.call_args_list[0].args[2]["after"])
        self.assertEqual(graphql.call_args_list[1].args[2]["after"], "cursor-1")

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
