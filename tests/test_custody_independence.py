"""Numeric GitHub contributor separation regression tests."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import custody_independence as mod

def user(i, login):
    return {"databaseId": i, "login": login}

def commit(oid, authors=(1,), committer=1):
    return {"oid": oid, "authors": {"totalCount": len(authors),
            "nodes": [{"user": user(i, str(i))} for i in authors]},
            "committer": {"user": user(committer, str(committer))}}

class CustodyIndependenceTests(unittest.TestCase):
    def test_independent_reviewer(self):
        contributors = mod.collect_contributors([commit("a")], 1)
        mod.require_independent(2, {2}, 1, contributors)

    def test_author_coauthor_and_committer_excluded(self):
        for record in (commit("a", authors=(2,)),
                       commit("a", authors=(1,2)),
                       commit("a", committer=2)):
            with self.subTest(record=record), self.assertRaises(mod.IndependenceError):
                mod.require_independent(2, {2}, 1,
                    mod.collect_contributors([record], 1))

    def test_pr_author_excluded(self):
        with self.assertRaises(mod.IndependenceError):
            mod.require_independent(1, {1}, 1, set())

    def test_untrusted_excluded(self):
        with self.assertRaises(mod.IndependenceError):
            mod.require_independent(2, {3}, 1, {1})

    def test_renamed_login_same_id_excluded(self):
        with self.assertRaises(mod.IndependenceError):
            mod.require_independent(2, {2}, 1,
                mod.collect_contributors([commit("a", authors=(2,))], 1))

    def test_incomplete_history_and_unresolved_identity(self):
        with self.assertRaises(mod.IndependenceError):
            mod.collect_contributors([commit("a")], 311)
        bad = commit("a")
        bad["authors"]["nodes"][0]["user"] = None
        with self.assertRaises(mod.IndependenceError):
            mod.collect_contributors([bad], 1)
        bad = commit("a")
        bad["authors"]["totalCount"] = 2
        with self.assertRaises(mod.IndependenceError):
            mod.collect_contributors([bad], 1)

    def test_duplicate_commit_records_rejected(self):
        with self.assertRaises(mod.IndependenceError):
            mod.collect_contributors([commit("same"), commit("same")], 2)

    def test_service_committer_is_still_compared_by_numeric_identity(self):
        record = commit("a")
        record["committer"]["user"] = user(99, "web-flow")
        self.assertEqual(mod.collect_contributors([record], 1), {1, 99})

    def test_unresolved_committer_fails_closed(self):
        record = commit("a")
        record["committer"]["user"] = None
        with self.assertRaises(mod.IndependenceError):
            mod.collect_contributors([record], 1)

if __name__ == "__main__":
    unittest.main()
