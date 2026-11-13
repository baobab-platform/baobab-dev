"""Negative controls for DEV-10 R5 protected stable-tag promotion."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_release_environment", ROOT / "scripts/verify_release_environment.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class PromotionEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "name": "dev10-release-promotion",
            "protection_rules": [{
                "type": "required_reviewers", "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"login": "independent-reviewer"}}],
            }],
            "deployment_branch_policy": {
                "protected_branches": False, "custom_branch_policies": True,
            },
        }
        self.policies = {
            "branch_policies": [{"type": "tag", "name": "v*.*.*"}],
        }

    def test_explicit_independent_review_and_tag_admission_pass(self):
        evidence = mod.qualify(self.env, self.policies, "v1.5.0")
        self.assertEqual(evidence["required_reviewers"], 1)
        self.assertEqual(evidence["accepted_tag_patterns"], ["v*.*.*"])

    def test_rc_series_uses_same_independent_protected_environment(self):
        for tag in ("v1.5.0-rc.1", "v2.0.0-rc.2", "v10.3.12-rc.10"):
            with self.subTest(tag=tag):
                evidence = mod.qualify(self.env, self.policies, tag)
                self.assertTrue(evidence["prevent_self_review"])
                self.assertEqual(evidence["release_tag"], tag)
        weak = deepcopy(self.env)
        weak["protection_rules"][0]["prevent_self_review"] = False
        with self.assertRaises(mod.PromotionEnvironmentError):
            mod.qualify(weak, self.policies, "v1.5.0-rc.1")

    def test_missing_or_self_approved_review_is_refused(self):
        for change in (
            lambda e: e.pop("protection_rules"),
            lambda e: e["protection_rules"][0].update(prevent_self_review=False),
            lambda e: e["protection_rules"][0].update(reviewers=[]),
            lambda e: e["protection_rules"][0].update(reviewers=[{"type": "User"}]),
        ):
            candidate = deepcopy(self.env)
            change(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(mod.PromotionEnvironmentError):
                mod.qualify(candidate, self.policies, "v1.5.0")

    def test_open_deploy_branches_and_wide_rules_refused(self):
        for policy in (
            {"branch_policies": [{"type": "branch", "name": "main"}]},
            {"branch_policies": [{"type": "tag", "name": "*"}]},
            {"branch_policies": [{"type": "tag", "name": "v*"}]},
            {"branch_policies": [{"type": "tag", "name": "v2.*.*"}]},
            {"branch_policies": []},
        ):
            with self.subTest(policy=policy), self.assertRaises(mod.PromotionEnvironmentError):
                mod.qualify(self.env, policy, "v1.5.0")
        candidate = deepcopy(self.env)
        candidate["deployment_branch_policy"] = None
        with self.assertRaises(mod.PromotionEnvironmentError):
            mod.qualify(candidate, self.policies, "v1.5.0")

    def test_unknown_release_and_pr_refs_refused(self):
        for tag in ("", "v1.5.0-rc.0", "v1.5.0-rc.01",
                    "v1.5.0-rc.foo", "v2.0.0-beta.1", "v1.5.0-rc.1-extra",
                    "1.5.0", "refs/pull/58/merge", "v1.5.0\ninjected"):
            with self.subTest(tag=tag), self.assertRaises(mod.PromotionEnvironmentError):
                mod.qualify(self.env, self.policies, tag)


if __name__ == "__main__":
    unittest.main()
