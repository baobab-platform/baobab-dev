#!/usr/bin/env python3
"""Validate actual GitHub Environment release-protection configuration.

The GITHUB_ENVIRONMENT reference and an enabled repository variable do not
prove required reviewers or restricted deployment tags exist. R5 fails closed
until GitHub's own REST responses attest to the owner-configured controls.
"""
from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
import json
from pathlib import Path
import sys

try:
    from release_tag_policy import classify
except ModuleNotFoundError as exc:
    if exc.name != "release_tag_policy":
        raise
    # The test harness imports this script directly from its file path. Load
    # only the adjacent, repository-owned policy, never a caller search path.
    import importlib.util
    policy_file = Path(__file__).resolve().with_name("release_tag_policy.py")
    policy_spec = importlib.util.spec_from_file_location("baobab_release_tag_policy", policy_file)
    if policy_spec is None or policy_spec.loader is None:
        raise ImportError("release policy cannot be loaded") from exc
    policy_module = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy_module)
    classify = policy_module.classify

NAME = "dev10-release-promotion"
# GitHub Environment selected-tag rules are glob patterns, not regex.
# The strict release_tag_policy.classify() separately validates semver.
ALLOWED_TAG_PATTERNS = frozenset({"v*.*.*", "v*.*.*-rc.*"})


class PromotionEnvironmentError(ValueError):
    pass


def require(ok: bool, error: str) -> None:
    if not ok:
        raise PromotionEnvironmentError(error)


def qualify(environment: dict, policies: dict, tag: str) -> dict:
    require(isinstance(environment, dict) and environment.get("name") == NAME,
            "expected configured release-promotion environment")
    require(classify(tag) is not None,
            "promotion requires strict GA or numbered RC semver")
    rules = environment.get("protection_rules")
    require(isinstance(rules, list), "missing GitHub Environment protection rules")
    reviewers = [r for r in rules if isinstance(r, dict)
                 and r.get("type") == "required_reviewers"]
    require(len(reviewers) == 1, "exactly one required-reviewers rule must be configured")
    rule = reviewers[0]
    require(rule.get("prevent_self_review") is True,
            "initiating release actor must not self-approve")
    entries = rule.get("reviewers")
    require(isinstance(entries, list) and len(entries) > 0,
            "at least one independent reviewer must be configured")
    require(all(isinstance(entry, dict) and entry.get("type") in {"User", "Team"}
                and isinstance(entry.get("reviewer"), dict)
                for entry in entries), "invalid reviewer configuration")

    deploy = environment.get("deployment_branch_policy")
    require(isinstance(deploy, dict)
            and deploy.get("custom_branch_policies") is True
            and deploy.get("protected_branches") is False,
            "only explicit deployment tag patterns are accepted for release")
    require(isinstance(policies, dict) and isinstance(policies.get("branch_policies"), list),
            "missing selected branches/tags response")
    entries = policies["branch_policies"]
    require(len(entries) > 0, "no selected deployment tag patterns")
    # Require exactly the two owner-configured GitHub glob patterns.
    # v*.*.* also matches RC tags in glob syntax; strict semver classification
    # above rejects beta, malformed and unnumbered RC tags.
    require(len(entries) == len(ALLOWED_TAG_PATTERNS)
            and all(isinstance(entry, dict) and entry.get("type") == "tag"
                    and entry.get("name") in ALLOWED_TAG_PATTERNS for entry in entries)
            and {entry["name"] for entry in entries} == ALLOWED_TAG_PATTERNS,
            "release environment must select exactly v*.*.* and v*.*.*-rc.* tag patterns")
    matched = [entry["name"] for entry in entries
               if fnmatchcase(tag, entry["name"])]
    require(bool(matched), f"tag {tag} is not admitted by GitHub Environment policy")
    return {"environment": NAME, "release_tag": tag,
            "required_reviewers": len(rule["reviewers"]),
            "prevent_self_review": True, "accepted_tag_patterns": matched}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--policies", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        evidence = qualify(json.loads(args.environment.read_text()),
                           json.loads(args.policies.read_text()), args.tag)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print("::error::DEV-10 R5 GitHub Environment governance DENIED:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
