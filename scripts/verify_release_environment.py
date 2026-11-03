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
import re
import sys

NAME = "dev10-release-promotion"
STABLE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+", re.ASCII)


class PromotionEnvironmentError(ValueError):
    pass


def require(ok: bool, error: str) -> None:
    if not ok:
        raise PromotionEnvironmentError(error)


def qualify(environment: dict, policies: dict, tag: str) -> dict:
    require(isinstance(environment, dict) and environment.get("name") == NAME,
            "expected configured release-promotion environment")
    require(bool(STABLE.fullmatch(tag)), "promotion requires exact stable semver tag")
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
    # A broad '*' rule would allow arbitrary release or PR workflow refs
    # despite the presence of one narrowly configured tag rule.
    require(all(isinstance(entry, dict) and entry.get("type") == "tag"
                and isinstance(entry.get("name"), str)
                and entry["name"].startswith("v")
                and entry["name"] not in ("v*", "v**")
                and entry["name"].count(".") >= 2 for entry in entries),
            "release environment admits a non-tag or over-broad ref pattern")
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
