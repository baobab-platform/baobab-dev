#!/usr/bin/env python3
"""Read-only verification of branch and tag controls required for DEV-10 release."""
import json
import os
import sys

from custody_independence import REPOSITORY
from github_api_transport import GitHubAPIError, rest_request
from release_tag_policy import classify

REQUIRED_TAG_RULES = {"creation", "update", "deletion"}
REQUIRED_TAG_PATTERNS = {"refs/tags/v*", "~ALL"}


class GovernanceError(ValueError):
    pass


def verify_main(branch, effective_rules):
    if not isinstance(branch, dict) or branch.get("name") != "main" or branch.get("protected") is not True:
        raise GovernanceError("GitHub does not report main as protected")
    if not isinstance(effective_rules, list) or not all(isinstance(rule, dict) for rule in effective_rules):
        raise GovernanceError("effective main branch rules are unavailable")
    for rule in effective_rules:
        if rule.get("type") != "pull_request":
            continue
        review = rule.get("parameters")
        if (isinstance(review, dict) and type(review.get("required_approving_review_count")) is int
                and review["required_approving_review_count"] > 0
                and review.get("dismiss_stale_reviews_on_push") is True
                and review.get("require_last_push_approval") is True):
            break
    else:
        raise GovernanceError("main requires current-head PR review and stale-review dismissal")
    if not any(
        rule.get("type") == "required_status_checks"
        and isinstance(rule.get("parameters"), dict)
        and rule["parameters"].get("strict_required_status_checks_policy") is True
        and isinstance(rule["parameters"].get("required_status_checks"), list)
        and rule["parameters"]["required_status_checks"]
        for rule in effective_rules
    ):
        raise GovernanceError("main requires enforced up-to-date status checks")


def matching_tag_ruleset(ruleset):
    if (not isinstance(ruleset, dict) or ruleset.get("target") != "tag"
            or ruleset.get("enforcement") != "active"):
        return False
    conditions = ruleset.get("conditions")
    names = conditions.get("ref_name") if isinstance(conditions, dict) else None
    if not isinstance(names, dict):
        return False
    includes, excludes = names.get("include"), names.get("exclude")
    if (not isinstance(includes, list) or not all(isinstance(item, str) for item in includes)
            or not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes)):
        return False
    # These supported includes protect the entire canonical release namespace.
    return bool(REQUIRED_TAG_PATTERNS.intersection(includes)) and not excludes


def verify_tag_protection(rulesets):
    coverage = {}
    for ruleset in rulesets:
        if not matching_tag_ruleset(ruleset):
            continue
        rules = ruleset.get("rules")
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            kind = rule.get("type")
            if isinstance(kind, str) and kind in REQUIRED_TAG_RULES:
                coverage.setdefault(kind, []).append(ruleset["id"])
    missing = REQUIRED_TAG_RULES - coverage.keys()
    if missing:
        raise GovernanceError("active canonical release-tag protection is missing: " + ", ".join(sorted(missing)))
    return coverage


def read_governance(token):
    base = f"/repos/{REPOSITORY}"

    def get(path):
        return rest_request(token, "GET", base + path)[1]

    verify_main(get("/branches/main"), get("/rules/branches/main"))
    index = get("/rulesets?includes_parents=true&per_page=100")
    if not isinstance(index, list) or len(index) >= 100:
        raise GovernanceError("complete tag ruleset inventory is unavailable")
    active = []
    for row in index:
        if isinstance(row, dict) and row.get("target") == "tag" and row.get("enforcement") == "active":
            ruleset_id = row.get("id")
            if type(ruleset_id) is not int or ruleset_id <= 0:
                raise GovernanceError("active tag ruleset identity is unavailable")
            detail = get(f"/rulesets/{ruleset_id}")
            if not isinstance(detail, dict) or detail.get("id") != ruleset_id:
                raise GovernanceError("tag ruleset detail does not match its immutable ID")
            active.append(detail)
    return verify_tag_protection(active)


def main():
    tag = os.environ.get("GITHUB_REF_NAME", "")
    token = os.environ.get("GITHUB_TOKEN")
    if (os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or not token or classify(tag) is None):
        print("::error::Release governance readback requires the canonical repository and a release tag", file=sys.stderr)
        return 2
    try:
        rulesets = read_governance(token)
    except (GitHubAPIError, GovernanceError) as exc:
        print(f"::error::Release governance refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"branch": "main", "release_tag": tag, "tag_rulesets": rulesets}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
