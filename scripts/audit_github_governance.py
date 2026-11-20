"""Capture sanitized read-only observations of GitHub release controls."""
import json
import os
import re

from custody_independence import REPOSITORY
from github_api_transport import GitHubAPIError, rest_request
from verify_release_governance import (
    GovernanceError,
    matching_tag_ruleset,
    read_active_tag_rulesets,
    verify_main,
    verify_tag_protection,
)


ENVIRONMENTS = (
    "dev10-security-policy-read",
    "dev10-security-policy-provision",
    "dev10-release-promotion",
)


def gate_result(check, *evidence):
    try:
        check(*evidence)
    except GovernanceError as exc:
        return {"status": "refused", "reason": str(exc)}
    return {"status": "requirements_observed"}


def read_environment(read, name):
    status, payload = read(f"/environments/{name}")
    entry = {"http_status": status, "status": "unverified"}
    if status != 200 or not isinstance(payload, dict) or payload.get("name") != name:
        return entry
    rules = payload.get("protection_rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        return entry
    reviewer_rules = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    review_rule = reviewer_rules[0] if len(reviewer_rules) == 1 else {}
    self_review = review_rule.get("prevent_self_review")
    admin_bypass = payload.get("can_admins_bypass")
    return {**entry, "status": "observed",
            "review_rule_count": len(reviewer_rules),
            "prevent_self_review": self_review if type(self_review) is bool else None,
            "can_admins_bypass": admin_bypass if type(admin_bypass) is bool else None}


def observe_governance(token):
    base = f"/repos/{REPOSITORY}"

    def read(path):
        return rest_request(token, "GET", base + path, allowed_status=(403, 404))

    branch_status, branch = read("/branches/main")
    rules_status, rules = read("/rules/branches/main")
    detail_status, _ = read("/branches/main/protection")
    observed_main = isinstance(branch, dict) and branch.get("name") == "main"
    protected = branch.get("protected") if observed_main else None
    commit = branch.get("commit") if observed_main else None
    sha = commit.get("sha") if isinstance(commit, dict) else None
    main = {"branch_http_status": branch_status, "rules_http_status": rules_status,
            "protection_http_status": detail_status,
            "protected": protected if type(protected) is bool else None,
            "head_sha": sha if isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{40}", sha) else None,
            "effective_rule_count": len(rules) if isinstance(rules, list) else None,
            "release_gate": {"status": "unverified"}}
    if branch_status == rules_status == 200:
        main["release_gate"] = gate_result(verify_main, branch, rules)

    def tag_evidence(path):
        status, body = read(path)
        if status != 200:
            raise GovernanceError(f"ruleset inventory unavailable (HTTP {status})")
        return body

    try:
        active = read_active_tag_rulesets(tag_evidence)
    except GovernanceError as exc:
        tags = {"status": "unverified", "reason": str(exc)}
    else:
        tags = {
            "status": "observed",
            "rulesets": [
                {"id": row["id"], "matches_release_namespace": matching_tag_ruleset(row),
                 "bypass_actor_count": len(row["bypass_actors"])
                 if isinstance(row.get("bypass_actors"), list) else None}
                for row in active
            ],
            "release_gate": gate_result(verify_tag_protection, active),
        }
    return {"schema": "dev10.github-governance-observation.v1", "repository": REPOSITORY,
            "main": main, "tags": tags,
            "environments": {name: read_environment(read, name) for name in ENVIRONMENTS}}


if __name__ == "__main__":
    token = os.environ.get("GITHUB_TOKEN")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or not token:
        raise SystemExit("Governance observation requires authenticated reads of the canonical repository")
    try:
        print(json.dumps(observe_governance(token), indent=2, sort_keys=True))
    except GitHubAPIError as exc:
        raise SystemExit(f"Governance observation failed: {exc}") from None
