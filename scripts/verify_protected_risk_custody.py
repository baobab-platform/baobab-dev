#!/usr/bin/env python3
"""Read-only GitHub custody verification for protected DEV-10 policy consumers.

The same merged-byte, owner and exact-head reviewer checks apply to both
policy readback and provisioning. Only the provisioner can write the anchor.
"""
import argparse
import json
import os
import re
from pathlib import Path

from custody_independence import REPOSITORY, review_timestamp
from provision_protected_risk_policy import (
    ProvisioningError, api_request, require, resolve_trusted_reviewers, verify_merged_custody,
)


def verify_read_custody(token, decision, decision_path, logins):
    require(isinstance(decision, dict), "protected decision must be a JSON object")
    path = Path(decision_path)
    require(path.as_posix().startswith("security/decisions/") and ".." not in path.parts
            and path.suffix == ".json", "decision must be a protected repository-relative JSON path")
    evidence = decision.get("approval_evidence")
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(REPOSITORY)}/pull/([1-9][0-9]*)", evidence
    ) if isinstance(evidence, str) else None
    require(match is not None, "invalid approval evidence URL")
    pr_number = int(match[1])
    _, pull = api_request(token, "GET", f"/repos/{REPOSITORY}/pulls/{pr_number}")
    head = pull.get("head") if isinstance(pull, dict) else None
    require(isinstance(head, dict) and isinstance(head.get("sha"), str)
            and re.fullmatch(r"[a-f0-9]{40}", head["sha"]),
            "merged approval PR head is unavailable")
    trusted = resolve_trusted_reviewers(token, logins)
    receipt = verify_merged_custody(
        token, decision, pr_number, head["sha"], trusted, decision_path=path.as_posix(),
    )
    return {
        **receipt,
        "approved_at": review_timestamp(receipt["approved_at"]).isoformat().replace("+00:00", "Z"),
        "approval_pr": evidence,
        "approval_pr_head": receipt["decision_pr_head"],
        "status": "approval_custody_verified",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--trusted-approvers", required=True,
                        help="comma-separated independently provisioned GitHub logins")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GITHUB_TOKEN is required for live GitHub custody")
    try:
        decision = json.loads(args.decision.read_text())
        logins = [item.strip() for item in args.trusted_approvers.split(",") if item.strip()]
        result = verify_read_custody(token, decision, args.decision, logins)
    except (ProvisioningError, ValueError) as exc:
        parser.error(str(exc))
    except OSError:
        parser.error("protected decision file could not be read")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
