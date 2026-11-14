#!/usr/bin/env python3
"""DEV-10 GitHub Actions artifact-container contract (read-only, fail closed).

Validates exact artifact names, cardinality, expiry and producer workflow run
before a downstream job downloads or consumes candidate records.
"""
import argparse
import json
import re
from pathlib import Path

TARGETS = ("final", "frontend", "frontend-e2e", "infra")
RC_NAMES = {"published-info-" + t for t in TARGETS}
GA_NAMES = {"ga-reused-candidates"}
SHA = re.compile(r"[0-9a-f]{40}\Z")

def validate(payload, channel, run_id, source_sha):
    if channel not in ("rc", "ga"):
        raise ValueError("unknown release channel")
    if not isinstance(run_id, int) or run_id < 1 or not SHA.fullmatch(source_sha):
        raise ValueError("invalid expected run identity")
    # gh api --paginate --slurp produces an array of API response pages.
    pages = payload if isinstance(payload, list) else [payload]
    if not pages or any(not isinstance(page, dict) or not isinstance(page.get("artifacts"), list) for page in pages):
        raise ValueError("invalid Actions artifact API response")
    artifacts = [artifact for page in pages for artifact in page["artifacts"]]
    names = RC_NAMES if channel == "rc" else GA_NAMES
    selected = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("invalid artifact entry")
        if artifact.get("name") not in names:
            continue
        workflow = artifact.get("workflow_run")
        if (artifact.get("expired") is not False
            or not isinstance(artifact.get("id"), int)
            or artifact["id"] < 1
            or not isinstance(workflow, dict)
            or workflow.get("id") != run_id
            or workflow.get("head_sha") != source_sha):
            raise ValueError("candidate artifact is expired or has wrong producer identity")
        selected.append(artifact["name"])
    if len(selected) != len(names) or set(selected) != names:
        raise ValueError("missing, duplicate or unexpected candidate artifact container: " + repr(selected))
    # Reject unrecognized candidate prefixes to avoid silent producer drift.
    for artifact in artifacts:
        name = artifact.get("name")
        if isinstance(name, str) and (name.startswith("published-info-") or name.startswith("ga-reused-candidates")) and name not in names:
            raise ValueError("unexpected candidate artifact: " + name)
    return sorted(selected)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--channel", choices=("rc", "ga"), required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    try:
        names = validate(json.loads(args.input.read_text()), args.channel, args.run_id, args.sha)
    except (ValueError, OSError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"validated_artifacts": names}, sort_keys=True))

if __name__ == "__main__":
    main()
