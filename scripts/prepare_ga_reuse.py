#!/usr/bin/env python3
"""Create GA records from qualified RC digests, without a new build."""
import argparse
import json
import re
from pathlib import Path
from verify_rc_ga_workflow import records
from verify_rc_ga_continuity import TARGETS, ContinuityError, qualify

def prepare(run, directory, tag, sha, output):
    if run.get("status") != "completed" or run.get("conclusion") != "success" or run.get("event") != "push":
        raise ContinuityError("RC workflow not successful")
    if run.get("path", "").split("@")[0] != ".github/workflows/publish.yml":
        raise ContinuityError("RC workflow path mismatch")
    if run.get("head_sha") != sha:
        raise ContinuityError("GA source differs from qualified RC")
    rc_tag = run.get("head_branch")
    num = r"(?:0|[1-9][0-9]*)"
    stable = re.fullmatch(rf"v{num}\\.{num}\\.{num}", tag)
    rc_match = re.fullmatch(rf"(v{num}\\.{num}\\.{num})-rc\\.[1-9][0-9]*", rc_tag or "")
    if not stable or not rc_match or rc_match.group(1) != tag:
        raise ContinuityError("qualified RC tag must be the exact GA version family")
    run_id = run.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise ContinuityError("qualified RC workflow run ID missing or invalid")
    rc = records(directory, rc_tag, sha)
    rc.update(qualified=True, qualification_ref=run.get("html_url"), run_id=run_id)
    ga = {"release_tag": tag, "source_sha": sha, "images": dict(rc["images"])}
    result = qualify(rc, ga)
    output.mkdir(parents=True, exist_ok=True)
    for target in TARGETS:
        suffix = "" if target == "final" else "-" + target
        record = {"target": target, "tag": "ghcr.io/baobab-platform/baobab-dev:" + tag[1:] + suffix,
                  "digest": rc["images"][target], "signer_tag": rc_tag,
                  "signer_run_id": run_id}
        (output / (target + ".json")).write_text(json.dumps(record, sort_keys=True) + "\n")
    return result

def main():
    p = argparse.ArgumentParser()
    for name in ("run","records","tag","sha","output"):
        p.add_argument("--"+name, required=True)
    a = p.parse_args()
    try:
        result = prepare(json.loads(Path(a.run).read_text()), Path(a.records), a.tag, a.sha, Path(a.output))
    except (ValueError, OSError, TypeError) as exc:
        p.error(str(exc))
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
