#!/usr/bin/env python3
"""Validate GA candidates against a successful prior RC workflow and its artifacts."""
import argparse
import json
from pathlib import Path
from verify_rc_ga_continuity import TARGETS, ContinuityError, qualify

def records(directory, tag, sha):
    expected_files = {target + ".json" for target in TARGETS}
    if not directory.is_dir() or {p.name for p in directory.iterdir()} != expected_files:
        raise ContinuityError("exactly four candidate records required")
    images = {}
    for target in TARGETS:
        item = json.loads((directory / (target + ".json")).read_text())
        suffix = "" if target == "final" else "-" + target
        expected_tag = "ghcr.io/baobab-platform/baobab-dev:" + tag[1:] + suffix
        if item.get("target") != target or item.get("tag") != expected_tag:
            raise ContinuityError("candidate target/tag mismatch: " + target)
        images[target] = item.get("digest")
    return {"release_tag": tag, "source_sha": sha, "images": images}

def verify(run, rc_dir, ga_dir, ga_tag, ga_sha):
    if run.get("status") != "completed" or run.get("conclusion") != "success" or run.get("event") != "push":
        raise ContinuityError("RC workflow did not complete successfully")
    if run.get("path", "").split("@")[0] != ".github/workflows/publish.yml":
        raise ContinuityError("RC workflow identity mismatch")
    if run.get("head_sha") != ga_sha:
        raise ContinuityError("RC and GA commits differ")
    tag = run.get("head_branch")
    if not isinstance(tag, str):
        raise ContinuityError("RC tag absent")
    rc = records(rc_dir, tag, ga_sha)
    rc.update(qualified=True, qualification_ref=run.get("html_url"), run_id=run.get("id"))
    return qualify(rc, records(ga_dir, ga_tag, ga_sha))

def main():
    p=argparse.ArgumentParser()
    for flag in ("rc-run","rc-records","ga-records","ga-tag","ga-sha","output"):
        p.add_argument("--"+flag,required=True)
    a=p.parse_args()
    try:
        result=verify(json.loads(Path(a.rc_run).read_text()),Path(a.rc_records),
                      Path(a.ga_records),a.ga_tag,a.ga_sha)
    except (ValueError,OSError,TypeError) as exc:
        p.error(str(exc))
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")

if __name__=="__main__":
    main()
