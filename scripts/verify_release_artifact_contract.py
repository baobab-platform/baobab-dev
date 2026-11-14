#!/usr/bin/env python3
"""Fail-closed producer/consumer contract for DEV-10 release candidate records.

Artifact containers: RC published-info-{target}; GA ga-reused-candidates.
Each contains {target}.json. Downloaded merged directory must contain
exactly four records, with no additional files or symlinks.
"""
import argparse
import json
import re
from pathlib import Path

TARGETS = ("final", "frontend", "frontend-e2e", "infra")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NUM = r"(?:0|[1-9][0-9]*)"
TAG = re.compile(rf"^v{NUM}\.{NUM}\.{NUM}(?:-rc\.[1-9][0-9]*)?$")
BASE = "ghcr.io/baobab-platform/baobab-dev:"

def validate(directory: Path, tag: str, channel: str):
    if not TAG.fullmatch(tag):
        raise ValueError("invalid release tag")
    if channel == "rc" and "-rc." not in tag:
        raise ValueError("RC channel requires numbered RC tag")
    if channel == "ga" and "-rc." in tag:
        raise ValueError("GA channel requires stable tag")
    expected = {t + ".json" for t in TARGETS}
    if not directory.is_dir() or {p.name for p in directory.iterdir()} != expected:
        raise ValueError("candidate artifact files must be exactly: " + ", ".join(sorted(expected)))
    results = {}
    common_signer = None
    common_run_id = None
    for target in TARGETS:
        path = directory / (target + ".json")
        if path.is_symlink() or not path.is_file():
            raise ValueError("candidate record must be a regular file: " + target)
        def reject_duplicate(keys):
            obj = {}
            for key, value in keys:
                if key in obj:
                    raise ValueError("duplicate JSON key: " + key)
                obj[key] = value
            return obj
        record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)
        required_keys = ({"target", "tag", "digest"} if channel == "rc" else
                         {"target", "tag", "digest", "signer_tag", "signer_run_id"})
        if not isinstance(record, dict) or set(record) != required_keys:
            raise ValueError("unexpected candidate record schema: " + target)
        suffix = "" if target == "final" else "-" + target
        expected_tag = BASE + tag[1:] + suffix
        if record["target"] != target or record["tag"] != expected_tag:
            raise ValueError("candidate target/tag identity mismatch: " + target)
        digest = record["digest"]
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError("invalid OCI digest: " + target)
        if channel == "ga":
            signer_tag = record["signer_tag"]
            signer_match = re.fullmatch(r"(v[0-9]+\.[0-9]+\.[0-9]+)-rc\.[1-9][0-9]*", signer_tag) if isinstance(signer_tag, str) else None
            run_id = record["signer_run_id"]
            if signer_match is None or signer_match.group(1) != tag:
                raise ValueError("GA signer tag must be a numbered RC in the exact release version family")
            if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
                raise ValueError("GA signer workflow run ID must be a positive integer")
            if common_signer is not None and (signer_tag != common_signer or run_id != common_run_id):
                raise ValueError("GA candidate records disagree on qualified RC signer")
            common_signer, common_run_id = signer_tag, run_id
        results[target] = digest
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--channel", required=True, choices=("rc", "ga"))
    parser.add_argument("--rc-directory", type=Path)
    parser.add_argument("--rc-tag")
    args = parser.parse_args()
    try:
        result = validate(args.directory, args.tag, args.channel)
        if (args.rc_directory is None) != (args.rc_tag is None):
            raise ValueError("RC directory and RC tag must be supplied together")
        if args.rc_directory is not None:
            if args.channel != "ga":
                raise ValueError("RC digest comparison is GA-only")
            original = validate(args.rc_directory, args.rc_tag, "rc")
            if result != original:
                raise ValueError("GA digests differ from qualified RC digests")
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"channel": args.channel, "tag": args.tag, "targets": result}, sort_keys=True))

if __name__ == "__main__":
    main()
