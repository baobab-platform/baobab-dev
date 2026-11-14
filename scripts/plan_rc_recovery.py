#!/usr/bin/env python3
"""Plan immutable DEV-10 RC recovery; never create, move or delete tags.

Read-only: consult remote refs, refuse non-RC inputs, require a reviewed
replacement SHA and propose the next unused RC tag. Tag creation is a
separate protected human-controlled operation.
"""
import argparse
import re
import subprocess
import sys
from release_tag_policy import classify

SHA = re.compile(r"[0-9a-f]{40}\Z")

def remote_tags(remote):
    result = subprocess.run(["git", "ls-remote", "--tags", "--refs", remote],
                            check=True, capture_output=True, text=True)
    refs = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].startswith("refs/tags/"):
            raise ValueError("unexpected remote tag listing")
        refs.add(fields[1].removeprefix("refs/tags/"))
    return refs

def next_rc(failed, existing):
    if classify(failed) != "rc":
        raise ValueError("recovery requires a numbered RC tag")
    if failed not in existing:
        raise ValueError("failed RC must already exist remotely; refusing ambiguous recovery")
    family, number = failed.rsplit("-rc.", 1)
    maximum = max((int(t.rsplit("-rc.", 1)[1]) for t in existing
                   if t.startswith(family + "-rc.") and classify(t) == "rc"),
                  default=int(number))
    candidate = family + "-rc." + str(max(maximum, int(number)) + 1)
    if candidate in existing:
        raise ValueError("replacement RC already exists")
    return candidate

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--failed-tag", required=True)
    p.add_argument("--replacement-sha", required=True)
    p.add_argument("--remote", default="origin")
    args = p.parse_args()
    if not SHA.fullmatch(args.replacement_sha):
        p.error("replacement must be a full lowercase 40-character commit SHA")
    try:
        tags = remote_tags(args.remote)
        candidate = next_rc(args.failed_tag, tags)
        # Refresh main before validating ancestry; never trust a stale tracking ref.
        subprocess.run(["git", "fetch", "--no-tags", args.remote, "main"],
                       check=True, capture_output=True)
        # A replacement must be a reviewed commit in main history.
        subprocess.run(["git", "merge-base", "--is-ancestor", args.replacement_sha,
                        args.remote + "/main"], check=True, capture_output=True)
    except (ValueError, subprocess.CalledProcessError, OSError) as exc:
        p.error(str(exc))
    print("FAILED RC (immutable): " + args.failed_tag)
    print("PROPOSED NEW RC: " + candidate)
    print("REVIEWED SOURCE SHA: " + args.replacement_sha)
    print("No tag was created or modified. After approval, create a new tag at")
    print("the reviewed commit, verify remote absence again, and push WITHOUT --force.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
