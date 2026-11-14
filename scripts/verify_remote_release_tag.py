#!/usr/bin/env python3
"""Fail closed if an existing release tag resolves to a different commit.

Read-only Git remote check, supporting annotated and lightweight tags.
Server-side GitHub rulesets remain the authoritative prevention mechanism.
"""
import argparse
import re
import subprocess

SHA = re.compile(r"[0-9a-f]{40}\Z")

def assert_tag_identity(tag, expected_sha, output):
    if not SHA.fullmatch(expected_sha):
        raise ValueError("invalid expected commit SHA")
    refs = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2 or not SHA.fullmatch(parts[0]):
            raise ValueError("invalid remote tag response")
        if parts[1] in refs:
            raise ValueError("duplicate remote tag reference")
        refs[parts[1]] = parts[0]
    direct = "refs/tags/" + tag
    peeled = direct + "^{}"
    if direct not in refs or set(refs) - {direct, peeled}:
        raise ValueError("missing or unexpected remote tag reference")
    resolved = refs.get(peeled, refs[direct])
    if resolved != expected_sha:
        raise ValueError("remote release tag points to a different commit")
    return resolved

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--remote", default="origin")
    args = parser.parse_args()
    from release_tag_policy import classify
    if classify(args.tag) is None:
        parser.error("invalid release tag")
    try:
        response = subprocess.run(
            ["git", "ls-remote", "--tags", args.remote,
             "refs/tags/" + args.tag, "refs/tags/" + args.tag + "^{}"],
            check=True, capture_output=True, text=True)
        assert_tag_identity(args.tag, args.sha, response.stdout)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.error(str(exc))
    print("Immutable remote tag identity verified: " + args.tag + " -> " + args.sha)

if __name__ == "__main__":
    main()
