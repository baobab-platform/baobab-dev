#!/usr/bin/env python3
"""Validate manifest-only PR inputs and append the two generated lock files."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

from custody_independence import REPOSITORY
from github_api_transport import API_ROOT, API_VERSION, GitHubAPIError, request_json, rest_request

MANIFEST = "config/versions.yaml"
GENERATED = ("config/versions.lock", ".python-version")
ALLOWED_CHANGES = frozenset((MANIFEST, *GENERATED))
SHA = re.compile(r"[0-9a-f]{40}")
ASSIGNMENT = re.compile(r"export ([A-Z][A-Z0-9_]*)=([A-Za-z0-9._:/+~-]+)")
MAX_FILE_BYTES = 64 * 1024
MUTATION = """
mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}
"""


class ResolutionError(ValueError):
    pass


def event_refs(event, *, trusted):
    pr = event["pull_request"]
    base, head = pr["base"], pr["head"]
    if (pr.get("state") != "open" or base["ref"] != "main"
            or base["repo"]["full_name"] != REPOSITORY
            or not all(isinstance(ref["sha"], str) and SHA.fullmatch(ref["sha"]) for ref in (base, head))):
        raise ResolutionError("open PR against canonical main with exact base/head SHAs required")
    branch = head["ref"]
    same_repo = head["repo"]["full_name"] == REPOSITORY
    if not isinstance(branch, str) or not branch or branch == "main" or (trusted and not same_repo):
        raise ResolutionError("same-repository non-main PR branch required for writeback")
    return pr, base["sha"], head["sha"]


def inspect_change(event, *, trusted):
    """Read immutable Git objects. Candidate paths are data, never checked out."""
    _, base, head = event_refs(event, trusted=trusted)
    changed = subprocess.check_output(
        ["git", "diff", "--no-renames", "--name-only", "-z", f"{base}...{head}", "--"],
    )
    files = set(changed.decode("utf-8").rstrip("\0").split("\0"))
    return MANIFEST in files and files <= ALLOWED_CHANGES


def read_blob(ref, path, *, optional=False):
    obj = f"{ref}:{path}"
    entry = subprocess.check_output(["git", "ls-tree", ref, "--", path], text=True).split()
    if not entry and optional:
        return None
    if len(entry) != 4 or entry[0] not in ("100644", "100755") or entry[1] != "blob":
        raise ResolutionError(f"immutable input is not a regular Git blob: {path}")
    size = int(subprocess.check_output(["git", "cat-file", "-s", obj], text=True))
    if not 0 < size <= MAX_FILE_BYTES:
        raise ResolutionError(f"immutable input exceeds the supported size: {path}")
    return subprocess.check_output(["git", "cat-file", "blob", obj])


def stage(event, output, *, trusted):
    _, base, head = event_refs(event, trusted=trusted)
    if not inspect_change(event, trusted=trusted):
        raise ResolutionError("expected a manifest-only PR with optional generated files")
    output.write_bytes(read_blob(head, MANIFEST))
    for path in GENERATED:
        Path(path).write_bytes(read_blob(base, path))


def validate_resolution(files, contract):
    if set(files) != set(GENERATED) or any(not 0 < len(data) <= MAX_FILE_BYTES for data in files.values()):
        raise ResolutionError("resolver must supply exactly the two bounded generated files")
    assignments = {}
    for line in files[GENERATED[0]].decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(line)
        if not match or match[1] in assignments or match[2] in ("latest", "null", "system"):
            raise ResolutionError("generated lock contains an invalid or duplicate assignment")
        assignments[match[1]] = match[2]
    expected = {
        match[1] for line in contract.decode("ascii").splitlines()
        if (match := ASSIGNMENT.fullmatch(line))
    }
    if set(assignments) != expected:
        raise ResolutionError("generated lock is missing a required key or contains an unexpected key")
    for key, value in assignments.items():
        if re.search(r"_APT_VERSION(?:_AMD64|_ARM64)?$", key) and not re.fullmatch(
            r"[0-9][0-9A-Za-z.+:~-]*", value
        ):
            raise ResolutionError(f"generated lock contains a malformed APT version for {key}")
        if key.endswith("_SOURCE_COMMIT") and not SHA.fullmatch(value):
            raise ResolutionError(f"generated lock contains a malformed source commit for {key}")
        if "_SHA256" in key and not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ResolutionError(f"generated lock contains a malformed SHA-256 for {key}")
        if key.endswith("_SHA512") and not re.fullmatch(r"[a-f0-9]{128}", value):
            raise ResolutionError(f"generated lock contains a malformed SHA-512 for {key}")
    python = assignments.get("PYTHON_VERSION", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", python):
        raise ResolutionError("lock requires an exact Python version")
    if (python.rsplit(".", 1)[0] != assignments.get("PYTHON_MINOR")
            or files[".python-version"] != (assignments["PYTHON_MINOR"] + "\n").encode("ascii")):
        raise ResolutionError("generated Python pin disagrees with the locked Python version")


def changes_for_head(event, files, *, trusted):
    _, base, head = event_refs(event, trusted=trusted)
    validate_resolution(files, read_blob(base, GENERATED[0]))
    return {path: data for path, data in files.items()
            if data != read_blob(head, path, optional=True)}


def resolution_receipt(event, files):
    pr, base, head = event_refs(event, trusted=False)
    return {
        "schema": "dev10.lock-resolution.v1",
        "pull_request": pr["number"],
        "base_sha": base,
        "head_sha": head,
        "manifest_sha256": hashlib.sha256(read_blob(head, MANIFEST)).hexdigest(),
        "generated_sha256": {path: hashlib.sha256(data).hexdigest() for path, data in files.items()},
    }


def writeback(event, files, read_token, write_token):
    pr, _, head = event_refs(event, trusted=True)
    if not inspect_change(event, trusted=True):
        raise ResolutionError("only a manifest-only PR can receive an automated lockfile commit")
    changed = changes_for_head(event, files, trusted=True)
    if not changed:
        return None
    number = pr["number"]
    if type(number) is not int or number <= 0:
        raise ResolutionError("PR number must be a positive integer")
    _, live = rest_request(read_token, "GET", f"/repos/{REPOSITORY}/pulls/{number}")
    if not isinstance(live, dict):
        raise ResolutionError("Live PR metadata is unavailable")
    _, live_base, live_head = event_refs({"pull_request": live}, trusted=True)
    if ((live_base, live_head) != (pr["base"]["sha"], head)
            or live["head"]["ref"] != pr["head"]["ref"] or live.get("number") != number):
        raise ResolutionError("PR changed during resolution. The current head needs a fresh run.")
    variables = {"input": {
        "branch": {"repositoryNameWithOwner": REPOSITORY, "branchName": pr["head"]["ref"]},
        "expectedHeadOid": head,
        "message": {"headline": "chore(dev10): resolve version manifest"},
        "fileChanges": {"additions": [
            {"path": path, "contents": base64.b64encode(data).decode("ascii")}
            for path, data in sorted(changed.items())
        ]},
    }}
    request = urllib.request.Request(
        f"{API_ROOT}/graphql", method="POST",
        data=json.dumps({"query": MUTATION, "variables": variables}).encode(),
        headers={"Authorization": f"Bearer {write_token}", "Content-Type": "application/json",
                 "X-GitHub-Api-Version": API_VERSION, "User-Agent": "baobab-dev-dev10"},
    )
    _, response = request_json(request, context="GitHub lockfile writeback")
    try:
        if "errors" in response:
            raise ResolutionError("GitHub refused the exact-head lockfile commit")
        new_head = response["data"]["createCommitOnBranch"]["commit"]["oid"]
    except (KeyError, TypeError):
        raise ResolutionError("GitHub returned no lockfile commit") from None
    if not isinstance(new_head, str) or not SHA.fullmatch(new_head) or new_head == head:
        raise ResolutionError("GitHub returned an invalid lockfile commit ID")
    return new_head


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "stage", "check", "write"))
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--trusted", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--resolved", type=Path)
    args = parser.parse_args()
    try:
        event = json.loads(args.event.read_bytes())
        if args.command == "plan":
            print("true" if inspect_change(event, trusted=args.trusted) else "false")
        elif args.command == "stage":
            stage(event, args.manifest, trusted=args.trusted)
        else:
            files = {path: (args.resolved / path).read_bytes() for path in GENERATED}
            receipt_file = args.resolved / "resolution-receipt.json"
            receipt = resolution_receipt(event, files)
            if args.command == "check":
                changed = changes_for_head(event, files, trusted=args.trusted)
                receipt_file.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
                print("true" if changed else "false")
            else:
                if json.loads(receipt_file.read_bytes()) != receipt:
                    raise ResolutionError("resolved files do not match this run's exact-head receipt")
                commit = writeback(event, files, os.environ["GITHUB_TOKEN"], os.environ["LOCKFILE_APP_TOKEN"])
                print(commit or "No lockfile change")
    except (GitHubAPIError, ResolutionError, OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError) as exc:
        if isinstance(exc, (GitHubAPIError, ResolutionError)):
            parser.error(str(exc))
        parser.error("could not read or qualify the immutable manifest and lockfile inputs")


if __name__ == "__main__":
    main()
