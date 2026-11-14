#!/usr/bin/env python3
"""Resolve the exact Cosign signer tag for an immutable release source commit.

GA images are digest-reused from a qualified RC. Their signature identity is
therefore the RC tag, not the later GA alias. Resolve by immutable Git refs and
require exactly one same-version RC tag to point at the GA source commit.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

SHA = re.compile(r"^[a-f0-9]{40}$")
NUM = r"(?:0|[1-9][0-9]*)"
STABLE = re.compile(rf"^v(?P<version>{NUM}\.{NUM}\.{NUM})$")
RC = re.compile(rf"^v(?P<version>{NUM}\.{NUM}\.{NUM})-rc\.(?P<number>[1-9][0-9]*)$")


class SignerResolutionError(ValueError):
    pass


def resolve_signer(release_tag: str, source_sha: str, candidate_tags: list[str],
                   resolve_tag: Callable[[str], str], preferred_tag: str | None = None) -> str:
    if not SHA.fullmatch(source_sha):
        raise SignerResolutionError("invalid release source SHA")
    rc_match = RC.fullmatch(release_tag)
    stable_match = STABLE.fullmatch(release_tag)
    if preferred_tag is not None:
        preferred_rc = RC.fullmatch(preferred_tag)
        if rc_match and preferred_tag != release_tag:
            raise SignerResolutionError("RC release must declare its own exact signer tag")
        if stable_match and preferred_tag != release_tag and (
                preferred_rc is None or preferred_rc.group("version") != stable_match.group("version")):
            raise SignerResolutionError("declared GA signer is outside the exact release version family")
        if not rc_match and not stable_match:
            raise SignerResolutionError("release tag must be stable semver or numbered RC")
        if resolve_tag(preferred_tag) != source_sha:
            raise SignerResolutionError("declared signer tag does not resolve to the release source SHA")
        return preferred_tag
    if rc_match:
        if resolve_tag(release_tag) != source_sha:
            raise SignerResolutionError("RC tag does not resolve to the selected release source")
        return release_tag
    if not stable_match:
        raise SignerResolutionError("release tag must be stable semver or numbered RC")
    expected_prefix = release_tag + "-rc."
    candidates = sorted({tag for tag in candidate_tags
                         if isinstance(tag, str) and tag.startswith(expected_prefix)
                         and RC.fullmatch(tag)})
    matching = [tag for tag in candidates if resolve_tag(tag) == source_sha]
    if len(matching) != 1:
        raise SignerResolutionError(
            "expected exactly one same-version RC tag at the GA source SHA; found "
            + str(len(matching)))
    return matching[0]


def gh_json(args: list[str]) -> object:
    try:
        result = subprocess.run(["gh", "api", *args], check=True, text=True,
                                capture_output=True, timeout=60)
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise SignerResolutionError("GitHub API lookup failed: " + type(exc).__name__) from exc


def dereference_tag(repository: str, tag: str) -> str:
    obj = gh_json([f"repos/{repository}/git/ref/tags/{tag}"])
    if not isinstance(obj, dict) or not isinstance(obj.get("object"), dict):
        raise SignerResolutionError("tag ref response is malformed")
    kind, sha = obj["object"].get("type"), obj["object"].get("sha")
    for _ in range(5):
        if kind == "commit":
            if not isinstance(sha, str) or not SHA.fullmatch(sha):
                raise SignerResolutionError("tag does not resolve to a commit SHA")
            return sha
        if kind != "tag" or not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise SignerResolutionError("tag object type is unsupported")
        obj = gh_json([f"repos/{repository}/git/tags/{sha}"])
        if not isinstance(obj, dict) or not isinstance(obj.get("object"), dict):
            raise SignerResolutionError("annotated tag response is malformed")
        kind, sha = obj["object"].get("type"), obj["object"].get("sha")
    raise SignerResolutionError("annotated tag nesting exceeds safety limit")


def matching_rc_tags(repository: str, release_tag: str) -> list[str]:
    pages = gh_json(["--paginate", "--slurp",
                     f"repos/{repository}/git/matching-refs/tags/{release_tag}-rc."])
    if isinstance(pages, list) and pages and all(isinstance(page, list) for page in pages):
        refs = [ref for page in pages for ref in page]
    elif isinstance(pages, list):
        refs = pages
    else:
        raise SignerResolutionError("GitHub matching-refs response is malformed")
    tags = []
    for ref in refs:
        name = ref.get("ref") if isinstance(ref, dict) else None
        if isinstance(name, str) and name.startswith("refs/tags/"):
            tags.append(name.removeprefix("refs/tags/"))
    return tags



def validate_qualified_run(run: object, signer_tag: str, source_sha: str,
                           expected_run_id: int | None = None) -> int:
    if not isinstance(run, dict):
        raise SignerResolutionError("qualified RC workflow run response is malformed")
    run_id = run.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise SignerResolutionError("qualified RC workflow run ID is invalid")
    if expected_run_id is not None and run_id != expected_run_id:
        raise SignerResolutionError("release metadata run ID does not match the GitHub Actions record")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise SignerResolutionError("RC workflow run is not completed successfully")
    if run.get("event") != "push" or run.get("head_branch") != signer_tag:
        raise SignerResolutionError("RC workflow run is not the exact tag-push run")
    if run.get("head_sha") != source_sha:
        raise SignerResolutionError("RC workflow run source SHA differs from the release")
    path = run.get("path")
    if not isinstance(path, str) or path.split("@", 1)[0] != ".github/workflows/publish.yml":
        raise SignerResolutionError("RC workflow run did not execute the canonical publish workflow")
    return run_id


def resolve_qualified_run(repository: str, signer_tag: str, source_sha: str,
                          preferred_run_id: int | None = None) -> int:
    if preferred_run_id is not None:
        run = gh_json([f"repos/{repository}/actions/runs/{preferred_run_id}"])
        return validate_qualified_run(run, signer_tag, source_sha, preferred_run_id)
    pages = gh_json(["--paginate", "--slurp",
                     f"repos/{repository}/actions/workflows/publish.yml/runs"
                     f"?head_sha={source_sha}&branch={signer_tag}&event=push&per_page=100"])
    if isinstance(pages, list) and pages and all(isinstance(page, list) for page in pages):
        runs = [run for page in pages for run in page]
    elif isinstance(pages, list):
        runs = pages
    else:
        raise SignerResolutionError("GitHub Actions run search response is malformed")
    valid = []
    for run in runs:
        try:
            valid.append(validate_qualified_run(run, signer_tag, source_sha))
        except SignerResolutionError:
            continue
    ids = sorted(set(valid))
    if len(ids) != 1:
        raise SignerResolutionError(
            "expected exactly one successful canonical publish run for the signer tag and source SHA; found "
            + str(len(ids)))
    return ids[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--preferred-tag")
    parser.add_argument("--preferred-run-id", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            raise SignerResolutionError("invalid repository name")
        rc_match = RC.fullmatch(args.release_tag)
        if args.preferred_tag:
            candidates = [args.preferred_tag]
        elif rc_match:
            candidates = [args.release_tag]
        else:
            candidates = matching_rc_tags(args.repository, args.release_tag)
        signer = resolve_signer(args.release_tag, args.source_sha, candidates,
                                lambda tag: dereference_tag(args.repository, tag),
                                preferred_tag=args.preferred_tag)
        signer_run_id = resolve_qualified_run(args.repository, signer, args.source_sha,
                                              args.preferred_run_id)
        result = {"schema": "baobab.dev10.release-signer.v1",
                  "release_tag": args.release_tag, "signer_tag": signer,
                  "signer_run_id": signer_run_id, "source_sha": args.source_sha}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (SignerResolutionError, OSError, ValueError) as exc:
        print("::error::Release signer resolution DENIED:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
