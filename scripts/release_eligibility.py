#!/usr/bin/env python3
"""DEV-10 manual-tag eligibility: new RC families need a changed baseline."""
import argparse
import json
import re
import subprocess
from pathlib import Path
from release_tag_policy import classify

GA = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
EXCEPTION = Path("config/dev10-maintenance-release.json")

class ReleaseEligibilityError(ValueError):
    pass

def run(*args, input=None):
    p = subprocess.run(args, input=input, text=True, capture_output=True)
    if p.returncode:
        raise ReleaseEligibilityError(f"{args[0]} failed: {p.stderr.strip()}")
    return p.stdout.strip()

def semver(tag):
    m = GA.fullmatch(tag)
    return tuple(map(int, m.groups())) if m else None

def previous_ga(family, tags):
    older = [t for t in tags if semver(t) is not None and semver(t) < semver(family)]
    if not older:
        raise ReleaseEligibilityError("no earlier GA baseline: explicit bootstrap review required")
    return max(older, key=semver)

def decide(tag, tags, manifest_changed, lock_changed, maintenance=False):
    kind = classify(tag)
    if kind is None:
        raise ReleaseEligibilityError("invalid release tag")
    if kind == "ga":
        return "qualified-RC-digest-reuse"
    family = tag.split("-rc.", 1)[0]
    if family in tags:
        raise ReleaseEligibilityError("release family already finalized")
    if manifest_changed:
        if not lock_changed:
            raise ReleaseEligibilityError("changed manifest requires updated versions.lock")
        return "changed-toolchain"
    if maintenance:
        return "reviewed-maintenance"
    raise ReleaseEligibilityError("unchanged toolchain baseline since preceding GA")

def manifest(ref):
    raw = run("git", "show", f"{ref}:config/versions.yaml")
    return json.loads(run("yq", "eval", "-o=json", ".", "-", input=raw))

def maintenance(family, previous):
    if not EXCEPTION.is_file():
        return False
    try:
        decision = json.loads(EXCEPTION.read_text())
    except (OSError, ValueError) as exc:
        raise ReleaseEligibilityError("invalid maintenance release declaration") from exc
    if not isinstance(decision, dict) or set(decision) != {"release_family", "previous_ga", "reason", "review_pr"}:
        raise ReleaseEligibilityError("invalid maintenance declaration schema")
    if decision["release_family"] != family or decision["previous_ga"] != previous:
        return False
    if not isinstance(decision["reason"], str) or len(decision["reason"].strip()) < 30:
        raise ReleaseEligibilityError("maintenance release requires an explicit rationale")
    if type(decision["review_pr"]) is not int or decision["review_pr"] < 1:
        raise ReleaseEligibilityError("maintenance release requires an independently reviewed PR")
    changed = run("git", "diff", "--name-only", previous, "HEAD").splitlines()
    if not any(p == "Dockerfile" or p.startswith(("scripts/security/", "config/security/"))
               or p in ("scripts/dev10_kernel_risk_gate.py", ".github/workflows/security.yml")
               for p in changed):
        raise ReleaseEligibilityError("maintenance release has no qualifying security/packaging change")
    # PR review itself remains protected by the repository's merge policy.
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    if classify(args.tag) is None:
        parser.error("invalid tag")
    if classify(args.tag) == "ga":
        print("GA must pass existing same-source qualified RC digest-reuse gate")
        return
    family = args.tag.split("-rc.", 1)[0]
    tags = run("git", "tag", "--list", "v*").splitlines()
    try:
        previous = previous_ga(family, tags)
        ga_tags = [t for t in tags if semver(t) is not None]
        if family in ga_tags or semver(family) <= max(map(semver, ga_tags)):
            raise ReleaseEligibilityError("RC family must be newer than the latest GA")
        changed = manifest(previous) != manifest("HEAD")
        locked = run("git", "show", f"{previous}:config/versions.lock") != run("git", "show", "HEAD:config/versions.lock")
        outcome = decide(args.tag, tags, changed, locked, maintenance(family, previous) if not changed else False)
        print(json.dumps({"tag": args.tag, "previous_ga": previous, "eligibility": outcome}))
    except ReleaseEligibilityError as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
