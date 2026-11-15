#!/usr/bin/env python3
"""DEV-10 manual-tag eligibility: new RC families need a changed baseline."""
import argparse
import json
import re
import subprocess
from pathlib import Path
try:
    from release_tag_policy import classify
except ModuleNotFoundError as exc:
    if exc.name != "release_tag_policy":
        raise
    import importlib.util
    policy = Path(__file__).resolve().with_name("release_tag_policy.py")
    spec = importlib.util.spec_from_file_location("dev10_release_tag_policy", policy)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    classify = module.classify

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

def verify_current_approval(pr, reviews, author):
    """Require a live independent approval on the exact merged PR head."""
    if not isinstance(reviews, list) or len(reviews) >= 100:
        raise ReleaseEligibilityError("incomplete or invalid review history")
    head = (pr.get("head") or {}).get("sha")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ReleaseEligibilityError("merged PR head is unavailable")
    latest = {}
    for review in reviews:
        if not isinstance(review, dict):
            raise ReleaseEligibilityError("malformed review evidence")
        actor = (review.get("user") or {}).get("login")
        state = review.get("state")
        if not actor or actor.casefold() == str(author).casefold() or state == "PENDING":
            continue
        if state not in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"):
            raise ReleaseEligibilityError("unrecognized review state")
        if not review.get("submitted_at"):
            raise ReleaseEligibilityError("submitted review timestamp missing")
        latest[actor.casefold()] = review
    if not any(review["state"] == "APPROVED" and review.get("commit_id") == head
               for review in latest.values()):
        raise ReleaseEligibilityError("no current independent approval on merged head")


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
    # Verify a merged, independently approved PR. A PR number alone is not
    # evidence of review; reject missing/unavailable API evidence.
    import os
    if not os.environ.get("GH_TOKEN"):
        raise ReleaseEligibilityError("maintenance exception requires GitHub review evidence")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ReleaseEligibilityError("invalid GitHub repository identity")
    try:
        pr = json.loads(run("gh", "api", f"repos/{repo}/pulls/{decision['review_pr']}"))
        reviews = json.loads(run("gh", "api", f"repos/{repo}/pulls/{decision['review_pr']}/reviews?per_page=100"))
    except (ValueError, ReleaseEligibilityError) as exc:
        raise ReleaseEligibilityError("cannot verify independent maintenance approval") from exc
    author = (pr.get("user") or {}).get("login")
    merged_sha = pr.get("merge_commit_sha")
    if not pr.get("merged") or not isinstance(merged_sha, str):
        raise ReleaseEligibilityError("maintenance exception PR is not merged")
    run("git", "merge-base", "--is-ancestor", merged_sha, "HEAD")
    verify_current_approval(pr, reviews, author)
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
