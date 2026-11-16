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

def verify_current_approval(pr, reviews, author, trusted_approvers=None):
    """Return current-head approvals after resolving each reviewer's latest state."""
    if not isinstance(reviews, list) or len(reviews) >= 100:
        raise ReleaseEligibilityError("incomplete or invalid review history")
    head = (pr.get("head") or {}).get("sha")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ReleaseEligibilityError("merged PR head is unavailable")
    trusted = None
    if trusted_approvers is not None:
        trusted = {str(login).casefold() for login in trusted_approvers if str(login).strip()}
        if not trusted:
            raise ReleaseEligibilityError("no trusted maintenance approvers are configured")
    latest = {}
    for review in reviews:
        if not isinstance(review, dict):
            raise ReleaseEligibilityError("malformed review evidence")
        review_id = review.get("id")
        if type(review_id) is not int or review_id <= 0:
            raise ReleaseEligibilityError("numeric GitHub review ID is missing")
        actor = (review.get("user") or {}).get("login")
        state = review.get("state")
        if state == "PENDING":
            continue
        if not actor:
            raise ReleaseEligibilityError("review actor is missing")
        if state not in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"):
            raise ReleaseEligibilityError("unrecognized review state")
        submitted_at = review.get("submitted_at")
        if not isinstance(submitted_at, str) or not submitted_at:
            raise ReleaseEligibilityError("submitted review timestamp missing")
        if actor.casefold() == str(author).casefold():
            continue
        key = actor.casefold()
        previous = latest.get(key)
        if previous is None or (submitted_at, review_id) > (
                previous["submitted_at"], previous["id"]):
            latest[key] = review
    approvals = [
        review for review in latest.values()
        if review["state"] == "APPROVED" and review.get("commit_id") == head
        and (trusted is None or review["user"]["login"].casefold() in trusted)
    ]
    if not approvals:
        raise ReleaseEligibilityError("no current trusted independent approval on merged head")
    return approvals

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

    import os
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise ReleaseEligibilityError("maintenance exception requires GitHub review evidence")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if repo != "baobab-platform/baobab-dev":
        raise ReleaseEligibilityError("maintenance custody verifier requires the canonical repository")
    trusted_logins = [
        value.strip() for value in os.environ.get("DEV10_SECURITY_APPROVER_LOGINS", "").split(",")
        if value.strip()
    ]
    if not trusted_logins or len({value.casefold() for value in trusted_logins}) != len(trusted_logins):
        raise ReleaseEligibilityError("trusted maintenance approver allow-list is missing or duplicated")
    try:
        pr = json.loads(run("gh", "api", f"repos/{repo}/pulls/{decision['review_pr']}"))
        reviews = json.loads(run("gh", "api", f"repos/{repo}/pulls/{decision['review_pr']}/reviews?per_page=100"))
    except (ValueError, ReleaseEligibilityError) as exc:
        raise ReleaseEligibilityError("cannot verify independent maintenance approval") from exc
    author = (pr.get("user") or {}).get("login")
    merged_sha = pr.get("merge_commit_sha")
    if (not pr.get("merged") or not isinstance(merged_sha, str)
            or pr.get("state") != "closed" or (pr.get("base") or {}).get("ref") != "main"):
        raise ReleaseEligibilityError("maintenance exception PR must be merged into main")
    run("git", "merge-base", "--is-ancestor", merged_sha, "HEAD")
    approvals = verify_current_approval(pr, reviews, author, trusted_logins)
    try:
        from custody_independence import collect_pr, require_independent, uid
    except ModuleNotFoundError as exc:
        if exc.name != "custody_independence":
            raise
        import importlib.util
        module_path = Path(__file__).resolve().with_name("custody_independence.py")
        spec = importlib.util.spec_from_file_location("dev10_custody_independence", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        collect_pr, require_independent, uid = module.collect_pr, module.require_independent, module.uid
    head = (pr.get("head") or {}).get("sha")
    author_id, contributors = collect_pr(token, decision["review_pr"], head)
    api_author_id = uid({"databaseId": (pr.get("user") or {}).get("id")})
    if author_id != api_author_id:
        raise ReleaseEligibilityError("numeric PR author identity differs between GitHub APIs")
    trusted_ids = {}
    for login in trusted_logins:
        try:
            identity = json.loads(run("gh", "api", f"users/{login}"))
        except (ValueError, ReleaseEligibilityError) as exc:
            raise ReleaseEligibilityError("cannot resolve trusted maintenance reviewer identity") from exc
        if not isinstance(identity, dict) or identity.get("login", "").casefold() != login.casefold():
            raise ReleaseEligibilityError("trusted maintenance reviewer login resolution mismatch")
        reviewer_id = uid({"databaseId": identity.get("id")})
        if reviewer_id in trusted_ids.values():
            raise ReleaseEligibilityError("trusted maintenance reviewers resolve to duplicate numeric identities")
        trusted_ids[login.casefold()] = reviewer_id
    for approval in approvals:
        reviewer = approval.get("user") or {}
        login = reviewer.get("login", "").casefold()
        reviewer_id = uid({"databaseId": reviewer.get("id")})
        if trusted_ids.get(login) != reviewer_id:
            continue
        try:
            require_independent(reviewer_id, set(trusted_ids.values()), author_id, contributors)
        except ValueError:
            continue
        return True
    raise ReleaseEligibilityError("no trusted current-head maintenance approver is independent of PR contributors")

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
