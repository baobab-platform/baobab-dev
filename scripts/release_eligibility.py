#!/usr/bin/env python3
"""DEV-10 manual-tag eligibility: new RC families need a changed baseline."""
import argparse
import json
import re
import subprocess
import urllib.parse
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

def positive_github_user_id(value, label):
    if type(value) is not int or value <= 0:
        raise ReleaseEligibilityError(f"{label} has no positive numeric GitHub user ID")
    return value


def review_timestamp(value):
    if not isinstance(value, str) or not value:
        raise ReleaseEligibilityError("submitted review timestamp missing")
    try:
        from datetime import datetime, timezone
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseEligibilityError("submitted review timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReleaseEligibilityError("submitted review timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def resolve_trusted_approvers(logins):
    """Resolve the configured allowlist to unique, typed immutable GitHub User IDs."""
    if not isinstance(logins, list) or not logins:
        raise ReleaseEligibilityError("trusted maintenance approver allow-list is missing")
    identities = {}
    seen_logins = set()
    for login in logins:
        if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login):
            raise ReleaseEligibilityError("trusted maintenance approver login has invalid syntax")
        key = login.casefold()
        if key in seen_logins:
            raise ReleaseEligibilityError("trusted maintenance approver allow-list contains duplicate logins")
        seen_logins.add(key)
        try:
            identity = json.loads(run("gh", "api", f"users/{urllib.parse.quote(login, safe='')}"))
        except (ValueError, ReleaseEligibilityError) as exc:
            raise ReleaseEligibilityError("cannot resolve trusted maintenance reviewer identity") from exc
        if (not isinstance(identity, dict) or identity.get("type") != "User"
                or not isinstance(identity.get("login"), str)
                or identity["login"].casefold() != key):
            raise ReleaseEligibilityError("trusted maintenance reviewer is not a matching typed GitHub User")
        user_id = positive_github_user_id(identity.get("id"), "trusted maintenance reviewer")
        if user_id in identities:
            raise ReleaseEligibilityError("trusted maintenance reviewers resolve to duplicate numeric identities")
        identities[user_id] = identity["login"]
    return identities


def flatten_review_pages(pages):
    """Flatten the page arrays returned by gh api --paginate --slurp."""
    if not isinstance(pages, list) or not pages or any(not isinstance(page, list) for page in pages):
        raise ReleaseEligibilityError("maintenance review pagination returned incomplete history")
    reviews = []
    for page in pages:
        reviews.extend(page)
    if len(reviews) > 10000:
        raise ReleaseEligibilityError("maintenance review history exceeded the safety limit")
    return reviews


def verify_current_approval(pr, reviews, author_id, trusted_approver_ids=None):
    """Return exact-head approvals after resolving each typed reviewer's latest state by ID."""
    if not isinstance(reviews, list) or len(reviews) > 10000:
        raise ReleaseEligibilityError("incomplete or invalid review history")
    head = (pr.get("head") or {}).get("sha")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ReleaseEligibilityError("merged PR head is unavailable")
    author_id = positive_github_user_id(author_id, "maintenance PR author")
    trusted = None
    if trusted_approver_ids is not None:
        if (not isinstance(trusted_approver_ids, set) or not trusted_approver_ids
                or any(type(item) is not int or item <= 0 for item in trusted_approver_ids)):
            raise ReleaseEligibilityError("trusted maintenance numeric reviewer allow-list is invalid")
        trusted = trusted_approver_ids

    latest = {}
    seen_review_ids = set()
    for review in reviews:
        if not isinstance(review, dict):
            raise ReleaseEligibilityError("malformed review evidence")
        state = review.get("state")
        if state == "PENDING":
            continue
        reviewer = review.get("user")
        if not isinstance(reviewer, dict):
            raise ReleaseEligibilityError("review contains no reviewer account identity")
        reviewer_type = reviewer.get("type")
        if reviewer_type == "Bot":
            # Bot records are not effective trusted reviewer state.
            continue
        if reviewer_type != "User":
            raise ReleaseEligibilityError("review contains a non-User or untyped reviewer identity")
        reviewer_id = positive_github_user_id(reviewer.get("id"), "reviewer")
        login = reviewer.get("login")
        if not isinstance(login, str) or not login.strip():
            raise ReleaseEligibilityError("typed review actor has no GitHub login")
        review_id = review.get("id")
        if type(review_id) is not int or review_id <= 0:
            raise ReleaseEligibilityError("numeric GitHub review ID is missing")
        if review_id in seen_review_ids:
            raise ReleaseEligibilityError("duplicate GitHub review ID in maintenance history")
        seen_review_ids.add(review_id)
        if state not in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"):
            raise ReleaseEligibilityError("unrecognized review state")
        submitted_at = review_timestamp(review.get("submitted_at"))
        candidate = (submitted_at, review_id, state, review)
        previous = latest.get(reviewer_id)
        if previous is None or candidate[:2] > previous[:2]:
            latest[reviewer_id] = candidate

    approvals = [
        review for reviewer_id, (_, _, state, review) in latest.items()
        if reviewer_id != author_id and state == "APPROVED"
        and review.get("commit_id") == head
        and (trusted is None or reviewer_id in trusted)
    ]
    if not approvals:
        raise ReleaseEligibilityError("no current trusted independent typed-User approval on merged head")
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
    except (ValueError, ReleaseEligibilityError) as exc:
        raise ReleaseEligibilityError("cannot verify maintenance exception PR metadata") from exc
    author = pr.get("user")
    if not isinstance(author, dict) or author.get("type") != "User":
        raise ReleaseEligibilityError("maintenance PR author is not a typed GitHub User")
    author_id = positive_github_user_id(author.get("id"), "maintenance PR author")
    merged_sha = pr.get("merge_commit_sha")
    if (not pr.get("merged") or not isinstance(merged_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40}", merged_sha)
            or pr.get("state") != "closed" or (pr.get("base") or {}).get("ref") != "main"
            or ((pr.get("base") or {}).get("repo") or {}).get("full_name") != repo):
        raise ReleaseEligibilityError("maintenance exception PR must be merged into canonical main")
    run("git", "merge-base", "--is-ancestor", merged_sha, "HEAD")
    trusted_identities = resolve_trusted_approvers(trusted_logins)
    review_pages = json.loads(run(
        "gh", "api", "--paginate", "--slurp",
        f"repos/{repo}/pulls/{decision['review_pr']}/reviews?per_page=100",
    ))
    reviews = flatten_review_pages(review_pages)
    approvals = verify_current_approval(
        pr, reviews, author_id, set(trusted_identities),
    )
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
    trusted_ids = set(trusted_identities)
    for approval in approvals:
        reviewer = approval.get("user") or {}
        reviewer_id = positive_github_user_id(reviewer.get("id"), "approved reviewer")
        if reviewer_id not in trusted_ids:
            continue
        try:
            require_independent(reviewer_id, trusted_ids, author_id, contributors)
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
