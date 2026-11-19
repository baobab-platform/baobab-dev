#!/usr/bin/env python3
"""Verify reviewed DEV-10 release source and eligibility of its tag."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from custody_independence import (
    REPOSITORY, CustodyError, collect_pr, is_positive_id, latest_user_reviews,
    require_independent, rest_user_id, review_timestamp,
)
from dev10_lockfile_pr import GENERATED, MANIFEST
from provision_protected_risk_policy import (
    ProvisioningError, api_request, contents_bytes, paginated, resolve_trusted_reviewers,
)
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

def verify_current_approval(pr, reviews, author_id, trusted_approver_ids=None, *, merged_at=None):
    """Return exact-head approvals after resolving each typed reviewer's latest state by ID."""
    head_record = pr.get("head")
    head = head_record.get("sha") if isinstance(head_record, dict) else None
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ReleaseEligibilityError("merged PR head is unavailable")
    if not is_positive_id(author_id):
        raise ReleaseEligibilityError("maintenance PR author has no positive numeric GitHub user ID")
    trusted = None
    if trusted_approver_ids is not None:
        if (not isinstance(trusted_approver_ids, set) or not trusted_approver_ids
                or any(type(item) is not int or item <= 0 for item in trusted_approver_ids)):
            raise ReleaseEligibilityError("trusted maintenance numeric reviewer allow-list is invalid")
        trusted = trusted_approver_ids

    try:
        latest = latest_user_reviews(reviews)
        merge_time = review_timestamp(merged_at) if merged_at is not None else None
    except CustodyError as exc:
        raise ReleaseEligibilityError(str(exc)) from None
    approvals = [
        review for reviewer_id, (submitted, _, review) in latest.items()
        if reviewer_id != author_id and review["state"] == "APPROVED"
        and review.get("commit_id") == head
        and (trusted is None or reviewer_id in trusted)
        and (merge_time is None or submitted <= merge_time)
    ]
    if not approvals:
        raise ReleaseEligibilityError("no current trusted independent typed-User approval on merged head")
    return approvals


def canonical_main_pr(pr):
    base = pr.get("base") if isinstance(pr, dict) else None
    repository = base.get("repo") if isinstance(base, dict) else None
    return (isinstance(repository, dict) and repository.get("full_name") == REPOSITORY
            and base.get("ref") == "main")


def reviewed_source(token, sha, trusted_ids):
    """Bind the release commit and its toolchain inputs to the exact reviewed PR."""
    if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ReleaseEligibilityError("invalid immutable release source SHA")
    root = f"/repos/{REPOSITORY}"
    try:
        associated = paginated(token, f"{root}/commits/{sha}/pulls")
        matches = [
            pr for pr in associated
            if canonical_main_pr(pr) and pr.get("merge_commit_sha") == sha
            and pr.get("state") == "closed" and pr.get("merged_at")
        ]
        if len(matches) != 1 or not is_positive_id(matches[0].get("number")):
            raise ReleaseEligibilityError("release commit must be the exact merge of one canonical main PR")
        pr_number = matches[0]["number"]
        endpoint = f"{root}/pulls/{pr_number}"
        _, pr = api_request(token, "GET", endpoint)
        if (not canonical_main_pr(pr) or not is_positive_id(pr.get("number"))
                or pr["number"] != pr_number or pr.get("merged") is not True
                or any(pr.get(field) != matches[0].get(field) for field in
                       ("merge_commit_sha", "merged_at", "state"))):
            raise ReleaseEligibilityError("release source PR metadata disagrees with the merged commit")
        author = rest_user_id(pr.get("user"), "release source PR author")
        approvals = verify_current_approval(
            pr, paginated(token, endpoint + "/reviews"), author, trusted_ids, merged_at=pr["merged_at"],
        )
        head = pr["head"]["sha"]
        graphql_author, contributors = collect_pr(token, pr_number, head)
        if graphql_author != author:
            raise ReleaseEligibilityError("numeric release source author differs between GitHub APIs")
        independent = []
        for review in approvals:
            reviewer = review["user"]["id"]
            try:
                require_independent(reviewer, trusted_ids, author, contributors)
            except CustodyError:
                continue
            independent.append({"review_id": review["id"], "reviewer_id": reviewer})
        if not independent:
            raise ReleaseEligibilityError("release source has no approved reviewer independent of all PR contributors")
        inputs = {}
        for path in (MANIFEST, *GENERATED):
            reviewed = contents_bytes(token, path, head)
            if contents_bytes(token, path, sha) != reviewed:
                raise ReleaseEligibilityError(f"merged {path} differs from the exact reviewed bytes")
            inputs[path] = hashlib.sha256(reviewed).hexdigest()
    except (ProvisioningError, CustodyError) as exc:
        raise ReleaseEligibilityError(str(exc)) from None
    return {
        "schema": "baobab.dev10.reviewed-release-source.v1",
        "repository": REPOSITORY, "source_sha": sha, "pr": pr_number, "pr_head_sha": head,
        "merged_at": pr["merged_at"], "approvals": independent, "input_sha256": inputs,
    }


def maintenance(family, previous):
    if not EXCEPTION.is_file():
        return False
    try:
        declaration = EXCEPTION.read_bytes()
        decision = json.loads(declaration)
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
    if not any(p in ("Dockerfile", ".devcontainer/docker/Dockerfile")
               or p.startswith(("scripts/security/", "config/security/"))
               or p in ("scripts/dev10_kernel_risk_gate.py", ".github/workflows/security.yml")
               for p in changed):
        raise ReleaseEligibilityError("maintenance release has no qualifying security/packaging change")

    token = os.environ.get("GH_TOKEN")
    if not token:
        raise ReleaseEligibilityError("maintenance exception requires GitHub review evidence")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if repo != REPOSITORY:
        raise ReleaseEligibilityError("maintenance custody verifier requires the canonical repository")
    trusted_logins = [
        value.strip() for value in os.environ.get("DEV10_SECURITY_APPROVER_LOGINS", "").split(",")
        if value.strip()
    ]
    pr_number = decision["review_pr"]
    endpoint = f"/repos/{repo}/pulls/{pr_number}"
    try:
        _, pr = api_request(token, "GET", endpoint)
        if not isinstance(pr, dict):
            raise ReleaseEligibilityError("maintenance exception PR metadata is unavailable")
        author_id = rest_user_id(pr.get("user"), "maintenance PR author")
        merged_sha = pr.get("merge_commit_sha")
        if (pr.get("merged") is not True or not isinstance(merged_sha, str)
                or not re.fullmatch(r"[0-9a-f]{40}", merged_sha)
                or pr.get("state") != "closed" or not canonical_main_pr(pr)):
            raise ReleaseEligibilityError("maintenance exception PR must be merged into canonical main")
        merge_time = pr.get("merged_at")
        if not isinstance(merge_time, str):
            raise ReleaseEligibilityError("maintenance exception PR merge timestamp is unavailable")
        run("git", "merge-base", "--is-ancestor", merged_sha, "HEAD")
        trusted_ids = set(resolve_trusted_reviewers(token, trusted_logins))
        reviews = paginated(token, endpoint + "/reviews")
        approvals = verify_current_approval(pr, reviews, author_id, trusted_ids, merged_at=merge_time)
        head = pr["head"]["sha"]
        path = EXCEPTION.as_posix()
        if not any(isinstance(item, dict) and item.get("filename") == path
                   and item.get("status") in ("added", "modified")
                   for item in paginated(token, endpoint + "/files")):
            raise ReleaseEligibilityError("maintenance approval PR did not change the release declaration")
        if any(contents_bytes(token, path, ref) != declaration for ref in (head, merged_sha)):
            raise ReleaseEligibilityError("maintenance release declaration differs from the exact reviewed bytes")
        graphql_author_id, contributors = collect_pr(token, pr_number, head)
        if graphql_author_id != author_id:
            raise ReleaseEligibilityError("numeric PR author identity differs between GitHub APIs")
    except (ProvisioningError, CustodyError) as exc:
        raise ReleaseEligibilityError(str(exc)) from None

    for approval in approvals:
        reviewer_id = approval["user"]["id"]
        try:
            require_independent(reviewer_id, trusted_ids, author_id, contributors)
        except CustodyError:
            continue
        return True
    raise ReleaseEligibilityError("no trusted current-head maintenance approver is independent of PR contributors")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-evidence", type=Path, required=True)
    args = parser.parse_args()
    if classify(args.tag) is None:
        parser.error("invalid tag")
    token = os.environ.get("GH_TOKEN")
    if not token or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        parser.error("release source verification requires the canonical repository and a read token")
    trusted_logins = [
        value.strip() for value in os.environ.get("DEV10_SECURITY_APPROVER_LOGINS", "").split(",")
        if value.strip()
    ]
    try:
        if run("git", "rev-parse", "HEAD") != args.source_sha:
            raise ReleaseEligibilityError("release source SHA differs from the checkout")
        trusted_ids = set(resolve_trusted_reviewers(token, trusted_logins))
        evidence = reviewed_source(token, args.source_sha, trusted_ids)
        evidence["release_tag"] = args.tag
        args.source_evidence.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if classify(args.tag) == "ga":
            print("GA must pass existing same-source qualified RC digest-reuse gate")
            return
        family = args.tag.split("-rc.", 1)[0]
        tags = run("git", "tag", "--list", "v*").splitlines()
        previous = previous_ga(family, tags)
        ga_tags = [t for t in tags if semver(t) is not None]
        if family in ga_tags or semver(family) <= max(map(semver, ga_tags)):
            raise ReleaseEligibilityError("RC family must be newer than the latest GA")
        changed = manifest(previous) != manifest("HEAD")
        locked = run("git", "show", f"{previous}:config/versions.lock") != run("git", "show", "HEAD:config/versions.lock")
        outcome = decide(args.tag, tags, changed, locked, maintenance(family, previous) if not changed else False)
        print(json.dumps({"tag": args.tag, "previous_ga": previous, "eligibility": outcome}))
    except (ReleaseEligibilityError, ProvisioningError, OSError) as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
