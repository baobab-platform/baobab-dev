"""Complete numeric commit-custody enumeration for protected DEV-10 decisions.

The GraphQL history is paginated to exhaustion. Missing identities, changing
heads/counts, duplicate commits, incomplete author connections, or API errors
are fatal: an incomplete history must never be treated as independent.
"""
import datetime as dt
import json
import re
import unicodedata
import urllib.request

from github_api_transport import (
    API_ROOT, API_VERSION, GitHubAPIError, request_json, safe_github_message,
)

REPOSITORY = "baobab-platform/baobab-dev"
# GitHub links this service User to PR #76 commit dad5dc64031d05b7e7d93345f1ea553abea6c70e.
GITHUB_WEB_FLOW_ID = 19864447
MAX_PAGES = 100


class CustodyError(ValueError):
    """GitHub commit custody could not be established completely."""


def _require(condition, message):
    if not condition:
        raise CustodyError(message)


def is_positive_id(value):
    return type(value) is int and value > 0


def rest_user_id(actor, label):
    _require(isinstance(actor, dict) and actor.get("type") == "User",
             f"{label} must be a typed GitHub User")
    user_id = actor.get("id")
    _require(is_positive_id(user_id), f"{label} has no positive numeric GitHub user ID")
    return user_id


def resolve_trusted_user_ids(logins, fetch_user):
    """Bootstrap the configured reviewer allowlist with typed, unique IDs."""
    _require(bool(logins), "trusted reviewer allow-list is empty")
    identities = {}
    seen_logins = set()
    for login in logins:
        _require(isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9-]{1,39}", login),
                 "trusted reviewer login has invalid syntax")
        key = login.casefold()
        _require(key not in seen_logins, "trusted reviewer allow-list contains duplicate logins")
        seen_logins.add(key)
        user = fetch_user(login)
        user_id = rest_user_id(user, "trusted reviewer")
        current_login = user.get("login")
        _require(isinstance(current_login, str) and current_login.casefold() == key,
                 "trusted reviewer login resolution mismatch")
        _require(user_id != GITHUB_WEB_FLOW_ID,
                 "GitHub service User is ineligible for the trusted reviewer allow-list")
        _require(user_id not in identities, "trusted reviewers resolve to duplicate numeric identities")
        identities[user_id] = current_login
    return identities


def review_timestamp(value):
    _require(isinstance(value, str) and value, "review timestamp is missing")
    try:
        timestamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CustodyError("review timestamp is invalid") from None
    _require(timestamp.tzinfo is not None, "review timestamp must include a timezone")
    return timestamp.astimezone(dt.timezone.utc)


def latest_user_reviews(reviews):
    """Order effective, typed PR review records by immutable reviewer ID."""
    _require(isinstance(reviews, list) and len(reviews) <= 10_000,
             "incomplete or invalid review history")
    latest = {}
    seen_review_ids = set()
    account_types = {}
    for review in reviews:
        _require(isinstance(review, dict), "malformed review evidence")
        state = review.get("state")
        if state == "PENDING":
            continue
        _require(state in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"),
                 "review contains an unknown effective state")
        review_id = review.get("id")
        _require(is_positive_id(review_id), "numeric GitHub review ID is missing")
        _require(review_id not in seen_review_ids, "duplicate GitHub review ID in history")
        seen_review_ids.add(review_id)
        reviewer = review.get("user")
        _require(isinstance(reviewer, dict), "review contains no reviewer account identity")
        reviewer_type = reviewer.get("type")
        _require(reviewer_type in ("User", "Bot"),
                 "review contains a non-User or untyped reviewer identity")
        reviewer_id = reviewer.get("id")
        _require(is_positive_id(reviewer_id), "reviewer has no positive numeric GitHub user ID")
        _require(account_types.setdefault(reviewer_id, reviewer_type) == reviewer_type,
                 "conflicting account type for a numeric reviewer")
        if reviewer_type == "Bot" or reviewer_id == GITHUB_WEB_FLOW_ID:
            continue
        login = reviewer.get("login")
        _require(isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9-]{1,39}", login),
                 "typed review actor has no valid GitHub login")
        submitted = review_timestamp(review.get("submitted_at"))
        candidate = (submitted, review_id, review)
        if reviewer_id not in latest or candidate[:2] > latest[reviewer_id][:2]:
            latest[reviewer_id] = candidate
    return latest


def _numeric_user_id(actor, label):
    _require(isinstance(actor, dict), f"{label} identity is missing")
    user = actor.get("user")
    _require(isinstance(user, dict), f"{label} is not linked to a GitHub user")
    _require(user.get("__typename") == "User", f"{label} is not a concrete GitHub User")
    user_id = user.get("databaseId")
    _require(is_positive_id(user_id), f"{label} has no immutable numeric GitHub user ID")
    return user_id


def _same_timestamp(left, right):
    """Compare timezone-aware ISO-8601 timestamps as the same instant."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        left_value = dt.datetime.fromisoformat(left.replace("Z", "+00:00"))
        right_value = dt.datetime.fromisoformat(right.replace("Z", "+00:00"))
    except ValueError:
        return False
    if left_value.tzinfo is None or right_value.tzinfo is None:
        return False
    return left_value.astimezone(dt.timezone.utc) == right_value.astimezone(dt.timezone.utc)


def _rest_commit_committer_user_id(token, oid, graphql_committer):
    """Resolve an unlinked GraphQL committer through its exact REST commit SHA."""
    _require(isinstance(oid, str) and len(oid) == 40
             and all(char in "0123456789abcdef" for char in oid),
             "REST committer resolution received an invalid commit SHA")
    _require(isinstance(graphql_committer, dict),
             "unlinked GraphQL committer metadata is missing")
    expected = {key: graphql_committer.get(key) for key in ("name", "email", "date")}
    _require(all(isinstance(value, str) and value for value in expected.values()),
             "commit committer is not linked to a GitHub user and metadata is incomplete for REST reconciliation")
    request = urllib.request.Request(
        f"{API_ROOT}/repos/{REPOSITORY}/commits/{oid}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "baobab-dev-dev10-custody-verifier",
        },
    )
    try:
        _, payload = request_json(request, context="REST committer lookup")
    except GitHubAPIError as exc:
        raise CustodyError(str(exc)) from None

    _require(isinstance(payload, dict) and payload.get("sha") == oid,
             "REST committer lookup returned a different commit SHA")
    raw_commit = payload.get("commit")
    raw_committer = raw_commit.get("committer") if isinstance(raw_commit, dict) else None
    _require(isinstance(raw_committer, dict),
             "REST commit response has no raw committer metadata")
    mismatched_fields = [
        key for key, value in expected.items()
        if (not _same_timestamp(raw_committer.get(key), value)
            if key == "date" else raw_committer.get(key) != value)
    ]
    fields = ", ".join(mismatched_fields)
    _require(not mismatched_fields,
             "REST and GraphQL committer metadata disagree for the exact commit "
             f"(fields: {fields})")
    committer = payload.get("committer")
    _require(isinstance(committer, dict) and committer.get("type") == "User",
             "REST exact-SHA committer is not a linked GitHub User")
    user_id = committer.get("id")
    login = committer.get("login")
    _require(type(user_id) is int and user_id > 0
             and isinstance(login, str) and login,
             "REST exact-SHA committer has no immutable numeric GitHub user identity")
    return user_id


def _pull_request_author_user_id(actor):
    """Resolve only a concrete GitHub User returned by PullRequest.author (Actor)."""
    _require(isinstance(actor, dict), "decision PR author identity is missing")
    _require(actor.get("__typename") == "User",
             "decision PR author is not a concrete GitHub User")
    user_id = actor.get("databaseId")
    _require(type(user_id) is int and user_id > 0,
             "decision PR author has no immutable numeric GitHub user ID")
    return user_id


def _safe_detail(value, limit=240):
    """Return bounded single-line diagnostics with credentials and controls removed."""
    if not isinstance(value, str):
        return ""
    value = "".join(
        " " if unicodedata.category(char)[0] == "C" else char
        for char in value
    )
    value = re.sub(
        r"(?i)\b(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}",
        "[REDACTED]", value,
    )
    value = re.sub(
        r"""(?i)(["']?(?:token|authorization|password|secret|api[_-]?key)["']?\s*[:=]\s*)["']?[^\s,;"' }]+["']?""",
        r"\1[REDACTED]", value,
    )
    value = re.sub(
        r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}",
        "[REDACTED_GITHUB_TOKEN]", value,
    )
    value = re.sub(r"://[^/\s:@]+:[^/\s@]+@", "://[REDACTED]@", value)
    value = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
        "[REDACTED_JWT]", value,
    )
    return " ".join(value.split()).lstrip(":%")[:limit]

_SAFE_GITHUB_ERROR_TYPES = {
    "FORBIDDEN", "NOT_FOUND", "RATE_LIMITED", "INVALID",
    "UNAUTHORIZED", "BAD_USER_INPUT", "THROTTLED",
    "SERVICE_UNAVAILABLE", "INTERNAL",
}
_GRAPHQL_FIELDS = {
    "repository", "pullRequest", "commits", "totalCount", "pageInfo",
    "endCursor", "hasNextPage", "nodes", "commit", "oid", "headRefOid",
    "author", "authors", "committer", "user", "databaseId",
    "name", "email", "date", "login",
}


def _graphql_error_summary(errors):
    if not isinstance(errors, list) or not errors:
        return "GraphQL response contained an invalid errors field"
    details = []
    for error in errors[:5]:
        if not isinstance(error, dict):
            details.append("malformed error entry")
            continue
        message = safe_github_message(error.get("message"))
        raw_type = error.get("type")
        error_type = (
            raw_type if isinstance(raw_type, str)
            and raw_type in _SAFE_GITHUB_ERROR_TYPES else ""
        )
        path = error.get("path")
        path_parts = []
        if isinstance(path, list):
            for item in path[:8]:
                if type(item) is int and 0 <= item <= 10_000:
                    path_parts.append(str(item))
                elif isinstance(item, str) and (
                    item in _GRAPHQL_FIELDS or re.fullmatch(r"c[0-9]{1,2}", item)
                ):
                    path_parts.append(item)
        safe_path = ".".join(path_parts)[:240]
        parts = [message]
        if error_type:
            parts.append(f"type={error_type}")
        if safe_path:
            parts.append(f"path={safe_path}")
        details.append(" (".join((parts[0], ", ".join(parts[1:]) + ")")) if len(parts) > 1 else message)
    return "; ".join(details)


def _graphql(token, query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    request = urllib.request.Request(
        f"{API_ROOT}/graphql",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "baobab-dev-dev10-custody-verifier",
        },
    )
    try:
        _, payload = request_json(request, context="GitHub GraphQL")
    except GitHubAPIError as exc:
        raise CustodyError(str(exc)) from None
    _require(isinstance(payload, dict), "GitHub GraphQL returned a malformed response")
    if "errors" in payload:
        raise CustodyError(_graphql_error_summary(payload["errors"]))
    data = payload.get("data")
    _require(isinstance(data, dict), "GitHub GraphQL response has no data")
    return data


def _pull_request_metadata(token, pr_number, expected_head):
    """Read current PR identity and server-reported commit count without paging history."""
    query = """
    query($owner: String!, $name: String!, $number: Int!) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          headRefOid
          author { __typename ... on User { databaseId } }
          commits(first: 1) { totalCount }
        }
      }
    }
    """
    data = _graphql(token, query, {
        "owner": "baobab-platform", "name": "baobab-dev", "number": pr_number,
    })
    repository = data.get("repository")
    pull = repository.get("pullRequest") if isinstance(repository, dict) else None
    _require(isinstance(pull, dict), "decision PR was not found in GraphQL metadata query")
    _require(pull.get("headRefOid") == expected_head,
             "decision PR head changed during custody enumeration")
    author_id = _pull_request_author_user_id(pull.get("author"))
    commits = pull.get("commits")
    count = commits.get("totalCount") if isinstance(commits, dict) else None
    _require(type(count) is int and count > 0, "decision PR has no complete commit count")
    return author_id, count


def _fetch_commit_records(token, commit_oids):
    """Resolve exact locally enumerated Git OIDs in bounded GraphQL object batches."""
    records = []
    batch_size = 20
    for offset in range(0, len(commit_oids), batch_size):
        batch = commit_oids[offset:offset + batch_size]
        declarations = ["$owner: String!", "$name: String!"]
        variables = {"owner": "baobab-platform", "name": "baobab-dev"}
        fields = []
        for index, oid in enumerate(batch):
            declarations.append(f"$oid{index}: String!")
            variables[f"oid{index}"] = oid
            fields.append(
                f"c{index}: object(expression: $oid{index}) {{ ... on Commit {{ "
                "oid author { user { __typename databaseId } } "
                "committer { name email date user { __typename databaseId login } } "
                "authors(first: 100) { totalCount pageInfo { hasNextPage } "
                "nodes { user { __typename databaseId } } } } }"
            )
        query = (
            "query(" + ", ".join(declarations) + ") { "
            "repository(owner: $owner, name: $name) { "
            + " ".join(fields) + " } }"
        )
        data = _graphql(token, query, variables)
        repository = data.get("repository")
        _require(isinstance(repository, dict),
                 "GitHub commit-object response has no repository")
        for index, expected_oid in enumerate(batch):
            record = repository.get(f"c{index}")
            _require(isinstance(record, dict) and record.get("oid") == expected_oid,
                     "GitHub did not resolve every requested commit object by exact SHA")
            records.append(record)
    return records


def _add_commit_contributors(token, commit, contributors, seen_commits):
    _require(isinstance(commit, dict), "decision PR contains a malformed commit")
    oid = commit.get("oid")
    _require(isinstance(oid, str) and len(oid) == 40
             and all(c in "0123456789abcdef" for c in oid),
             "decision PR commit has an invalid object ID")
    _require(oid not in seen_commits, "decision PR commit history contains a duplicate")
    seen_commits.add(oid)
    contributors.add(_numeric_user_id(commit.get("author"), "commit author"))
    committer = commit.get("committer")
    _require(isinstance(committer, dict) and "user" in committer,
             "commit committer link evidence is missing")
    if committer["user"] is None:
        contributors.add(_rest_commit_committer_user_id(token, oid, committer))
    else:
        contributors.add(_numeric_user_id(committer, "commit committer"))
    authors = commit.get("authors")
    _require(isinstance(authors, dict), "commit author/co-author connection is missing")
    author_nodes = authors.get("nodes")
    author_count = authors.get("totalCount")
    author_page = authors.get("pageInfo")
    _require(isinstance(author_nodes, list) and type(author_count) is int
             and isinstance(author_page, dict),
             "commit author/co-author connection is malformed")
    _require(author_page.get("hasNextPage") is False and len(author_nodes) == author_count,
             "commit author/co-author history is incomplete")
    _require(author_count > 0, "commit has no resolvable author identity")
    for actor in author_nodes:
        contributors.add(_numeric_user_id(actor, "commit author/co-author"))

def collect_pr(token, pr_number, expected_head, commit_oids=None):
    """Return (PR author numeric ID, all commit author/co-author/committer IDs)."""
    _require(type(pr_number) is int and pr_number > 0, "invalid decision PR number")
    _require(isinstance(expected_head, str) and len(expected_head) == 40
             and all(c in "0123456789abcdef" for c in expected_head),
             "invalid expected decision PR head")
    if commit_oids is not None:
        author_id, expected_count = _pull_request_metadata(token, pr_number, expected_head)
        _require(isinstance(commit_oids, list) and len(commit_oids) == expected_count
                 and bool(commit_oids) and expected_head in commit_oids
                 and all(isinstance(oid, str) and len(oid) == 40
                         and all(char in "0123456789abcdef" for char in oid)
                         for oid in commit_oids)
                 and len(set(commit_oids)) == len(commit_oids),
                 "local commit range does not match GitHub PR commit count/head")
        commits = _fetch_commit_records(token, commit_oids)
        seen_commits = set()
        contributors = set()
        for commit in commits:
            _add_commit_contributors(token, commit, contributors, seen_commits)
        _require(len(seen_commits) == expected_count,
                 f"decision PR commit history is incomplete ({len(seen_commits)}/{expected_count})")
        final_author, final_count = _pull_request_metadata(token, pr_number, expected_head)
        _require(final_author == author_id and final_count == expected_count,
                 "decision PR identity or commit count changed during enumeration")
        return author_id, contributors

    query = """
    query($owner: String!, $name: String!, $number: Int!, $after: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          headRefOid
          author {
            __typename
            ... on User { databaseId }
          }
          commits(first: 100, after: $after) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes {
              commit {
                oid
                author { user { __typename databaseId } }
                committer { name email date user { __typename databaseId login } }
                authors(first: 100) {
                  totalCount
                  pageInfo { hasNextPage }
                  nodes { user { __typename databaseId } }
                }
              }
            }
          }
        }
      }
    }
    """
    variables = {
        "owner": "baobab-platform",
        "name": "baobab-dev",
        "number": pr_number,
        "after": None,
    }
    author_id = None
    expected_count = None
    seen_commits = set()
    seen_cursors = set()
    contributors = set()

    for _page in range(MAX_PAGES):
        data = _graphql(token, query, variables)
        repository = data.get("repository")
        pull = repository.get("pullRequest") if isinstance(repository, dict) else None
        _require(isinstance(pull, dict), "decision PR was not found in GraphQL custody query")
        _require(pull.get("headRefOid") == expected_head,
                 "decision PR head changed during complete custody enumeration")
        current_author = pull.get("author")
        current_author_id = _pull_request_author_user_id(current_author)
        if author_id is None:
            author_id = current_author_id
        _require(author_id == current_author_id,
                 "decision PR author identity changed during custody enumeration")

        commits = pull.get("commits")
        _require(isinstance(commits, dict), "decision PR commit connection is missing")
        count = commits.get("totalCount")
        _require(type(count) is int and count > 0, "decision PR has no complete commit count")
        if expected_count is None:
            expected_count = count
        _require(expected_count == count, "decision PR commit count changed during enumeration")

        nodes = commits.get("nodes")
        page_info = commits.get("pageInfo")
        _require(isinstance(nodes, list) and isinstance(page_info, dict),
                 "decision PR commit page is malformed")
        for item in nodes:
            commit = item.get("commit") if isinstance(item, dict) else None
            _add_commit_contributors(token, commit, contributors, seen_commits)

        has_next = page_info.get("hasNextPage")
        cursor = page_info.get("endCursor")
        _require(type(has_next) is bool, "commit pagination state is missing")
        if not has_next:
            _require(len(seen_commits) == expected_count,
                     f"decision PR commit history is incomplete ({len(seen_commits)}/{expected_count})")
            _require(expected_head in seen_commits, "complete commit history omits the expected PR head")
            return author_id, contributors
        _require(bool(nodes) and isinstance(cursor, str) and cursor and cursor not in seen_cursors,
                 "commit pagination did not advance")
        seen_cursors.add(cursor)
        variables["after"] = cursor

    raise CustodyError("decision PR commit history exceeded the 10,000-commit safety limit")


def require_independent(reviewer_id, trusted_reviewer_ids, author_id, contributors):
    """Require a trusted reviewer distinct from the PR author and all contributors."""
    _require(type(reviewer_id) is int and reviewer_id > 0,
             "reviewer numeric GitHub user ID is missing")
    _require(type(author_id) is int and author_id > 0,
             "PR author numeric GitHub user ID is missing")
    _require(isinstance(trusted_reviewer_ids, set)
             and all(type(item) is int and item > 0 for item in trusted_reviewer_ids),
             "trusted reviewer numeric identity set is malformed")
    _require(reviewer_id in trusted_reviewer_ids,
             "reviewer is not in the trusted numeric reviewer set")
    _require(isinstance(contributors, set)
             and all(type(item) is int and item > 0 for item in contributors),
             "complete contributor identity set is malformed")
    _require(reviewer_id != author_id and reviewer_id not in contributors,
             "reviewer is not independent of the PR author and commit contributors")
