"""Complete numeric commit-custody enumeration for protected DEV-10 decisions.

The GraphQL history is paginated to exhaustion. Missing identities, changing
heads/counts, duplicate commits, incomplete author connections, or API errors
are fatal: an incomplete history must never be treated as independent.
"""
import datetime as dt
import json
import re
import unicodedata
import urllib.error
import urllib.request

from github_api_transport import open_github, read_bounded

API_URL = "https://api.github.com/graphql"
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
MAX_PAGES = 100


class CustodyError(ValueError):
    """GitHub commit custody could not be established completely."""


def _require(condition, message):
    if not condition:
        raise CustodyError(message)


def _numeric_user_id(actor, label):
    _require(isinstance(actor, dict), f"{label} identity is missing")
    user = actor.get("user")
    _require(isinstance(user, dict), f"{label} is not linked to a GitHub user")
    user_id = user.get("databaseId")
    _require(type(user_id) is int and user_id > 0,
             f"{label} has no immutable numeric GitHub user ID")
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
        f"https://api.github.com/repos/baobab-platform/baobab-dev/commits/{oid}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "baobab-dev-dev10-custody-verifier",
        },
    )
    try:
        with open_github(request, timeout=30) as response:
            payload = json.loads(read_bounded(response))
    except urllib.error.HTTPError as exc:
        raise CustodyError(_http_error_summary(exc, "REST committer lookup")) from exc
    except urllib.error.URLError as exc:
        raise CustodyError("REST committer lookup transport failure") from exc
    except TimeoutError as exc:
        raise CustodyError("REST committer lookup timed out") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CustodyError("REST committer lookup returned invalid JSON") from exc
    except ValueError as exc:
        raise CustodyError(f"REST committer lookup response rejected: {_safe_detail(str(exc), 120)}") from exc

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

_SAFE_GITHUB_MESSAGES = {
    "resource not accessible by integration": "Resource not accessible by integration",
    "bad credentials": "Bad credentials",
    "requires authentication": "Requires authentication",
    "not found": "Not Found",
    "validation failed": "Validation Failed",
    "api rate limit exceeded": "API rate limit exceeded",
    "secondary rate limit": "Secondary rate limit",
    "problems parsing json": "Problems parsing JSON",
    "unprocessable entity": "Unprocessable Entity",
    "forbidden": "Forbidden",
    "unauthorized": "Unauthorized",
    "internal server error": "Internal Server Error",
}
_SAFE_GITHUB_ERROR_TYPES = {
    "FORBIDDEN", "NOT_FOUND", "RATE_LIMITED", "INVALID",
    "UNAUTHORIZED", "BAD_USER_INPUT", "THROTTLED",
    "SERVICE_UNAVAILABLE", "INTERNAL",
}


def _safe_github_message(value):
    if not isinstance(value, str):
        return "unrecognized GitHub error"
    return _SAFE_GITHUB_MESSAGES.get(value.strip().casefold(), "unrecognized GitHub error")


def _graphql_error_summary(errors):
    if not isinstance(errors, list) or not errors:
        return "GraphQL response contained an invalid errors field"
    details = []
    for error in errors[:5]:
        if not isinstance(error, dict):
            details.append("malformed error entry")
            continue
        message = _safe_github_message(error.get("message"))
        raw_type = error.get("type")
        error_type = (
            raw_type if isinstance(raw_type, str)
            and raw_type in _SAFE_GITHUB_ERROR_TYPES else ""
        )
        path = error.get("path")
        path_parts = []
        if isinstance(path, list):
            for item in path[:8]:
                if type(item) is int and item >= 0:
                    path_parts.append(str(item))
                elif (isinstance(item, str)
                      and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", item)
                      and not re.search(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}", item)):
                    path_parts.append(item)
        safe_path = ".".join(path_parts)[:240]
        parts = [message]
        if error_type:
            parts.append(f"type={error_type}")
        if safe_path:
            parts.append(f"path={safe_path}")
        details.append(" (".join((parts[0], ", ".join(parts[1:]) + ")")) if len(parts) > 1 else message)
    return "; ".join(details)


def _http_error_summary(exc, context="GitHub API"):
    """Return bounded HTTP diagnostics without exposing raw response data."""
    payload = None
    oversized = False
    try:
        raw = exc.read(1_048_577)
        if len(raw) > 1_048_576:
            oversized = True
        elif raw:
            payload = json.loads(raw)
    except (AttributeError, OSError, ValueError, TypeError):
        payload = None

    message = ""
    if oversized:
        message = "error response exceeded the 1 MiB safety limit"
    elif isinstance(payload, dict):
        message = _safe_github_message(payload.get("message"))
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = [
                _safe_github_message(item.get("message")) for item in errors[:5]
                if isinstance(item, dict) and item.get("message")
            ]
            if messages:
                message = "; ".join(([message] if message else []) + messages)[:600]

    request_id = ""
    headers = getattr(exc, "headers", None)
    candidate = headers.get("x-github-request-id", "") if headers is not None else ""
    if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9-]{1,80}", candidate):
        request_id = candidate

    parts = [f"{context} HTTP {exc.code}"]
    if message:
        parts.append(message)
    if request_id:
        parts.append(f"GitHub request ID {request_id}")
    return ": ".join(parts)


def _graphql(token, query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
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
        with open_github(request, timeout=30) as response:
            payload = json.loads(read_bounded(response))
    except urllib.error.HTTPError as exc:
        raise CustodyError(_http_error_summary(exc, "GitHub GraphQL")) from exc
    except json.JSONDecodeError as exc:
        raise CustodyError("GitHub GraphQL returned invalid JSON") from exc
    except UnicodeDecodeError as exc:
        raise CustodyError("GitHub GraphQL returned invalid JSON") from exc
    except ValueError as exc:
        raise CustodyError(_safe_detail(str(exc), 180)) from exc
    except urllib.error.URLError as exc:
        raise CustodyError("GitHub GraphQL transport failed") from exc
    except TimeoutError as exc:
        raise CustodyError("GitHub GraphQL custody request timed out") from exc
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
                "oid author { user { databaseId } } "
                "committer { name email date user { databaseId login } } "
                "authors(first: 100) { totalCount pageInfo { hasNextPage } "
                "nodes { user { databaseId } } } } }"
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
    committer_user = committer.get("user") if isinstance(committer, dict) else None
    if isinstance(committer_user, dict):
        contributors.add(_numeric_user_id(committer, "commit committer"))
    else:
        contributors.add(_rest_commit_committer_user_id(token, oid, committer))
    authors = commit.get("authors")
    _require(isinstance(authors, dict), "commit author/co-author connection is missing")
    author_nodes = authors.get("nodes")
    author_count = authors.get("totalCount")
    author_page = authors.get("pageInfo")
    _require(isinstance(author_nodes, list) and type(author_count) is int
             and isinstance(author_page, dict),
             "commit author/co-author connection is malformed")
    _require(not author_page.get("hasNextPage") and len(author_nodes) == author_count,
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
                author { user { databaseId } }
                committer { name email date user { databaseId login } }
                authors(first: 100) {
                  totalCount
                  pageInfo { hasNextPage }
                  nodes { user { databaseId } }
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
            return author_id, contributors
        _require(isinstance(cursor, str) and cursor,
                 "commit pagination cursor is missing")
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
