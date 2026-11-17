"""Complete numeric commit-custody enumeration for protected DEV-10 decisions.

The GraphQL history is paginated to exhaustion. Missing identities, changing
heads/counts, duplicate commits, incomplete author connections, or API errors
are fatal: an incomplete history must never be treated as independent.
"""
import json
import urllib.error
import urllib.request

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
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            json.JSONDecodeError) as exc:
        raise CustodyError("GitHub GraphQL custody request failed") from exc
    _require(isinstance(payload, dict) and not payload.get("errors"),
             "GitHub GraphQL returned errors or malformed data")
    data = payload.get("data")
    _require(isinstance(data, dict), "GitHub GraphQL response has no data")
    return data


def collect_pr(token, pr_number, expected_head):
    """Return (PR author numeric ID, all commit author/co-author/committer IDs)."""
    _require(type(pr_number) is int and pr_number > 0, "invalid decision PR number")
    _require(isinstance(expected_head, str) and len(expected_head) == 40
             and all(c in "0123456789abcdef" for c in expected_head),
             "invalid expected decision PR head")

    query = """
    query($owner: String!, $name: String!, $number: Int!, $after: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          headRefOid
          author { databaseId }
          commits(first: 100, after: $after) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes {
              commit {
                oid
                author { user { databaseId } }
                committer { user { databaseId } }
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
        current_author = pull.get("author") or {}
        current_author_id = current_author.get("databaseId")
        _require(type(current_author_id) is int and current_author_id > 0,
                 "decision PR author has no immutable numeric GitHub user ID")
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
            _require(isinstance(commit, dict), "decision PR contains a malformed commit")
            oid = commit.get("oid")
            _require(isinstance(oid, str) and len(oid) == 40
                     and all(c in "0123456789abcdef" for c in oid),
                     "decision PR commit has an invalid object ID")
            _require(oid not in seen_commits, "decision PR commit history contains a duplicate")
            seen_commits.add(oid)

            contributors.add(_numeric_user_id(commit.get("author"), "commit author"))
            contributors.add(_numeric_user_id(commit.get("committer"), "commit committer"))

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

        has_next = page_info.get("hasNextPage")
        cursor = page_info.get("endCursor")
        _require(type(has_next) is bool, "commit pagination state is missing")
        if not has_next:
            _require(len(seen_commits) == expected_count,
                     "decision PR commit history is incomplete")
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
