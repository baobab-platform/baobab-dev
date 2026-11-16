#!/usr/bin/env python3
"""Fail-closed numeric GitHub identity and complete PR contributor custody."""
import json
import urllib.request

class IndependenceError(ValueError):
    pass

PR_QUERY = """query($owner:String!,$repo:String!,$number:Int!){
 repository(owner:$owner,name:$repo){pullRequest(number:$number){
 headRefOid author{... on User{databaseId login}} commits(first:1){totalCount}
 }}}"""

def uid(node):
    value = (node or {}).get("databaseId")
    if type(value) is not int or value <= 0:
        raise IndependenceError("unresolved numeric GitHub user identity")
    return value

def graphql(token, query, variables):
    request = urllib.request.Request("https://api.github.com/graphql",
        data=json.dumps({"query":query,"variables":variables}).encode(),
        headers={"Authorization":f"Bearer {token}","Content-Type":"application/json",
                 "Accept":"application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if payload.get("errors"):
        raise IndependenceError("GitHub GraphQL returned errors")
    return payload.get("data") or {}

def pull_metadata(token, number, expected_head):
    variables = {"owner":"baobab-platform","repo":"baobab-dev","number":number}
    data = graphql(token, PR_QUERY, variables)
    pr = (((data.get("repository") or {}).get("pullRequest")))
    if not pr or pr.get("headRefOid") != expected_head:
        raise IndependenceError("PR head changed during contributor enumeration")
    author = uid(pr.get("author"))
    count = (pr.get("commits") or {}).get("totalCount")
    if type(count) is not int or count <= 0:
        raise IndependenceError("invalid PR commit count")
    return author, count

def collect_contributors(commits, count):
    if type(count) is not int or count <= 0 or len(commits) != count:
        raise IndependenceError("incomplete commit enumeration")
    found = set()
    seen_oids = set()
    for commit in commits:
        if not isinstance(commit, dict) or not commit.get("oid"):
            raise IndependenceError("malformed commit")
        if commit["oid"] in seen_oids:
            raise IndependenceError("duplicate commit in contributor enumeration")
        seen_oids.add(commit["oid"])
        authors = commit.get("authors")
        if not isinstance(authors, dict) or authors.get("totalCount") != len(authors.get("nodes", [])) or not authors["nodes"]:
            raise IndependenceError("incomplete author/coauthor enumeration")
        for author in authors["nodes"]:
            found.add(uid((author or {}).get("user")))
        committer = (commit.get("committer") or {}).get("user")
        # Include every resolvable committer identity. Eligibility is decided
        # only by numeric IDs; unresolved identities fail closed.
        found.add(uid(committer))
    return found

def fetch_commit_records(token, oids):
    """Fetch every commit's full author/co-author and committer identity in bounded batches."""
    records = []
    batch_size = 20
    for offset in range(0, len(oids), batch_size):
        batch = oids[offset:offset + batch_size]
        declarations = ["$owner:String!", "$repo:String!"]
        variables = {"owner":"baobab-platform", "repo":"baobab-dev"}
        fields = []
        for index, oid in enumerate(batch):
            declarations.append(f"$oid{index}:String!")
            variables[f"oid{index}"] = oid
            fields.append(
                f"c{index}: object(expression: $oid{index}) {{ ... on Commit {{ "
                "oid authors(first:10){totalCount nodes{user{databaseId login}}} "
                "committer{user{databaseId login}} } }"
            )
        query = (
            "query(" + ",".join(declarations) + "){repository(owner:$owner,name:$repo){"
            + " ".join(fields) + "}}"
        )
        repository = (graphql(token, query, variables).get("repository") or {})
        for index, expected_oid in enumerate(batch):
            record = repository.get(f"c{index}")
            if not isinstance(record, dict) or record.get("oid") != expected_oid:
                raise IndependenceError("GitHub did not resolve every requested commit object")
            records.append(record)
    return records

def collect_pr(token, number, expected_head, commit_oids=None):
    author, count = pull_metadata(token, number, expected_head)
    if commit_oids is not None:
        if (not isinstance(commit_oids, list) or len(commit_oids) != count
                or not commit_oids or expected_head not in commit_oids
                or len(set(commit_oids)) != len(commit_oids)):
            raise IndependenceError("local commit range does not match GitHub PR commit count/head")
        commits = fetch_commit_records(token, commit_oids)
    else:
        cursor = None
        commits = []
        seen = set()
        while True:
            query = """query($owner:String!,$repo:String!,$number:Int!,$cursor:String){
             repository(owner:$owner,name:$repo){pullRequest(number:$number){
             headRefOid author{... on User{databaseId login}}
             commits(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}
             nodes{commit{oid authors(first:10){totalCount nodes{user{databaseId login}}}
             committer{user{databaseId login}}}}}}}}"""
            variables = {"owner":"baobab-platform","repo":"baobab-dev",
                         "number":number,"cursor":cursor}
            data = graphql(token, query, variables)
            pr = (((data.get("repository") or {}).get("pullRequest")))
            if not pr or pr.get("headRefOid") != expected_head:
                raise IndependenceError("PR head changed during contributor enumeration")
            if uid(pr.get("author")) != author:
                raise IndependenceError("PR author changed during enumeration")
            connection = pr.get("commits") or {}
            if connection.get("totalCount") != count:
                raise IndependenceError("PR commit count changed")
            nodes = connection.get("nodes")
            if not isinstance(nodes, list) or not nodes:
                raise IndependenceError("missing commit page")
            commits.extend((node or {}).get("commit") for node in nodes)
            page = connection.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                break
            next_cursor = page.get("endCursor")
            if not next_cursor or next_cursor in seen:
                raise IndependenceError("invalid GraphQL pagination cursor")
            seen.add(next_cursor)
            cursor = next_cursor
    # Re-read PR metadata after all commit objects to reject a moving head.
    final_author, final_count = pull_metadata(token, number, expected_head)
    if final_author != author or final_count != count:
        raise IndependenceError("PR identity or commit count changed during enumeration")
    return author, collect_contributors(commits, count)

def require_independent(reviewer_id, trusted_ids, pr_author_id, contributors):
    if uid({"databaseId":reviewer_id}) not in trusted_ids:
        raise IndependenceError("reviewer not trusted")
    if reviewer_id == pr_author_id or reviewer_id in contributors:
        raise IndependenceError("reviewer contributed to approval PR")
