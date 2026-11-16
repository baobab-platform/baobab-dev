#!/usr/bin/env python3
"""Fail-closed numeric GitHub identity and complete PR contributor custody."""
import json
import urllib.request

class IndependenceError(ValueError):
    pass

QUERY = """query($owner:String!,$repo:String!,$number:Int!,$cursor:String){
 repository(owner:$owner,name:$repo){pullRequest(number:$number){
 headRefOid author{... on User{databaseId login}}
 commits(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}
 nodes{commit{oid authors(first:100){totalCount nodes{user{databaseId login}}}
 committer{user{databaseId login}}}}}}}}"""

def uid(node):
    value = (node or {}).get("databaseId")
    if type(value) is not int or value <= 0:
        raise IndependenceError("unresolved numeric GitHub user identity")
    return value

def collect_contributors(commits, count):
    if type(count) is not int or count <= 0 or len(commits) != count:
        raise IndependenceError("incomplete commit enumeration")
    found = set()
    for commit in commits:
        if not isinstance(commit, dict) or not commit.get("oid"):
            raise IndependenceError("malformed commit")
        authors = commit.get("authors")
        if not isinstance(authors, dict) or authors.get("totalCount") != len(authors.get("nodes", [])) or not authors["nodes"]:
            raise IndependenceError("incomplete author/coauthor enumeration")
        for author in authors["nodes"]:
            found.add(uid((author or {}).get("user")))
        committer = (commit.get("committer") or {}).get("user")
        # GitHub's service account is not a human contributor.
        if (committer or {}).get("login") != "web-flow":
            found.add(uid(committer))
    return found

def collect_pr(token, number, expected_head):
    cursor = None
    commits = []
    count = None
    author = None
    seen = set()
    while True:
        variables = {"owner":"baobab-platform","repo":"baobab-dev",
                     "number":number,"cursor":cursor}
        request = urllib.request.Request("https://api.github.com/graphql",
            data=json.dumps({"query":QUERY,"variables":variables}).encode(),
            headers={"Authorization":f"Bearer {token}","Content-Type":"application/json",
                     "Accept":"application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
        if payload.get("errors"):
            raise IndependenceError("GitHub GraphQL returned errors")
        pr = (((payload.get("data") or {}).get("repository") or {}).get("pullRequest"))
        if not pr or pr.get("headRefOid") != expected_head:
            raise IndependenceError("PR head changed during contributor enumeration")
        current_author = uid(pr.get("author"))
        if author is not None and current_author != author:
            raise IndependenceError("PR author changed during enumeration")
        author = current_author
        connection = pr.get("commits") or {}
        if count is not None and count != connection.get("totalCount"):
            raise IndependenceError("PR commit count changed")
        count = connection.get("totalCount")
        nodes = connection.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            raise IndependenceError("missing commit page")
        commits.extend((n or {}).get("commit") for n in nodes)
        page = connection.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        next_cursor = page.get("endCursor")
        if not next_cursor or next_cursor in seen:
            raise IndependenceError("invalid GraphQL pagination cursor")
        seen.add(next_cursor)
        cursor = next_cursor
    return author, collect_contributors(commits, count)

def require_independent(reviewer_id, trusted_ids, pr_author_id, contributors):
    if uid({"databaseId":reviewer_id}) not in trusted_ids:
        raise IndependenceError("reviewer not trusted")
    if reviewer_id == pr_author_id or reviewer_id in contributors:
        raise IndependenceError("reviewer contributed to approval PR")
