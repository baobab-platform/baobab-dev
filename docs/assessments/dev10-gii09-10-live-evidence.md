# GII-09–10 authenticated identity evidence and API cost

The policy-contract workflow reads the live GitHub schema for the triggering PR head and corroborates the historical decision and service-committer witness. Each Actions receipt now carries the checked-out source SHA, run ID and attempt alongside the observed PR head. The verifier compares the actual Git checkout with the workflow SHA before writing the receipt. [Issue #81](https://github.com/baobab-platform/baobab-dev/issues/81) · [ADR-DEV10-001](../adr/ADR-DEV10-001-reusable-development-risk-policy.md) · [Policy workflow](../../.github/workflows/dev10-policy-decision.yml)

## GII-09 live qualification

| Witness | Verified evidence |
| --- | --- |
| Historical decision | #76 at `f9fd73d4e848a7c4d3bcfbe28651e06149cdcb6d`, 94 commits and eight reviews |
| Exact service commit | `dad5dc64031d05b7e7d93345f1ea553abea6c70e`, GitHub service User ID `19864447`, and matching raw name, email and instant |
| Review and owner | Review `5932308847` from ID `356900102` and owner comment `6924572973` from ID `49340314` |
| Trust boundaries | The typed REST identity corroborates the exact SHA. The test permits a subsequently linked GraphQL account when its numeric ID agrees. Missing data, changed heads and conflicting identities fail closed. |

The ZIP from hosted run `44683694368`, attempt 1, independently matched SHA-256 `f75811660e4f973ef6d6872faa857dbd2556718368131d16831ee16285e5f206`. Its receipt covers the pinned historical witness and the workflow ran a separate live schema query on #74. Future receipts distinguish the workflow's checked-out code from the historical PR head under examination. [Archived live receipt](https://github.com/baobab-platform/baobab-dev/actions/runs/44683694368/artifacts/14605591489) · [Live and offline tests](../../tests/test_custody_independence.py)

CI uses read-only credentials. The local suite checks refusal for malformed and mismatched responses. Authenticated runs supply the live evidence, including API status and sanitized request IDs. The receipt contains no credentials or raw response bodies. [Receipt implementation](../../scripts/audit_pr_reviewer_independence.py)

## GII-10 measured API cost

The historical audit trace contains seven HTTP 200 responses. The counts are per receipt and omit the workflow's separate current-head and release-lineage checks.

| Request kind | Count | Observed quota remaining |
| --- | ---: | --- |
| GraphQL history and pinned commit object | 2 | 4,961–4,962 of 5,000 in the GraphQL pool |
| REST exact-SHA committer | 2 | Included in the core pool below |
| REST PR, reviews and owner comments | 3 | 4,533–4,543 of 5,000 across all five REST calls |

One REST committer call corroborates the identified service commit independently of history enumeration. Remaining quota is a snapshot of the shared runner credential and may move between requests. This run establishes a measured baseline; call costs on a longer or differently linked history depend on pagination and unlinked committers.

Continue with fresh exact-SHA reads for each custody decision. There is no measured need for caching in this witness. Any future per-run cache would need to retain the immutable SHA, verified metadata and typed numeric ID and preserve head and completeness checks. [Shared transport](../../scripts/github_api_transport.py)
