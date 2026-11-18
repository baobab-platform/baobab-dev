# GII-05 — historical PR #76 reviewer/contributor collision

Status: **OPEN / custody not independently qualified**. This is a read-only audit aid, not a policy decision, approval, or provisioning authority.

## Evidence observed (18 November 2026)

- PR #76 is merged, final PR head `f9fd73d4e848a7c4d3bcfbe28651e06149cdcb6d`, with 94 commits. Its author is GitHub numeric user ID `350241706` (`wekhason`).
- Issue #81 records commit `dad5dc64031d05b7e7d93345f1ea553abea6c70e` as authored by `sknabusiu` and committed by GitHub `web-flow`. The issue identifies this as a reviewer/contributor collision; the collision must be checked against the **complete exact-head commit history**, not only that commit.
- The PR review timeline contains several approvals by `sknabusiu`, a later `CHANGES_REQUESTED`, and approvals by `sdnabusiu`. At least one approval by a different reviewer appears in the history, but its *current-head eligibility*, trusted numeric identity, temporal ordering and effective review state have **not** been independently established by this audit.
- The GitHub connector's review listing exposes author logins but omits immutable numeric reviewer IDs and review commit SHA in its normalized result. This listing alone cannot prove qualifying custody.
- The existing `custody_independence.collect_pr` enumerates commit authors, co-authors and committers, with fatal handling of incomplete histories. It should remain the authoritative collector; do not replace it with a hand-maintained contributor list.

## Read-only next step

Collect a fresh, paginated, authenticated GitHub REST/GraphQL snapshot for PR #76, including:
1. Exact head and full commit history (every author, co-author, committer numeric ID, and all pages); confirm the observed merge-commit author.
2. All PR review records with numeric `user.id`, state, `commit_id`, numeric review ID and `submitted_at`, plus dismissal information.
3. Independently resolved trusted reviewer numeric IDs, and attributable pre-merge owner concurrence with timestamps.
4. GitHub API errors, missing identities and truncated pages as **refusal**, never successful evidence.

`scripts/audit_gii05_review_custody.py --evidence evidence.json` checks a **supplied** normalized evidence snapshot for reviewer/contributor collision and latest effective exact-head approval. Its `history_complete` flag is only an input assertion: it is **not cryptographic proof of completeness**, and the tool does not authenticate GitHub data. Use it as a regression/analysis aid alongside the existing live custody verifier, not as an authorization decision. Never feed arbitrary user-edited JSON into provisioning.

The fixture tests deliberately model reviewer ID `356890520` as a contributor and ID `356900102` as a distinct reviewer; they are **synthetic qualification scenarios**, not a declaration that the historical review passed. The final outcome stays **UNVERIFIED** until independent live evidence confirms exact-head eligibility, effective review state and owner concurrence.

## Controls unchanged

No token or secret output; no environment changes; no protected variable write; no reviewer impersonation; no deployment approval; no merge; no weakening of exact-SHA/metadata reconciliation or contributor exclusion. Issue #81 remains open. If no independent eligible review is demonstrable, record historical governance nonconformance and require explicit owner-led remediation, without retroactively fabricating approval.
