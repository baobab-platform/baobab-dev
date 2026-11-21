# GII-05 historical custody of PR #76

The authenticated audit corroborated independent exact-head approval and pre-merge owner concurrence for PR #76. The audit used the shared custody verifier and the accepted DEV-10 decision contract. [Issue #81](https://github.com/baobab-platform/baobab-dev/issues/81) · [ADR-DEV10-001](../adr/ADR-DEV10-001-reusable-development-risk-policy.md)

| Evidence | Verified historical value |
| --- | --- |
| Decision PR and exact head | [#76](https://github.com/baobab-platform/baobab-dev/pull/76) at `f9fd73d4e848a7c4d3bcfbe28651e06149cdcb6d` |
| Complete history | 94 commits and eight reviews. Contributor IDs are `19864447`, `350241706`, and `356890520`. |
| Reviewer collision | ID `356890520` authored `dad5dc64031d05b7e7d93345f1ea553abea6c70e` and is excluded from independent review. The platform committer ID `19864447` remains in the contributor set. |
| Effective approval | Reviewer ID `356900102`, review `5932308847`, approved the exact head at `2026-11-17T03:28:08Z`. [Review](https://github.com/baobab-platform/baobab-dev/pull/76#pullrequestreview-5932308847) |
| Owner concurrence | Owner ID `49340314` posted comment `6924572973` at `2026-11-16T17:56:59Z`. [Comment](https://github.com/baobab-platform/baobab-dev/pull/76#issuecomment-6924572973) |
| Canonical merge | `29db8484fead93bf5eee95f29803592d575f7d17`, merged at `2026-11-17T03:36:58Z`. |

The policy-contract workflow ran both the historical custody and reviewed-source checks on #74 at `f860332af8442f3ad85e43109a1f243441f3e562`. The independently downloaded artifact ZIP matched SHA-256 `f75811660e4f973ef6d6872faa857dbd2556718368131d16831ee16285e5f206`. Its two receipts agree on head, contributors and effective approval. [Run 44683694368, attempt 1](https://github.com/baobab-platform/baobab-dev/actions/runs/44683694368) · [Receipt archive](https://github.com/baobab-platform/baobab-dev/actions/runs/44683694368/artifacts/14605591489)

## Review and reproduction

1. Run `python3 -m unittest discover -s tests -p 'test_audit_pr_reviewer_independence.py' -v` for the exact-head historical receipt and negative review cases.
2. Use the policy-contract workflow to run `scripts/audit_pr_reviewer_independence.py --historical` with authenticated read-only GitHub access. Review the retained head, approval and owner evidence together.
3. Use the custody and provisioning suites to verify paginated history, typed IDs, effective state changes, stale approvals and contributor exclusion.

The earlier standalone snapshot evaluator has been superseded by the shared verifier in #74. The regression cases now exercise that verifier. This is historical evidence for #76. Current repository enforcement and the authority for #92 or a release are evaluated separately. [Shared verifier](../../scripts/audit_pr_reviewer_independence.py) · [Custody negative cases](../../tests/test_custody_independence.py)
