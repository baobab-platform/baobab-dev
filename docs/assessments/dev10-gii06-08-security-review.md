# GII-06–08 GitHub API diagnostics and identity assessment

The reviewed integration baseline is PR #74 at `f860332af8442f3ad85e43109a1f243441f3e562`. Its shared transport owns REST and GraphQL request handling. This review completes the REST failure regressions against that implementation. [Issue #81](https://github.com/baobab-platform/baobab-dev/issues/81) · [ADR-DEV10-001](../adr/ADR-DEV10-001-reusable-development-risk-policy.md)

## GII-06 safe diagnostics

| Failure | Evidence retained | Refusal |
| --- | --- | --- |
| GitHub HTTP error | HTTP status, validated request ID and an allowlisted GitHub message | Custody fails unless the caller explicitly handles the status as part of its contract |
| Malformed or oversized error body | HTTP status and validated request ID. Oversized data adds the 1 MiB limit diagnostic. | The error body stays out of logs |
| Hostile request ID or unknown message | HTTP status and a generic diagnostic when available | Arbitrary header, body and transport text stay out of logs |
| Transport, timeout, malformed response, SHA or metadata failure | A bounded diagnostic for the failed stage. Metadata mismatches identify field names. | The caller refuses the identity |

The new tests exercise the committer-lookup caller through the same bounded HTTP handler used by provisioning. Existing tests cover documented messages, successful-response size limits, timeouts, malformed JSON and unsafe response metadata. Failure cases use offline fixtures. The historical receipt provides authenticated evidence for the successful exact-SHA path. [Transport](../../scripts/github_api_transport.py) · [Custody tests](../../tests/test_custody_independence.py) · [Historical receipt](https://github.com/baobab-platform/baobab-dev/actions/runs/44683694368/artifacts/14605591489)

## GII-07 exact SHA and raw metadata

The committer fallback is available only when GraphQL includes an explicitly null committer user link. It requires REST to return the same immutable commit SHA, a typed linked positive numeric User ID, and matching raw name, email and instant. Timestamp parsing accepts equivalent timezone spellings. A malformed response or disagreement fails closed. These checks retain separate evidence for commit identity and account linkage. [Custody implementation](../../scripts/custody_independence.py)

## GII-08 contributor and approver roles

The REST committer fallback contributes to reviewer exclusion only. GitHub's `web-flow` User ID `19864447` remains in the contributor set and is ineligible as an independent reviewer. Review eligibility also requires trusted appointments, complete contributor exclusion and a current-head effective review. Author, co-author, reviewer and owner identity use their role-specific typed evidence. Login strings, email aliases, AI trailers and commit signatures carry no approval authority. [Provisioner tests](../../tests/test_provision_protected_risk_policy.py)

## Verification

Run `python3 -m unittest discover -s tests -p 'test_custody_independence.py' -v` and the policy-contract workflow. Keep each refusal and the live successful receipt tied to the tested commit. The validation of other API callers and repository enforcement is tracked under GII-12–14.
