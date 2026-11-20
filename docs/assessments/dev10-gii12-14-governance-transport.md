# GII-12–14 repository governance and GitHub transport

The review uses the #74 integration baseline and the accepted decision ADR. It adds a read-only governance receipt and exercises the refusal paths against the existing release-governance and GitHub transport implementations. [Issue #81](https://github.com/baobab-platform/baobab-dev/issues/81) · [ADR-DEV10-001](../adr/ADR-DEV10-001-reusable-development-risk-policy.md)

## GII-12 effective controls

| Observation | Evidence and interpretation |
| --- | --- |
| Main branch | Record the exact head, GitHub's branch `protected` flag, and the active rules effective on `main`. Evaluate the same review and status requirements used by the release workflow. |
| Protection detail | Preserve the HTTP status of the detailed protection read. HTTP 403 and 404 leave those details unverified. |
| Tag rules | Read the active tag rulesets by numeric ID and check the canonical release namespace. The same release check requires creation, update and deletion controls across that namespace. Unavailable bypass actors are recorded as null. |
| Protected environments | Observe the read, provision and promotion environments with read-only credentials. Retain visible review-rule counts, self-review settings and admin-bypass evidence. Missing responses remain unverified. |

The preparer controls updates to a policy decision PR. Any merge or conflict-resolution commit forms part of the reviewed history. Every author, co-author and committer remains in the contributor set. CODEOWNERS routes reviews. Effective enforcement depends on GitHub's active rules.

The hosted observation archives sanitized JSON from the repository's actual settings. A successful job verifies receipt collection and the audit tests. The report includes the release verifier's results and unavailable admin details explicitly. [Workflow](../../.github/workflows/dev10-governance-audit.yml) · [Observation script](../../scripts/audit_github_governance.py) · [Release verifier](../../scripts/verify_release_governance.py)

## GII-13 refusal coverage

| Boundary | Refusal evidence |
| --- | --- |
| Contributor identity | Missing, non-numeric, boolean or inconsistent identities and incomplete PR or co-author history are refused. Platform committer evidence stays in the contributor set. [Commit custody tests](../../tests/test_custody_independence.py) |
| Current approval and owner concurrence | Reviewer contribution, stale approvals, changed heads, dismissals, and omitted or late owner concurrence are refused. [Provisioning tests](../../tests/test_provision_protected_risk_policy.py) |
| Protected variables | Existing anchors are idempotent by exact hash. A different hash is refused. [Variable custody tests](../../tests/test_provision_protected_risk_policy.py) |
| Workflow approval | The original and triggering actors must agree with the exact first attempt. Protected reruns are refused. [Promotion tests](../../tests/test_verify_promotion_approval.py) |
| Release source | The source check binds the canonical merge to current-head independent approval and the manifest inputs. [Release source tests](../../tests/test_release_eligibility.py) |
| API failures | Invalid URLs are refused before opening a connection. The transport refuses cross-origin redirects, HTTP downgrades, credential-bearing URLs and oversized bodies. [Boundary tests](../../tests/test_gii14_transport_boundary.py) |

## GII-14 authenticated call sites

| Caller | Verified transport |
| --- | --- |
| PR and commit identity | GraphQL and exact-commit REST callers pass through `request_json`. Custody enumeration checks completeness and exact IDs. |
| Decision custody and provisioning | The provisioner uses `rest_request` for the approved evidence reads and its protected variable operation. The active-decision verifier delegates to the same provisioner and custody logic. |
| Reviewed release source and review identity | The source check reuses the provisioner and shared custody helpers. The promotion verifier reads run attempts and approval evidence through `rest_request`. |
| Release branch/tag governance | The release and audit readers share the same ruleset enumeration and `https://api.github.com` transport. The verifier still owns release refusals. |
| Hosted workflow CLI calls | The publish workflow also uses GitHub CLI for pinned workflow-run, registry-artifact and environment lookups. These are separate CLI paths with their own response validation in the workflow. |

The shared Python transport validates the API origin, bounds JSON and includes only sanitized diagnostic metadata. Unit tests exercise rejected transport responses. The hosted observation verifies the live read path and records access limitations. [Transport](../../scripts/github_api_transport.py) · [Publish call sites](../../.github/workflows/publish.yml)
