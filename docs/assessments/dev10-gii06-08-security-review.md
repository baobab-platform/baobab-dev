# DEV-10 issue #81 — GII-06 implementation and GII-07/GII-08 security assessments

**Baseline:** PR #74 head `ceb2f1b8323466b56e3572a7f8174c2e0c2c027c`. **Scope:** no protected writes, approval grants, release activation, policy broadening, or relaxed contributor exclusion.

## GII-06 — REST diagnostics (implemented)

The PR #74 baseline already includes `_http_error_summary` with HTTP status, bounded error-body parsing, optional validated `x-github-request-id`, and a 1 MiB response cap. Its REST exception handler was using that helper. However, `_http_error_summary` still emitted the arbitrary GitHub JSON `message` after generic redaction, and REST transport failures included `URLError.reason`. Error bodies and network error reasons are not a trustworthy diagnostic channel and may contain unanticipated secrets or attacker-supplied content.

This change admits only a small allowlist of known GitHub error messages; unknown messages are reported as `unrecognized GitHub error`. HTTP status and syntactically validated request ID remain visible. REST transport failure is reported without the raw reason. API failures still abort custody. Negative tests cover known/unknown messages, invalid JSON, oversized bodies, malicious request IDs and transport reasons.

**Residual review:** `_http_error_summary` also services GraphQL HTTP errors, so its message allowlist is deliberately shared. Check CI and consider follow-on audits of *all* other authenticated GitHub API callers under GII-14. No successful live REST failure was induced as part of this change.

## GII-07 — metadata equality (assessment; no policy relaxation)

**Observed implementation:** `_rest_commit_committer_user_id` requires a 40-character lowercase exact SHA; compares the REST response `sha` to that SHA; requires raw `commit.committer` name, email and timezone-normalized date to match GraphQL GitActor metadata; then requires REST `committer.type == "User"` and a positive integer `committer.id`.

**Threat distinction:** The SHA identifies immutable commit bytes; it does *not* prove the GitHub account association, because the account link is platform-provided metadata, not necessarily a signed statement inside the commit. Comparing the raw Git metadata across two GitHub API representations is useful for detecting inconsistent responses, stale projections and implementation defects, but is **not an independent human-identity attestation**: both APIs can reflect the same platform attribution. Dropping name/email/date checks would reduce consistency assurance without improving the proof that an account is a human.

**Decision:** retain exact-SHA, metadata equality and numeric account ID requirements. Continue accepting equivalent timestamp offsets that represent the same instant; reject missing/naive timestamps and conflicting raw metadata. A change to this rule needs an explicit security decision, representative live read-only evidence and tests of GitHub commit attribution behavior. Never resolve a reviewer, PR author, owner or initiator by the committer-only fallback.

## GII-08 — actor classification (assessment; no new trust grants)

| Actor/source | Current evidence | Permitted role |
| --- | --- | --- |
| GraphQL PR author `__typename=User`, positive `databaseId` | Concrete account identity, not independent proof of a human | Preparer; excluded from independent review |
| GraphQL linked commit author/committer/co-author `user.databaseId` | Linked account identity | Contributor; excluded |
| GraphQL null committer -> REST exact-SHA `committer.type=User`, positive `id` | GitHub-linked account for this immutable commit | **Exclusion-only** contributor |
| GitHub `web-flow` service User | REST type `User` may be service-owned | Contributor; never automatically eligible as a human reviewer |
| `Bot`, GitHub App, Dependabot, Actions, AI automation | Distinct actor semantics; commit trailers/email are not identity proof | No human reviewer/owner approval eligibility |
| Unknown, null, ambiguous, missing ID, inconsistent API metadata | No reliable numeric attribution | Fail closed |

**Security rationale:** GitHub API `User` is an account object type, not a verified human/personhood claim. Git signatures establish integrity/authenticity of the signed commit under the signing identity; they do not establish independence of an eligible human policy reviewer. The literal `Claude` trailer, GitHub noreply email or apparent bot name is untrusted commit text and cannot authorize an identity. GitHub-signed platform commits are not exempt from contributor accounting without separately approved evidence and governance.

**Options reviewed:**
- **A: classify platform actor by signed-commit metadata.** Useful as corroborating provenance; not sufficient to waive contributor exclusion.
- **B: REST exact-SHA reconciliation.** Keep current narrow committer-only approach and consistency checks; account ID is exclusion evidence, not human approval.
- **C: unresolved human actor.** Refuse qualification. Do not infer IDs from name/email or AI-generated trailers.

**Decision:** maintain the current fail-closed model. A future role-aware resolver may explicitly distinguish `contributor`, `preparer`, `reviewer`, `owner` and `workflow initiator`, with independent identity eligibility per role and authenticated provenance; do not deploy a generic fallback or allow service Users into the trusted human set.

## Verification and follow-up

Run `python3 -m unittest discover -s tests -p 'test_gii06_safe_rest_diagnostics.py' -v` plus existing custody and provisioner tests, final-head workflow checks and security review. GII-05 historical custody, GII-09 live proof, GII-11 typed resolver, GII-13 full negatives and GII-14 transport inventory remain open in issue #81. **No claim of complete #81 closure or protected-policy authorization is made here.**
