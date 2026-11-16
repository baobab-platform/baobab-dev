# ADR-DEV10-001: Reusable development-risk acceptance policy

| | |
|---|---|
| **Status** | Accepted for implementation; final risk approval pending a separate decision PR |
| **Date** | 2026-11-16 |
| **Owner** | Baobab Platform security-policy owner |
| **Repository** | `baobab-platform/baobab-dev` |
| **Related records** | Issue #54; PRs #62, #71 and #74; `docs/security/protected-artifact-risk-decisions.md` |

## 1. Context

The Ubuntu 26.04 package `linux-libc-dev=7.0.0-43.43` is reported by Trivy
0.73.0 with eight HIGH findings across the four development image profiles and
both supported Linux architectures. PR #74 scans are inventory evidence only;
they are not an approval or a release qualification.

The 12 November issue #54 amendment explicitly names PR #62 for the eight-CVE
treatment. It does not name PR #71. The 16 November independent review by
@sknabusiu confirmed that #62, not #71, is the relevant historical record and
marked the earlier #71 statement in #54 superseded. The older #62/#71
acceptance cannot be silently extended to PR #74 or later candidates.

The owner prefers reusable, expiry-bounded governance over hard-coded PR
numbers. On 16 November, @sknabusiu approved finalisation of that reusable
policy subject to a separate decision PR and exact-head independent approval.
@sdnabusiu supported finalisation while requiring the outstanding engineering
and governance controls described below. Neither review is itself the final
risk acceptance.

## 2. Decision

Implement one reusable development-only decision for the exact eight findings
below, with no PR-number allowlist:

- Repository: `baobab-platform/baobab-dev`
- Image repository: `ghcr.io/baobab-platform/baobab-dev`
- Environment: `development`
- Package: `linux-libc-dev=7.0.0-43.43`
- Findings: CVE-2022-50240, CVE-2025-40190, CVE-2026-68103,
  CVE-2026-72198, CVE-2026-74578, CVE-2026-89805, CVE-2026-98376,
  CVE-2026-98420; all HIGH, Ubuntu type
- Profiles: `final`, `frontend`, `frontend-e2e`, `infra`
- Architectures: `linux/amd64`, `linux/arm64`
- Expiry: `2026-11-26T00:00:00Z`

Execution is allowed only for same-repository `pull_request` events whose base
is `main` and whose merge ref is `refs/pull/<positive-number>/merge`, plus
`push` events on `refs/heads/main`. The pull-request head repository must be
`baobab-platform/baobab-dev`.

Fork PRs, other base branches, tags, releases, workflow dispatch, schedules,
deployments, staging and production are excluded. New or changed findings,
fixed-version signals, secrets, missing inventory, scanner errors or a
different package/version remain blocking. Partial remediation may reduce the
observed findings to a subset of this exact approved inventory; it cannot add
or redefine a finding.

## 3. Approval and identity model

The final decision lives at
`security/decisions/development/foundation.json` and is introduced by a
separate pull request to `main`. The decision records the preparer's login as
display metadata and the preparer's immutable numeric GitHub user ID. Its
`approval_evidence` points to the exact decision PR.

The custody verifier must establish all of the following from GitHub API
evidence:

1. The decision PR is merged into `main` and changed the selected decision
   file.
2. The PR author's numeric GitHub ID equals the recorded preparer ID.
3. The latest effective `APPROVED` review is on the exact merged head and the
   reviewer resolves to an independently provisioned trusted numeric ID.
4. The reviewer ID is neither the PR author nor an author, co-author or
   committer of any commit in the complete PR history.
5. Every commit and every author/co-author/committer identity is enumerated.
   GraphQL author connection counts must match the returned nodes; unresolved
   identities, incomplete history and malformed IDs fail closed.

The configured `DEV10_SECURITY_APPROVER_LOGINS` values are used only to
resolve the trusted reviewers to numeric GitHub IDs. Login and email are not
identity comparison keys. A GitHub service account is not silently excluded:
if its numeric identity appears as a committer, it is included in the
contributor set.

The actual GitHub review ID, reviewer numeric ID and `submitted_at` timestamp
are derived from the effective review at runtime. They are not embedded in the
decision document, avoiding a self-referential timestamp or approval ID in the
bytes that the reviewer must approve. The decision PR approval is therefore
bound to the exact final file contents and current head.

## 4. Trust anchor and activation

The policy SHA-256 is computed over the exact final bytes of the merged
`foundation.json`. The separately controlled
`DEV10_PROTECTED_DECISION_SHA256` repository variable is provisioned only
after the decision PR is merged and custody verification succeeds. The
proposal file is never hashed as an authority.

The policy remains inactive while the active file, exact hash, trusted
reviewer configuration or custody evidence is missing. The decision PR may
contain the proposed final record, but it has no enforcement effect before
merge and trust-anchor provisioning.

## 5. Expiry and execution are separate controls

The expiry governs how long the residual-risk decision remains valid. The
event/ref/base/repository checks govern where it can execute. Both checks are
mandatory on every scan. A future expiry does not authorize a tag, fork,
different base branch or deployment; a permitted branch context does not
extend the expiry. There is no silent renewal.

The `dev10-security-policy-read` environment must require the configured
human reviewers and permit the `main` branch plus the
`refs/pull/*/merge` deployment-ref pattern. GitHub matches environment
deployment branch rules against `GITHUB_REF`; a protected-main-only rule does
not admit pull-request merge refs. Any temporary feature-branch rule is
removed after PR #74 qualification. A blanket wildcard is prohibited.

## 6. Release separation

This development decision grants no release-tag, publication, signing,
attestation, promotion, staging or production authority. Release qualification
continues to require exact OCI child-manifest digests, signatures,
SBOM/provenance, independent release decisions, RC-to-GA digest continuity and
the protected promotion process. GA must reuse qualified RC digests; it must
not rebuild.

## 7. Bootstrap and governance

The separate decision PR must pass its required checks and receive an
independent approval on its exact final head. Any administrator bypass must be
attributable and recorded with the administrator identity, exact commit,
reason and checks bypassed. A broad or undocumented bypass is not acceptable.

Default-branch review protection, code-owner enforcement, latest-push approval,
the security team's repository permission, environment branch rules and the
trust-anchor administration path must be verified by an authorized
administrator. Their configuration must not be inferred from CODEOWNERS or a
successful workflow run.

## 8. Consequences and deferred work

The reusable policy removes PR-number hard-coding and avoids repeated human
approval for every matching development PR. It also creates a strict,
time-limited dependency on GitHub review history and numeric contributor
enumeration; missing API identity data blocks the scan.

The current promotion workflow also consumes the single
`DEV10_PROTECTED_DECISION_SHA256` trust anchor for tag/target decision files.
That one hash cannot authenticate a distinct development decision and one or
more separate release decisions concurrently. No release decision file is
currently active; release residual findings therefore remain blocking unless
a separately approved release trust mechanism is implemented. A versioned
multi-decision registry or separate release trust anchor is deferred to a
later increment and must not be approximated by reusing development authority.

PR #74 is unusually large (383 commits and 92 changed files); future work
should be split into smaller, independently reviewable increments without
weakening these controls.
