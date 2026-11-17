# ADR-DEV10-001: Reusable development-risk acceptance policy

| | |
|---|---|
| **Status** | Accepted for implementation; final risk approval pending a separate decision PR |
| **Date** | 2026-11-16 |
| **Owner** | Baobab Platform security-policy owner |
| **Repository** | `baobab-platform/baobab-dev` |
| **Related records** | Issue #54; PRs #62, #71, #74 and #76; `docs/security/protected-artifact-risk-decisions.md` |

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
contributor set. If GraphQL returns a null `GitActor.user` for a committer,
the verifier may reconcile that one identity against the REST commit endpoint
for the exact same immutable commit SHA. It must require the REST response SHA
to equal the requested commit SHA and the REST committer to have type `User`
with a positive immutable numeric ID. Name, email and timestamp are Git-object
presentation metadata, not identity keys; comparing their serialized forms
across REST and GraphQL adds false-negative failure modes without strengthening
the exact-object check. A missing REST identity, wrong SHA, non-User actor,
malformed response or API error remains fatal. This is exact-object identity
resolution, not a login/email-based identity match or a service-account
exclusion.

The actual GitHub review ID, reviewer numeric ID and `submitted_at` timestamp
are derived from the effective review at runtime. They are not embedded in the
decision document, avoiding a self-referential timestamp or approval ID in the
bytes that the reviewer must approve. The decision PR approval is therefore
bound to the exact final file contents and current head.

## 4. Trust anchor and activation

The policy SHA-256 is computed over the exact final bytes of the merged
`foundation.json`. The separately controlled
`DEV10_PROTECTED_DECISION_SHA256` repository Actions variable is provisioned
by the explicit `Provision DEV-10 development risk policy` workflow. The
workflow is manual-dispatch-only and runs from `main`. It first pauses at the
existing `dev10-security-policy-read` environment for human approval; that
job receives no provisioning credential. Only after that gate succeeds does
the provisioning job enter the separate `dev10-security-policy-provision`
environment. That environment is the sole location for
`DEV10_POLICY_PROVISIONER_TOKEN`, and only the provisioning job references
it. Configure its deployment branch policy to allow `main` only, and move
the existing fine-grained token secret out of
`dev10-security-policy-read` into this dedicated environment. The workflow
also checks that it is running in the canonical repository on `refs/heads/main`.
It requires the exact decision-PR head SHA as a dispatch input.

The fine-grained token is restricted to this repository with `Variables:
read/write`, `Contents: read`, `Pull requests: read`, `Issues: read` and
`Metadata: read`. Repository variables require the distinct `Variables`
permission; the workflow `GITHUB_TOKEN` permission model does not provide
that permission, so substituting `Actions: write` would not authorize this
write. Ensure `DEV10_SECURITY_APPROVER_LOGINS` is available to the new
provisioning job as a repository variable or as a variable on the dedicated
provisioning environment; an environment-scoped variable on the approval-only
environment is not inherited. The token is never printed or written to an artifact. A short-lived
GitHub App installation token would be preferable, but no configured
repository app/token issuer is part of this accepted implementation; that
migration is deferred rather than represented as complete. The configured
`DEV10_SECURITY_APPROVER_LOGINS` variable resolves trusted reviewer logins to
immutable numeric GitHub IDs.

Before changing the repository variable, the provisioner verifies that the
decision PR is merged into `main`, the PR head equals the explicitly supplied
SHA, the PR author numeric ID matches `prepared_by_id`, the PR changed the
selected decision file, and the current effective APPROVED review is on that
exact head by a trusted numeric reviewer who is independent of the PR author
and every author/co-author/committer in the complete GraphQL commit history.
It also verifies that the approved PR-head file bytes equal the current
`main` file bytes and that the PR merge commit is an ancestor of `main`.
Only then does it hash the exact bytes.

Provisioning is create-only and idempotent: if the variable is absent, it is
created; if it already contains the same hash, the operation succeeds without
changing it; if it contains a different hash, provisioning fails and never
overwrites it. The workflow records a non-secret receipt containing the hash,
decision PR/head/merge commit, reviewer numeric ID, review ID and approval
timestamp. The proposal file is never hashed as an authority.


The provisioner also verifies attributable owner concurrence on this exact
decision PR from the accountable owner's immutable numeric GitHub ID
(49340314), rather than trusting the PR description. The comment must be
created and last edited before merge; the receipt records its ID and
timestamp. This is an accountability/attribution record, not an independent
approval and not a substitute for the trusted reviewer check. The preparer
login is display metadata; the numeric preparer ID is the identity key, so
account renames do not break custody verification.
The policy remains inactive while the active file, exact hash, trusted
reviewer configuration, dedicated environment credential, token permissions
or custody evidence is missing. The decision PR carries `record_type: proposed_approved_form` to
distinguish the candidate record from an effective decision. Its
`status: approved` expresses the intended decision state only; no operator or
workflow may treat that field alone as proof of approval or activation.
Effectiveness requires the merged file, current independent review, verified
custody and exact-byte trust-anchor provisioning.

## 5. Expiry and execution are separate controls

The expiry governs how long the residual-risk decision remains valid. The
event/ref/base/repository checks govern where it can execute. Both checks are
mandatory on every scan. A future expiry does not authorize a tag, fork,
different base branch or deployment; a permitted branch context does not
extend the expiry. There is no silent renewal.

Development PR and main-push vulnerability scans do not use a
manual-review environment gate. That gate delayed evidence collection but did
not authenticate the risk decision. Scans therefore run immediately; residual
findings still fail closed unless the active decision file, exact repository
SHA-256 trust anchor, trusted reviewer identities and merged custody all
verify. Removing the pause does not authorize the findings or weaken the
evaluator.

The separate release-promotion job retains its protected environment and
human approval. Environment approval is an execution/access control, not a
substitute for an independently approved, exact-digest release decision.
A broad deployment-ref wildcard is prohibited.

## 6. Release separation

This development decision grants no release-tag, publication, signing,
attestation, promotion, staging or production authority. Release qualification
continues to require exact OCI child-manifest digests, signatures,
SBOM/provenance, independent release decisions, RC-to-GA digest continuity and
the protected promotion process. GA must reuse qualified RC digests; it must
not rebuild.

## 7. Bootstrap and governance

The separate decision PR must pass its required checks and receive an
independent approval on its exact final head. The shared Foundation workflow
continues to run its full profile on every event; no Foundation security,
baseline, reproducibility, runtime or environment gate is disabled for this
policy PR. The additional unfiltered Foundation image CVE scan runs when a PR
changes container build inputs (`.devcontainer/`, `config/`, the scripts
explicitly consumed by the Dockerfile), the repository's shared scanner-policy
manifest (`.baobab/repository.yaml`), or the kernel inventory. The
custodian-only `scripts/provision_protected_risk_policy.py` and
`scripts/custody_independence.py` are not copied or executed by the image and
are explicitly excluded from the image-scan triggers;
its provisioning contract is tested by the policy workflow. A policy-only PR
does not claim an image scan passed; decision JSON and proposal records are
validated against the pinned Draft 2020-12 schema, including negative
fixtures. Any PR changing image inputs still runs the full image scan and must
satisfy the active exact risk policy. PR #74's Foundation/Publish qualification
remains mandatory after this decision is merged and activated. Any administrator bypass must be
attributable and recorded with the administrator identity, exact commit,
reason and checks bypassed. A broad or undocumented bypass is not acceptable.

The repository does not currently have a GitHub Teams subscription, and
GitHub rejected review requests for the `security` and
`platform-engineering` team slugs because those teams are not recognized as
repository collaborators. The CODEOWNERS file therefore uses individually
requestable accounts only: `@bjnabs` for general/platform ownership and
`@sknabusiu` plus `@sdnabusiu` for security-sensitive paths. Explicit
ownership entries cover `/security/decisions/`, `/docs/assessments/`,
`/docs/security/` and this ADR. Do not add unavailable team slugs as owners.

CODEOWNERS is still advisory until branch protection enforces code-owner
reviews. With the current subscription, the compensating procedure is:
(1) request the named individual reviewers on every PR touching an owned path;
(2) before merge, verify the latest effective review is APPROVED on the exact
current head, and verify reviewer numeric identity is independent of the PR
author and all commit contributors; (3) verify all required CI checks on that
same head; (4) record the decision and evidence in the PR conversation; and
(5) only then use the normal merge operation. The existing reviewer-independence
audit and protected-decision custody verifier provide machine-verifiable
evidence for the security-sensitive path. This process is not an equivalent
technical prevention mechanism: a repository user with direct write/merge
authority can bypass it while branch protection is unavailable. The limitation
must remain visible in audit records, and unauthorized direct updates to
`main` must be detected by the repository's push-triggered verification and
reviewed immediately.

No Enterprise-only feature is assumed. Individual reviewer requests, Actions,
CODEOWNERS syntax, immutable commit IDs, exact-head review evidence and
repository-local scripts are the available controls.

## 8. Consequences and deferred work

The reusable policy removes PR-number hard-coding and avoids repeated human
approval for every matching development PR. It also creates a strict,
time-limited dependency on GitHub review history and numeric contributor
enumeration; missing API identity data blocks the scan.

The release-promotion workflow no longer consumes
`DEV10_PROTECTED_DECISION_SHA256` or the development custody verifier.
Development risk acceptance cannot authorize release tags or promotion. The
current release scan path has no release-decision waiver inputs; any residual
HIGH/CRITICAL finding remains blocking until a separate release-specific
schema, custody verifier and independently provisioned trust anchor are
implemented. The separate release trust mechanism is deferred and must not be
approximated by reusing development authority.

PR #74 is unusually large (383 commits and 92 changed files); future work
should be split into smaller, independently reviewable increments without
weakening these controls.
