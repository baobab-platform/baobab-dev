# DEV-10 protected, artifact-bound security decisions

Status: reusable policy implementation is under review on PR #74; @sknabusiu approved finalisation subject to a separate decision PR; final policy approval and activation are still pending.
This change issues no new risk acceptance and does not qualify PR #74.

## Decision model

PR numbers are review-container identifiers, not vulnerability-risk identities.
A reusable risk-policy decision scopes the exact CVE, package ecosystem/type, installed version
and severity; GHCR image repository; permitted profiles and architectures;
development-only environment; the preparer's numeric GitHub user ID; the merged
decision-PR reference; expiry and revocation state. The effective approver's
numeric ID, GitHub review ID and submitted timestamp are derived from the
current effective review at runtime, not embedded in the policy bytes.

The policy deliberately does not enumerate candidate image digests. That
allows later PRs to be evaluated automatically when their actual findings
remain within the same approved package/CVE and operating-context boundary.

Every successful evaluation is nevertheless bound to the exact image repository,
child-manifest digest, profile, architecture, Trivy version and raw-report
SHA-256. That output is qualification evidence for that artifact, not release
authorization. Existing signature, SBOM, provenance, digest-continuity and
protected RC-to-GA promotion controls remain mandatory.

## Implementation

The reusable evaluator validates the Trivy report schema and scanner version,
exact GHCR digest, actual image architecture, policy scope, CVE/package/version/
severity identities, numeric maker/checker separation (decision-PR author ID
versus the selected trusted reviewer ID), expiry and revocation. A clean
scan needs no risk decision. A subset of approved findings is permitted after
partial remediation; every new or changed finding and any fixed-version signal
is denied.

The protected qualification workflow uses checksum-verified Trivy 0.73.0,
scans the exact remote GHCR child digest and uploads only sanitized evidence.
The raw Trivy report is never uploaded because secret findings can contain
matched credential material.

## Approval custody

The policy SHA-256 is a trust anchor, not a hash supplied by the candidate PR.
The DEV10_PROTECTED_DECISION_SHA256 repository variable must be maintained
only by the designated security-policy custodian after verifying the protected
decision record and independent approval. An approved_by string or evidence
URL is not, by itself, authentication.

The policy file must live on the default branch under
security/decisions/. CODEOWNERS assigns the protected decision and security
documentation paths to the individually requestable accounts @sknabusiu and
@sdnabusiu; general/platform ownership is assigned to @bjnabs. The repository
does not currently have a GitHub Teams subscription, so unavailable team
slugs are not listed as owners. The approval_evidence field must point to the
merged pull request that introduced the exact decision file. The custody verifier selects the latest effective
APPROVED review on that merged head whose immutable numeric GitHub user ID is
trusted and is neither the PR author nor an author, co-author or committer of
any commit in the PR. It enumerates the complete PR commit history through
GraphQL, checks every commit's author/co-author and committer identity, and
fails closed if an identity or author connection cannot be resolved. Logins
are used only to resolve the configured allowlist and display audit labels;
they are never used for identity comparison. The review ID and submitted_at
timestamp are emitted from GitHub API evidence at runtime, avoiding a
self-referential approval timestamp in the bytes being approved.

CODEOWNERS is advisory until branch protection enforces it. GitHub
rejected the unavailable `security` and `platform-engineering` team slugs,
so the repository uses individually requestable owners instead. The current
compensating process is:

1. Request @sknabusiu and @sdnabusiu on every PR that changes the protected
   decision, security assessment or security-policy documentation paths.
2. Before merge, verify the latest effective review is APPROVED on the exact
   current PR head, and verify the reviewer numeric ID is independent of the
   PR author and every commit author, co-author and committer.
3. Verify all required CI checks on that same head and record the review and
   check evidence in the PR conversation.
4. Merge only after the checks and independent review are confirmed. After
   merge, run the custody verifier against the merged decision PR before
   provisioning the exact-byte trust anchor.

The current subscription does not provide enforceable default-branch
protection. This manual process is auditable but cannot technically prevent a
sufficiently privileged user from bypassing it. Do not describe CODEOWNERS or
a green workflow as a branch-protection substitute. The preparer and selected
reviewer must remain different numeric GitHub principals. Trust-anchor
provisioning remains a separate, attributable custodian operation.

Development PR/main image scans run without a manual-review environment pause
so that vulnerability evidence is collected immediately. This does not
authorize residual findings: the active decision, exact SHA-256, trusted
reviewer identity and merged custody must all verify, or the evaluator fails
closed. The release-promotion job retains its separate protected environment
and human approval. Environment approval is not a substitute for an
independently approved release decision.
A per-candidate GitHub environment approval is intentionally not used: it
would turn routine artifact qualification into a repeated human gate. Human
approval belongs to the risk-policy decision, not every subsequent matching PR.

## Current authorization, reviewer disposition and activation state

The 12 November issue #54 amendment explicitly names **PR #62** for the eight
HIGH findings on `linux-libc-dev=7.0.0-43.43`; it does not name PR #71.
@sknabusiu's 16 November independent review confirms that the eight findings
belong to #62, not #71, and marks the earlier #71 statement in #54 superseded.
The earlier v1.5.0–v1.5.1 acceptance is not transferable to this policy. PR #74
is inventory and implementation evidence, not the source of risk authority.

On 16 November at 12:35 UTC, @sknabusiu approved **finalisation** of the
reusable development-risk policy, subject to a separate decision PR, exact-head
independent approval, owner concurrence, decision-PR bootstrap checks and
numeric contributor-independence verification. This was explicitly **not**
the final policy approval and was not an instruction to unblock CI.
@sdnabusiu supported finalisation at 12:44 UTC but stated PR #74 was not ready
to merge until the outstanding engineering and governance conditions pass.

The separate decision PR #76 contains the final candidate record and contract test. Owner concurrence is recorded by @bjnabs in PR comment #6924572973. @sknabusiu and @sdnabusiu have been requested to review the latest CODEOWNERS/ADR revision. The earlier formal approval predates those edits and is not treated as current-head approval; a fresh independent approval is still required.

The proposed policy is reusable across same-repository pull requests targeting
`main` and pushes to `refs/heads/main`, with exactly the eight HIGH findings,
four profiles, two architectures and expiry **2026-11-26T00:00:00Z**. Fork
PRs, other PR base branches, tags, releases, workflow dispatch, schedules,
deployments, staging and production are excluded. The risk-validity clock
(expiry) and execution boundary (event/ref/base/repository) are independent
controls; both must pass on every evaluation.

The Foundation and Publish workflows fail closed when the active decision,
trust anchor or reviewer configuration is unavailable. No active
`security/decisions/development/foundation.json` or trust-anchor value has
been provisioned. The eight findings are therefore **not yet accepted**.
PR #74 has no PR-number-specific risk exception, no VEX `not_affected` claim,
no Trivy suppression, no remediation claim and no release waiver.

Release publication and promotion remain separate. PR-triggered runs do not
establish final RC publication or RC-to-GA digest continuity. The existing
exact-digest, signature, SBOM/provenance and promotion gates must be qualified
independently; development policy must never authorize a release tag or
promotion.

## Activation prerequisites

1. Create the separate decision PR with the final `foundation.json` and this exact schema. Record owner concurrence and the #62/#71 reconciliation in the PR. Obtain a current trusted independent approval on its exact head; the decision PR must pass its required checks. Any admin bypass must be explicitly attributable and recorded with reason, commit and bypassed checks.
2. Follow the documented individual-review/manual-merge protocol because enforceable branch protection is unavailable on the current subscription. Verify current-head approval, numeric contributor independence and all CI checks; record the evidence in the PR. This is a compensating process, not technical prevention of privileged bypass.
3. Verify the decision PR is merged to `main`; the custody verifier must confirm the PR author/preparer numeric ID, a current trusted independent reviewer, complete commit-author/co-author/committer enumeration, changed decision path and exact merged-head approval.
4. Only after the final approved `foundation.json` is merged and custody verification passes, compute its exact lowercase SHA-256 and provision `DEV10_PROTECTED_DECISION_SHA256` through the separately controlled repository-variable administration path. Never hash the proposal.
5. Rerun Foundation, locked onboarding and all eight Publish profile/architecture scans. Development scans run without a manual environment pause; the evaluator still denies tags, dispatch, schedules, forks and wrong-base PRs. Keep the separate release-promotion environment protected.
6. Keep exact-digest release qualification, signatures, SBOM/provenance, digest continuity and protected promotion independent.

## Operating objective

The intended normal human actions remain: update config/versions.yaml,
review new or changed security findings, and approve/reject bounded risk
decisions when necessary. Clean scans and later candidate builds matching an
active approved policy require no repeated risk approval. Genuine remediation,
compatibility and governance exceptions still require engineering intervention.

## Upstream contracts consulted

- Trivy JSON reporting documents SchemaVersion, ArtifactType, RepoDigests and
  ImageConfig architecture metadata used to bind scan evidence:
  https://trivy.dev/docs/dev/guide/configuration/reporting/
- GitHub CODEOWNERS documentation requires teams to be visible and have
  explicit repository write permission, and uses the base branch's CODEOWNERS
  file for pull-request review requests:
  https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners
- GitHub deployment-environment documentation confirms deployment branch rules
  are matched against `GITHUB_REF` and that `refs/pull/*/merge` allows
  pull-request workflows:
  https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- GitHub protected-branch documentation describes required code-owner reviews,
  stale-review dismissal and approval of the latest reviewable push:
  https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
