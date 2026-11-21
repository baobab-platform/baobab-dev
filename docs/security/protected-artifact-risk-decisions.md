# DEV-10 protected, artifact-bound security decisions

PR #76 merged the eight-finding development decision. The scan and
provisioning paths verify its exact bytes independently. Release authority
requires its own qualification.

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

The local development scan receipt records the source commit, image config
digest, profile, architecture, Trivy version and raw-report SHA-256. A scan of
a Docker archive records the archive's SHA-256 as well. The separate registry
qualification path uses the remote OCI child-manifest digest. Releases require
signature, SBOM, provenance, digest continuity and protected promotion.

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
The `DEV10_PROTECTED_DECISION_SHA256` repository Actions variable is
written only by the manual `Provision DEV-10 development risk policy`
workflow. The workflow runs from `main` behind the existing
`dev10-security-policy-read` environment approval and requires an explicit
expected decision-PR head SHA. An `approved` status, `prepared_by` string or
evidence URL is not, by itself, authentication.

The provisioner verifies the merged PR, exact head, author/preparer numeric
identity, changed decision path, latest effective exact-head APPROVED review,
trusted reviewer numeric ID distinct from the accountable owner, complete
commit author/co-author/committer independence and attributable concurrence
from numeric owner ID 49340314
(created and last edited before merge), merge ancestry and byte-for-byte
equality between the approved PR-head file and current main. It hashes the
exact current main bytes only after those checks. The variable is create-only
and idempotent: the same hash is accepted, but a different existing hash is
never overwritten.

The workflow uses an environment-scoped fine-grained token named
`DEV10_POLICY_PROVISIONER_TOKEN` with repository permissions limited to
Variables read/write, Contents read, Pull requests read, Issues read and Metadata read.
The token is not a workflow artifact or log output. The run records a
non-secret provisioning receipt with the decision PR/head/merge commit, exact
SHA-256 and reviewer evidence.

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

## Decision history and audit of 21 November 2026

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

The merged decision PR #76 contains the eight-finding record. The linked
Publish run verified owner comment 6924572973 and the effective approval
5932308847 from independent reviewer ID 356900102 on the exact decision head.

The proposed policy is reusable across same-repository pull requests targeting
`main` and pushes to `refs/heads/main`, with exactly the eight HIGH findings,
four profiles, two architectures and expiry **2026-11-26T00:00:00Z**. Fork
PRs, other PR base branches, tags, releases, workflow dispatch, schedules,
deployments, staging and production are excluded. The risk-validity clock
(expiry) and execution boundary (event/ref/base/repository) are independent
controls; both must pass on every evaluation.

The audited `main` revision `bc6ca0a` still invokes the legacy scanner gate.
PR #74 at `513d53d` already uses the protected branch policy in Foundation and
Publish. In [Publish run 44858283649](https://github.com/baobab-platform/baobab-dev/actions/runs/44858283649),
all eight profile and architecture scans found 30 exact advisories (27 HIGH,
3 CRITICAL) for `linux-libc-dev=7.0.0-44.44`. The retained inventory adds
`CVE-2026-99312` and `CVE-2026-99317` to the 28-finding assessment. The linked
final/amd64 job verified custody, then denied the scan because #76 covers eight
HIGH findings for `7.0.0-43.43`. The proposed 12-finding decision in #92 also
uses the older kernel-header version. The linked build, database checks and
native runtime qualification completed. The scan denial blocks qualification.

Release publication and promotion remain separate. PR-triggered runs do not
establish final RC publication or RC-to-GA digest continuity. The existing
exact-digest, signature, SBOM/provenance and promotion gates must be qualified
independently; development policy must never authorize a release tag or
promotion.

## Activation prerequisites

1. Create the separate decision PR with the final `foundation.json` and this exact schema. Record owner concurrence and the #62/#71 reconciliation in the PR. Obtain a current trusted independent approval on its exact head; the decision PR must pass its required checks. Any admin bypass must be explicitly attributable and recorded with reason, commit and bypassed checks.
2. Follow the documented individual-review/manual-merge protocol because enforceable branch protection is unavailable on the current subscription. Verify current-head approval, numeric contributor independence and all CI checks; record the evidence in the PR. This is a compensating process, not technical prevention of privileged bypass.
3. Verify the decision PR is merged to `main`; the custody verifier must confirm the PR author/preparer numeric ID, a current trusted independent reviewer, complete commit-author/co-author/committer enumeration, changed decision path and exact merged-head approval.
4. Configure the fine-grained `DEV10_POLICY_PROVISIONER_TOKEN` with Variables read/write, Contents read, Pull requests read, Issues read and Metadata read. Store it in `dev10-security-policy-provision`. The preceding `dev10-security-policy-read` environment supplies human approval without access to the credential.
5. After merge, dispatch `Provision DEV-10 development risk policy` from `main`, supplying the exact approved PR head SHA. The workflow independently verifies merged custody and exact file bytes, computes the lowercase SHA-256, creates the repository variable only if absent, and records a non-secret receipt. It refuses a different pre-existing hash. Never hash the proposal.
6. Rerun Foundation, locked onboarding and all eight Publish profile/architecture scans. Development scans run without a manual environment pause; the evaluator still denies tags, dispatch, schedules, forks and wrong-base PRs. Keep the separate release-promotion environment protected.
7. Keep exact-digest release qualification, signatures, SBOM/provenance, digest continuity and protected promotion independent.

## Review a blocking development scan

Open the Foundation or Publish job summary and locate the evidence artifact
for its profile, architecture, commit and run attempt. `gate-result.json`
records the gate outcome and any verified custody. `findings.json` records
the unwaived HIGH/CRITICAL vulnerability inventory. The raw scanner output
and the full image configuration stay on the runner.

| Outcome | Operator action |
| --- | --- |
| Clean | The complete scan reported no blocking findings. |
| Covered | The receipt records the active development decision and verified approval. |
| Inventory changed | Open the prefilled owner-review issue from the job summary. Use the attached `risk-review-request.json` to start per-finding dispositions. |
| Remediation required | Investigate secret findings, available fixes or unsupported advisory identities. |
| Awaiting owner concurrence | Obtain attributable concurrence on the dedicated decision PR. |
| Awaiting independent approval | Obtain a current trusted independent approval on that PR's exact head. |
| Awaiting activation | Reconcile the decision bytes and the protected hash via the provisioning procedure. |
| Decision inactive | Resolve expiry, revocation or pending approval with a new scoped decision. |
| Outside development scope | Remediate the findings under the scan's applicable policy. |
| Technical scan failure or policy verification failure | Repair the reported scanner, evidence, configuration or custody problem and rerun. |

The issue form links the scan attempt and review-request hash. A repository
operator submits it to notify the owner. Each review row starts pending.
Record applicability and uncertainty, evidence references, available fixes,
compensating controls and the proposed expiry before drafting a decision PR.
The repository's current schema and create-only provisioner limit activation
to the governed eight- or twelve-finding records. A different inventory
requires its own reviewed policy amendment and activation procedure.

After activation, run qualification from a source revision containing the
verified decision bytes and the supported scan workflows. GitHub's rerun
uses the original source SHA, so an older snapshot may require a new PR run
after updating its base. Keep the previous attempt for evidence comparison.

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
