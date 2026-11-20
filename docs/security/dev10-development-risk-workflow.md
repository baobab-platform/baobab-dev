# DEV-10 development vulnerability acceptance — minimal operating procedure

Baobab-dev builds **internal development environments**, not application staging or production deployments.

## Normal release path

1. Update `config/versions.yaml`; let the existing resolver and CI enforce the lock.
2. Review the actual Trivy findings. If there are **no findings** or only exact, previously accepted findings **within the current time-bounded decision**, CI may proceed without an additional per-PR security approval. If the findings change, an authorized human reviewer independent of the PR author must explicitly approve a narrowly scoped security decision (or the engineer must remediate) before changing the risk inventory/decision and rerunning CI.
3. After existing Foundation/Publish checks and independent release controls pass, use the established GHCR publication flow. No automatic publication from an ordinary PR.

## Reusable future-PR qualification — proposed, not yet active

The protected policy implementation is being prepared to reuse one approved decision across eligible future pull requests. Eligibility is not inferred from a PR number: the GitHub event must be `pull_request`, the merge ref must match `refs/pull/<positive-number>/merge`, and the PR base branch must be `main`. Post-merge development CI may reuse the same decision only for `push` to `refs/heads/main`.

The proposed amendment is bounded to the exact 12 HIGH findings: 11 Ubuntu `linux-libc-dev=7.0.0-43.43` advisories (the original eight plus CVE-2026-98869, CVE-2026-98890 and CVE-2026-99083) and one `node-pkg` picomatch 4.0.5 advisory (CVE-2026-112366). It covers all four image profiles, both supported Linux architectures, this repository/image repository, and expiry **2026-11-26 00:00 UTC**. It is not PR-number-bound. New/changed findings, package/version/severity drift, fixed-version signals, secrets, incomplete scan inventory, or scanner errors remain blocking.

The PR contains a proposed approved-form record (`record_type: proposed_approved_form`). Its JSON `status: approved` is the intended decision content, not evidence of effective approval. The policy is **not active** until the exact record is merged, an independent current-head approval and owner concurrence are verified, custody is proven, and the protected exact-byte SHA-256 trust anchor is provisioned. It cannot authorize tags, releases, workflow dispatch, schedules, deployments, PRs targeting another branch, staging or production. Release qualification and promotion remain separate controls.

The decision preparer is bound by immutable numeric GitHub user ID to the decision-PR author. Trusted reviewer logins are resolved through the Users API and must resolve to typed `User` accounts with positive numeric IDs; duplicate IDs in the configured list are rejected. The custody verifier selects a current effective approval only when the exact-head review actor is also typed `User`, is in the trusted numeric-ID allowlist, is not the PR author, and has not authored, co-authored or committed any commit in the decision PR. Bot reviews cannot qualify. GitHub's `User` type does not prove a natural-person identity; the trusted allowlist is a manually governed appointment. It enumerates the complete commit history through GraphQL and fails closed on unresolved identities. Login and email are not identity keys. The GitHub review ID and submitted timestamp are derived from API evidence at runtime; they are not embedded in the bytes being approved.

Risk validity is expiry-based; execution authorization is branch/event-based. The policy is usable only while unexpired **and** only for same-repository pull requests targeting `main` or pushes to `refs/heads/main`. A valid expiry never grants authority to another branch, tag, release or deployment, and a valid branch context never extends expiry.

The trust anchor `DEV10_PROTECTED_DECISION_SHA256` is a repository-level Actions variable created by the provisioning workflow through the repository Variables API; it is not an environment-level variable. `DEV10_SECURITY_APPROVER_LOGINS` is also supplied as a repository-level Actions variable so the Foundation and Publish pull-request jobs can resolve the trusted reviewer allowlist without referencing a protected environment. These values are non-secret configuration, not credentials. Their presence alone grants no authority: every scan still verifies the exact policy bytes, current GitHub approval custody, numeric maker-checker separation, repository, event, ref, base branch, findings and expiry.

The `dev10-security-policy-read` environment is used only by the manual provisioning workflow's human-authorization job on `main`; it is not referenced by routine Foundation or Publish scan jobs. The separate `dev10-security-policy-provision` environment holds the fine-grained provisioning token and is referenced only by the provisioning job. This separation avoids a manual environment pause on every eligible PR while keeping the write credential isolated from candidate code. The environment restrictions and required reviewers must be administrator-verified rather than inferred.

The decision record, independent review, custody verifier, protected default-branch controls and exact policy hash must all agree before the trust anchor is provisioned.


The 12-finding amendment candidate is in the separate PR
https://github.com/baobab-platform/baobab-dev/pull/92. It remains draft and is
not active. Fresh independent approval on its exact head and attributable
accountable-owner concurrence are still required; merge, custody verification
and exact-byte trust-anchor provisioning remain separate activation steps.

## Foundation bootstrap and image-scan applicability

The shared Foundation reusable workflow remains on its **full profile** for
all PRs; baseline, reproducibility, runtime, environment and security gates are
not disabled for the decision PR. The additional unfiltered DEV-10 image scan
runs when container build inputs change (`.devcontainer/`, `config/`,
Dockerfile-consumed scripts), the shared scanner-policy manifest
(`.baobab/repository.yaml`) changes, or either the historical kernel inventory or expanded 298-CVE audit inventory changes. The Publish workflow also runs its full four-profile by two-architecture matrix when the 298-CVE inventory, Canonical status input, protected decision schema/record or decision evaluator changes. The
custodian-only `scripts/provision_protected_risk_policy.py` is not an image
input and is explicitly excluded from the image-scan trigger; its tests run in
the dedicated policy-contract workflow. A policy-only decision PR does not
alter image inputs, so the DEV-10 image rebuild is not applicable; risk-gate
negative tests still run and the policy workflow validates the proposal and
decision against the pinned Draft 2020-12 schema. No image scan pass is claimed
for that path. The shared Foundation container job remains in the full profile and
builds/validates the image and SBOM, but its Trivy install/scan steps are
skipped under the separately governed `container-scan` implementation
exception, which PR #65 aligned to the 2026-11-26 sunset. This is not an
image-scan pass. That exception is not the reusable DEV-10 decision and
cannot authorize release. No image CVE scan is claimed for a policy-only PR;
current-head PR #74 requalification and all eight Publish scans remain
required before policy activation/release. Any PR changing image inputs must run the unfiltered DEV-10 scan, and
the eight Publish profile/architecture scans remain mandatory for release
qualification.
