# DEV-10 development vulnerability acceptance — minimal operating procedure

Baobab-dev builds **internal development environments**, not application staging or production deployments.

## Normal release path

1. Update `config/versions.yaml`; let the existing resolver and CI enforce the lock.
2. Review the actual Trivy findings. If there are **no findings** or only exact, previously accepted findings **within the current time-bounded decision**, CI may proceed without an additional per-PR security approval. If the findings change, an authorized human reviewer independent of the PR author must explicitly approve a narrowly scoped security decision (or the engineer must remediate) before changing the risk inventory/decision and rerunning CI.
3. After existing Foundation/Publish checks and independent release controls pass, use the established GHCR publication flow. No automatic publication from an ordinary PR.

## Reusable future-PR qualification — proposed, not yet active

The protected policy implementation is being prepared to reuse one approved decision across eligible future pull requests. Eligibility is not inferred from a PR number: the GitHub event must be `pull_request`, the merge ref must match `refs/pull/<positive-number>/merge`, and the PR base branch must be `main`. Post-merge development CI may reuse the same decision only for `push` to `refs/heads/main`.

The proposed policy is bounded to the exact eight HIGH Ubuntu findings for `linux-libc-dev=7.0.0-43.43`, all four image profiles, both supported Linux architectures, this repository/image repository, and expiry **2026-11-26 00:00 UTC**. It is not PR-number-bound. New/changed findings, package/version/severity drift, fixed-version signals, secrets, incomplete scan inventory, or scanner errors remain blocking.

The PR contains a proposed approved-form record (`record_type: proposed_approved_form`). Its JSON `status: approved` is the intended decision content, not evidence of effective approval. The policy is **not active** until the exact record is merged, an independent current-head approval and owner concurrence are verified, custody is proven, and the protected exact-byte SHA-256 trust anchor is provisioned. It cannot authorize tags, releases, workflow dispatch, schedules, deployments, PRs targeting another branch, staging or production. Release qualification and promotion remain separate controls.

The decision preparer is bound by immutable numeric GitHub user ID to the decision-PR author. The custody verifier selects a current effective approval from the trusted reviewer allowlist only when that reviewer is not the PR author and has not authored, co-authored or committed any commit in the decision PR. It enumerates the complete commit history through GraphQL and fails closed on unresolved identities. Login and email are not identity keys. The GitHub review ID and submitted timestamp are derived from API evidence at runtime; they are not embedded in the bytes being approved.

Risk validity is expiry-based; execution authorization is branch/event-based. The policy is usable only while unexpired **and** only for same-repository pull requests targeting `main` or pushes to `refs/heads/main`. A valid expiry never grants authority to another branch, tag, release or deployment, and a valid branch context never extends expiry.

The `dev10-security-policy-read` environment must permit only `main` and same-repository `refs/pull/*/merge` deployment refs. GitHub matches environment branch rules against `GITHUB_REF`; a protected-main-only allowlist blocks pull-request merge refs. This environment is an access boundary for reading the non-secret trust-anchor hash, not risk approval. Once branch/ref restrictions, fork exclusion and read-only token permissions are administrator-verified, prefer no human reviewer on every eligible PR so reusable qualification remains automatic. If an organisation retains per-run environment approval, count it only as access approval, never as the independent policy review. This admin configuration must be verified rather than inferred.

The decision record, independent review, custody verifier, protected default-branch controls and exact policy hash must all agree before the trust anchor is provisioned.


The final decision candidate is in the separate PR
https://github.com/baobab-platform/baobab-dev/pull/76. It is not active while
that PR is open. Owner attestation and independent exact-head approval are
still required; merge and exact-byte trust-anchor provisioning remain separate
activation steps.

## Foundation bootstrap and image-scan applicability

The shared Foundation reusable workflow remains on its **full profile** for
all PRs; baseline, reproducibility, runtime, environment and security gates are
not disabled for the decision PR. The additional unfiltered DEV-10 image scan
runs when container build inputs change (`.devcontainer/`, `config/`,
`scripts/`), the shared scanner-policy manifest (`.baobab/repository.yaml`)
changes, or the kernel inventory changes. A policy-only decision PR does not alter
those image inputs, so the DEV-10 image rebuild is not applicable; its risk
gate negative tests still run and the dedicated policy workflow validates the
proposal and decision against the pinned Draft 2020-12 schema. No image scan
pass is claimed for that path. The shared Foundation container job remains in the full profile and
builds/validates the image and SBOM, but its Trivy install/scan steps are
skipped under the separately governed `container-scan` implementation
exception, which PR #65 aligned to the 2026-11-26 sunset. This is not an
image-scan pass. That exception is not the reusable DEV-10 decision and
cannot authorize release. No image CVE scan is claimed for a policy-only PR;
current-head PR #74 requalification and all eight Publish scans remain
required before policy activation/release. Any PR changing image inputs must run the unfiltered DEV-10 scan, and
the eight Publish profile/architecture scans remain mandatory for release
qualification.
