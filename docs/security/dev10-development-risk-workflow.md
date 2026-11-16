# DEV-10 development vulnerability acceptance — minimal operating procedure

Baobab-dev builds **internal development environments**, not application staging or production deployments.

## Normal release path

1. Update `config/versions.yaml`; let the existing resolver and CI enforce the lock.
2. Review the actual Trivy findings. If there are **no findings** or only exact, previously accepted findings **within the current time-bounded decision**, CI may proceed without an additional per-PR security approval. If the findings change, an authorized human reviewer independent of the PR author must explicitly approve a narrowly scoped security decision (or the engineer must remediate) before changing the risk inventory/decision and rerunning CI.
3. After existing Foundation/Publish checks and independent release controls pass, use the established GHCR publication flow. No automatic publication from an ordinary PR.

## Reusable future-PR qualification — proposed, not yet active

The protected policy implementation is being prepared to reuse one approved decision across eligible future pull requests. Eligibility is not inferred from a PR number: the GitHub event must be `pull_request`, the merge ref must match `refs/pull/<positive-number>/merge`, and the PR base branch must be `main`. Post-merge development CI may reuse the same decision only for `push` to `refs/heads/main`.

The proposed policy is bounded to the exact eight HIGH Ubuntu findings for `linux-libc-dev=7.0.0-43.43`, all four image profiles, both supported Linux architectures, this repository/image repository, and expiry **2026-11-26 00:00 UTC**. It is not PR-number-bound. New/changed findings, package/version/severity drift, fixed-version signals, secrets, incomplete scan inventory, or scanner errors remain blocking.

The policy is **not active** while its status is `pending_independent_review`, the protected SHA-256 trust anchor is unset, or approval custody is unverified. It cannot authorize tags, releases, workflow dispatch, schedules, deployments, PRs targeting another branch, staging or production. Release qualification and promotion remain separate controls.

The decision preparer is bound by immutable numeric GitHub user ID to the decision-PR author. The custody verifier selects a current effective approval from the trusted reviewer allowlist only when that reviewer is not the PR author and has not authored, co-authored or committed any commit in the decision PR. It enumerates the complete commit history through GraphQL and fails closed on unresolved identities. Login and email are not identity keys. The GitHub review ID and submitted timestamp are derived from API evidence at runtime; they are not embedded in the bytes being approved.

Risk validity is expiry-based; execution authorization is branch/event-based. The policy is usable only while unexpired **and** only for same-repository pull requests targeting `main` or pushes to `refs/heads/main`. A valid expiry never grants authority to another branch, tag, release or deployment, and a valid branch context never extends expiry.

The `dev10-security-policy-read` environment must permit `main` and `refs/pull/*/merge` deployment refs, in addition to its required reviewers. GitHub matches environment branch rules against `GITHUB_REF`; a protected-main-only allowlist blocks pull-request merge refs. This admin configuration must be verified rather than inferred.

The decision record, independent review, custody verifier, protected default-branch controls and exact policy hash must all agree before the trust anchor is provisioned.


The final decision candidate is in the separate PR
https://github.com/baobab-platform/baobab-dev/pull/76. It is not active while
that PR is open. Owner attestation and independent exact-head approval are
still required; merge and exact-byte trust-anchor provisioning remain separate
activation steps.
