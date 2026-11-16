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

The author prepares the decision; a separately trusted reviewer must approve the exact final merged head. The decision record, independent review, custody verifier, protected default-branch controls and exact policy hash must all agree before the trust anchor is provisioned.
