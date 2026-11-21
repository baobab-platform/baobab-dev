# ADR-DEV10-002: Pre-activation validation of development-risk decisions

| | |
|---|---|
| **Status** | Proposed — governance decision and implementation review required |
| **Date** | 2026-11-21 |
| **Owner** | Accountable DEV-10 security-policy owner (@wekhason, GitHub user ID `350241706`) |
| **Repository** | `baobab-platform/baobab-dev` |
| **Supersedes** | None |
| **Related** | [ADR-DEV10-001](ADR-DEV10-001-reusable-development-risk-policy.md); PR #92; PR #74 |

## 1. Context

ADR-DEV10-001 requires all of the following before a development-risk decision becomes effective:

1. A separate decision PR with attributable accountable-owner concurrence.
2. A fresh trusted independent approval on the exact final PR head.
3. Complete contributor-history and custody verification.
4. Merge of the reviewed decision, with exact approved-head, merge-commit and current-main bytes.
5. Create-only provisioning of the trust anchor for those exact bytes after merge and custody verification.

The same ADR requires the shared Foundation workflow to run its full profile on every event and prohibits disabling Foundation security, baseline, reproducibility, runtime or environment gates for a policy PR.

The current repository workflow calls the shared Foundation reusable workflow with its default `full` profile. At the pinned shared revision, that profile includes the container gate. Separately, the repository's DEV-10 Foundation container-risk job scopes its additional unfiltered image scan to image/build-policy inputs. These are distinct controls; skipping the repository-local additional scan does not mean the shared Foundation container gate was skipped.

This creates a potential bootstrap conflict when the full shared container gate reports the exact residual findings that the separate decision PR is intended to govern: the decision cannot become active until after merge, while the decision PR is subject to the full Foundation profile before merge. The current PR #92 is decision-only and its local DEV-10 image scan is not applicable to its diff. At the time this ADR was drafted, the shared Foundation container job was still running; a failure on the current head had not been established.

ADR-DEV10-001 section 7 says a policy-only PR does not claim an image scan passed and that the additional unfiltered scan runs when image inputs change. That text does not, by itself, exempt the shared reusable Foundation container gate from the full profile. The distinction must be explicit to prevent an inaccurate CI status or an accidental gate bypass.

## 2. Decision

**No pre-activation risk exception or CI bypass is authorized by this ADR.**

Until an explicit, independently reviewed bootstrap procedure is accepted and implemented:

- The decision PR remains subject to every required check, including the shared Foundation full profile.
- A scan result must not be relabelled as passed, not applicable, remediated, or accepted merely because the decision file proposes an acceptance.
- A proposed decision, owner-concurrence comment, `status: approved` field, evidence lock, or requested reviewer approval does not activate the decision.
- No repository exception, scanner ignore, workflow condition, branch-protection bypass, administrator bypass, or temporary trust anchor may be introduced solely to make the decision PR mergeable.
- If the full Foundation container gate fails on the exact residual inventory, the decision PR must remain unmerged until the bootstrap conflict is resolved through a separately reviewed ADR amendment and corresponding implementation. If the gate passes, this potential conflict is not a reason to block it.
- A failure unrelated to the proposed inventory must be investigated and corrected normally; it is not eligible for candidate treatment.

This is a fail-closed governance position, not a claim that the current PR #92 has failed.

## 3. Requirements for any future bootstrap proposal

A future proposal must specify and prove all of the following before implementation is authorized:

1. **Exact candidate binding.** Candidate validation is bound to one canonical repository, one decision PR number, one immutable head SHA, the exact decision bytes, the exact evidence-lock bytes/hash, and the exact normalized finding inventory. It must reject changed heads, changed files, changed inventory, additional findings and non-kernel findings.
2. **Independent pre-merge authorization.** The accountable owner's attributable concurrence and a fresh trusted independent `APPROVED` review must be verified against the exact current head before any candidate-specific treatment is permitted. Reviewer numeric identity must be independent of the preparer and every author, co-author and committer in the complete PR history.
3. **Evidence, not suppression.** The full unfiltered scan must execute and retain its raw report. Candidate validation may not hide findings, alter scanner output, use `--ignore-unfixed`, mark findings remediated or VEX `not_affected`, or accept tool/scanner errors.
4. **Strict scope.** Any candidate-specific handling is limited to the exact decision PR and exact inventory under review. It must not affect other pull requests, main-branch scans, image-input changes, release workflows, tags, publication, signing, attestation, promotion, staging or production.
5. **No premature activation.** Candidate validation is not an active risk decision, does not provision or impersonate the protected trust anchor, and does not authorize ordinary development PRs or main-branch execution.
6. **Post-merge continuity.** The proposal must explain how the first post-merge main-branch verification is made deterministic with the required post-merge trust-anchor provisioning. It must not rely on a race between independent workflows or claim the decision is active before exact-byte provisioning succeeds.
7. **Fail-closed negative tests.** Tests must demonstrate rejection of a changed PR head, wrong PR/repository/base/ref, stale or missing approval, owner-concurrence mismatch, contributor overlap, incomplete custody history, altered evidence lock, extra CVE, changed package/version, non-kernel finding, scanner/tool failure, expired decision and any release/deployment context.
8. **Independent review and governance.** The bootstrap design, workflow changes and tests require a separate PR, exact-head independent trusted review, full CI, and accountable-owner approval. The author of the proposal must not approve their own work.

A proposal that cannot satisfy these conditions must not be implemented as a candidate exception. The acceptable alternative is to resolve the underlying findings or obtain a different supported upstream image/package state that passes the existing controls.

## 4. Relationship to ADR-DEV10-001

This ADR clarifies the pre-activation boundary in ADR-DEV10-001; it does not weaken or replace its identity, custody, expiry, trust-anchor, execution-scope or release-separation requirements.

If an implementation requires changing ADR-DEV10-001's requirement that the full shared Foundation profile run on every event, that change must be explicit in a reviewed ADR amendment. It must not be inferred from the conditional scope of the repository-local DEV-10 image scan.

The exact 30-finding proposal in PR #92 remains a proposed decision. Its owner concurrence is evidence of accountable-owner direction only. It does not satisfy independent approval, custody, merge, provisioning or activation by itself.

## 5. Consequences

- The repository has an explicit rule against solving a governance bootstrap conflict by silently weakening CI.
- CI reporting must distinguish the shared Foundation container gate from the repository-local additional DEV-10 image scan.
- The decision PR may remain blocked if the shared Foundation gate detects the residual findings. That is preferable to merging an unactivated or inadequately authorized exception.
- A future implementation must solve both the pre-merge candidate-validation problem and the first post-merge verification/provisioning ordering problem; solving only one is insufficient.
- No implementation or risk acceptance is authorized by this proposed ADR.
