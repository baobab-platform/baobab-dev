# DEV-10 PR #92 — current decision and documentation reconciliation

**As of:** 2026-11-21  
**Decision PR:** [#92](https://github.com/baobab-platform/baobab-dev/pull/92)  
**Governing policy:** [ADR-DEV10-001](../adr/ADR-DEV10-001-reusable-development-risk-policy.md)  
**Status:** documentation reconciliation only; the proposed 30-finding decision is not active.

## 1. Exact subject of PR #92

PR #92 proposes a development-only residual-risk decision for the exact inventory below:

- Image: `ghcr.io/baobab-platform/baobab-dev`
- Package: `linux-libc-dev=7.0.0-44.44`
- Findings: 30 unique CVE identities — 27 HIGH and 3 CRITICAL
- Profiles: `final`, `frontend`, `frontend-e2e`, `infra`
- Architectures: `linux/amd64`, `linux/arm64`
- Expiry: `2026-11-26T00:00:00Z`; no automatic renewal
- Normalized five-tuple inventory SHA-256: `2b30ad504108d5192ceb747f089f9016d3bbb011a9676e55a2d52663b230d2df`
- Eight-image evidence-lock SHA-256: `f8f4773c54a66caa1a8f95a0a09653c5fb7fb0dab0c5710c82008e3fa3ed0d7a`

The inventory is the exact union reconciled from Foundation runs [44894755391](https://github.com/baobab-platform/baobab-dev/actions/runs/44894755391) and [44898408942](https://github.com/baobab-platform/baobab-dev/actions/runs/44898408942), and the eight Publish profile/architecture artifacts from [44898408090](https://github.com/baobab-platform/baobab-dev/actions/runs/44898408090). This is inventory evidence, not a technical applicability verdict or proof of remediation.

The three CRITICAL identities are CVE-2026-99287, CVE-2026-99306 and CVE-2026-99310. Their inclusion raises the severity of the proposed decision compared with the earlier eight-HIGH proposal. The earlier applicability material does not establish their individual source-patch, shipped-binary, UAPI/ABI or host-kernel impact. They remain unresolved for technical disposition; this document does not classify them as `not_affected`.

## 2. Decision lifecycle: proposed record is not an effective exception

The file `security/decisions/development/foundation.json` is a `proposed_approved_form`. Its `status: approved` value represents the intended content of the proposed decision record; it is not proof that a trusted reviewer approved the exact head, that the PR was merged, that contributor custody was verified, or that the protected SHA trust anchor was provisioned.

The notes in that file state that the decision is **PROPOSED, INACTIVE**. The separate `foundation.proposal.json` remains `pending_independent_review`. Under ADR-DEV10-001 section 4, effectiveness requires all of the following:

1. Attributable accountable-owner concurrence on this exact decision PR.
2. A fresh trusted independent approval on the exact final PR head, with reviewer numeric identity independent of the preparer and every PR commit author, co-author and committer.
3. Complete contributor-history and custody verification.
4. Merge of the reviewed decision and byte-for-byte equality among approved-head, merge-commit and current-main decision bytes.
5. Authorized create-only provisioning of `DEV10_PROTECTED_DECISION_SHA256` for those exact bytes.

Owner concurrence is not independent approval. A review on an earlier head is not approval of a later head. A green decision-contract test is not activation. No trust-anchor provisioning, merge, release, publication, signing, attestation, promotion, staging or production authority is implied here.

**Documentation clarity note:** the combination of `status: approved`, `record_type: proposed_approved_form` and inactive notes is easy to misread. The status field's intended-form semantics are described in ADR-DEV10-001, but the JSON presentation remains a reviewer usability concern. It must not be interpreted as an effective approval. Changing the field semantics requires a coordinated schema, provisioner and test change; this documentation-only reconciliation does not silently alter that contract.

## 3. Runtime evaluator reconciliation on the PR #92 head

The PR #92 branch now replaces the legacy hard-coded 42.42/43.43 inventories, PR #71 allowlist and v1.5.0/v1.5.1 tag scope in `scripts/dev10_kernel_risk_gate.py`. The Foundation workflow passes the exact decision file, its eight-image evidence lock, the protected repository variable, and the GitHub event/base/head-repository context to that evaluator.

The evaluator now:

- authenticates the exact UTF-8 bytes of `foundation.json` against `DEV10_PROTECTED_DECISION_SHA256`; a missing, malformed or mismatched anchor denies every non-clean scan;
- verifies the evidence-lock bytes against `foundation.json.evidence_lock_sha256` and checks that all eight profile/architecture artifacts are present;
- validates the 30 unique five-tuple finding identities, exact package/version/ecosystem, 27 HIGH / 3 CRITICAL split, development-only scope and fixed expiry;
- permits only same-repository pull requests targeting `main` and pushes to `refs/heads/main`; forks, tags, schedules, manual dispatch, other branches and deployment contexts are denied;
- permits an observed subset of the exact inventory after partial remediation, but rejects unknown/changed findings, duplicate CVEs, fixed-version signals, secrets and malformed/incomplete Trivy output.

The evaluator is workflow-only and is not copied or executed by the development image. Foundation and Publish path filters now exclude that evaluator from image-build qualification triggers; scripts actually consumed by the Dockerfile remain in scope. The Foundation job still runs its evaluator regression suite on each event. This is a scope correction, not a scan suppression.

**Activation remains separate.** The branch's `foundation.json` is still a proposed form. The trust anchor is not provisioned by this PR, and the evaluator does not infer approval from `status: approved`. Until the exact decision bytes are merged and ADR-DEV10-001's independent review, owner concurrence, complete custody and authorized create-only trust-anchor provisioning have been verified, any non-clean Foundation scan remains denied. This reconciliation does not claim the 30 findings are technically harmless, fixed, or `not_affected`, and it does not make PR #74's current scan pass.

## 4. Historical records versus current proposal

Several repository documents still describe earlier states. They must be read according to their evidence dates and original scope, not silently rewritten to imply that PR #92 was already effective.

| Repository reference | What it describes | Reconciliation |
|---|---|---|
| `docs/assessments/dev10-linux-libc-dev-risk-decision.md` | 30 October investigation of `7.0.0-42.42` and its 295 source-package advisory matches | Historical evidence; not the 30-finding PR #92 decision |
| `docs/security/dev10-foundation-policy-review.md` | Earlier eight-HIGH `7.0.0-43.43` evidence and run 43829121908 | Historical eight-finding assessment; not current 30-finding evidence |
| `docs/usage/engine-onboarding.md` and `docs/usage/toolchain-upgrade-playbook.md` | Original 295-finding `7.0.0-42.42` treatment and 13 November expiry | Historical scope; must not be cited as authority for #92 |
| `README.md` | Original DEV-10 R4 candidate and the 295-finding/13 November historical boundary | Historical candidate summary; not the #92 decision |
| `.baobab/repository.yaml` | Shared scanner exception text still naming 295 findings on `7.0.0-42.42` with expiry 2026-11-26 | Inconsistent with the historical 13 November wording and not evidence that the 30-finding proposal is active. Its owner-authorized purpose and expiry need explicit reconciliation; this PR does not repurpose it. |
| `.baobab/environment.yaml`, `.devcontainer/devcontainer.json`, and README image references | The machine-readable application version/minimum version in `.baobab/environment.yaml` are `1.5.1`, and the actual `image` field in `.devcontainer/devcontainer.json` is `ghcr.io/baobab-platform/baobab-dev:1.5.1`. However, the environment-contract note and Dev Container comments still say `v1.4.2`, while README's Foundation 4 paragraph says `v1.4.4`. | The checked-in machine-readable fields agree on `1.5.1`; the prose/comments are stale. This is a confirmed documentation mismatch, not evidence of a published digest or current registry availability. Correcting `.devcontainer/` in this decision PR would change a declared image-input path and trigger image qualification, so the version-comment cleanup should be a separate, appropriately qualified documentation/configuration change rather than being smuggled into this decision-only PR. |

Historical scan reports, source inventories and assessments must retain the version, date, run ID and conclusions that were true when they were produced. A current status note may supersede their applicability as policy authority; it must not rewrite historical evidence as though it were generated against `7.0.0-44.44`.

## 5. Required follow-up before PR #92 can be considered decision-ready

The following are not completed by this documentation update:

1. **Runtime gate verification:** run the new evaluator's positive and negative regression tests on the final PR #92 head, then independently review the evaluator, Foundation call site and event-scope enforcement. The exact candidate must remain inactive until the ADR's approval, custody, merge and provisioning conditions are met. Do not add an unreviewed PR-specific bypass.
2. **Scanner exception metadata:** obtain an explicit owner decision on the purpose and expiry of the legacy `.baobab/repository.yaml` shared-scanner exception. Do not change its inventory to 30 or extend it based only on PR #92's proposed record.
3. **Decision-state representation:** decide whether to retain the current intended-form `approved` status with stronger machine-readable inactive semantics, or change the schema/provisioner/tests together to use a pending state. A prose-only explanation does not eliminate the underlying presentation ambiguity.
4. **Applicability analysis:** update the technical review for all 30 identities, with particular attention to the three CRITICALs. Record Canonical package status, Ubuntu patch/backport evidence, exact installed binary/header correspondence, downstream UAPI/ABI implications and host-kernel separation. Keep unresolved cases `under_investigation`; do not infer `not_affected` from package type or source-path absence.
5. **Image-version metadata:** the checked-in environment contract and Dev Container image field both identify v1.5.1; their surrounding prose/comments and the README's Foundation 4 statement still cite v1.4.2/v1.4.4. Correct those stale references in a separate change with the required image-input qualification. This inspection establishes the configured tag only, not its current registry digest or availability.
6. **Exact-head governance:** after any content change, rerun all applicable checks on the new PR head and obtain fresh independent review of that exact head. Recheck owner concurrence and contributor independence. Expiry remains 2026-11-26T00:00:00Z with no automatic renewal.

## 6. Explicit non-claims

This document does not assert that the 30 findings are harmless, fixed, non-applicable, or covered by an active exception. It records the PR #92 branch's runtime evaluator implementation, but does not claim that the trust anchor has been provisioned or that the proposed decision is active. It does not approve a release, image tag, publication, signing, attestation, promotion, staging or production deployment. The exact inventory and evidence hashes above identify the candidate under review only.
