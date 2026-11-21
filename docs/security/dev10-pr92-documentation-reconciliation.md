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

## 3. Runtime enforcement is not yet aligned with this proposal

The executable `scripts/dev10_kernel_risk_gate.py` on the reviewed base still encodes the legacy inventory and execution scope:

- `linux-libc-dev=7.0.0-42.42`: the pinned 295-CVE inventory;
- `linux-libc-dev=7.0.0-43.43`: the separate eight-HIGH-CVE inventory;
- PR allowlist: PR #71;
- tagged development image refs: v1.5.0/v1.5.1 and their configured RC patterns.

It does not load or evaluate the 30-finding `foundation.json` record. The proposed record is validated by its schema/tests and consumed by the protected provisioner; that is not the same as the Foundation scan gate enforcing it.

Accordingly, PR #92's proposed 30-finding decision **cannot currently be represented as an active runtime exception**, and it does not make a scan of `7.0.0-44.44` pass. The runtime gate, its workflow call sites and negative tests require a separately reviewed implementation change before anyone can claim the 30-finding record is enforced by CI. Until that work is completed and authorized, the existing scan gates remain fail-closed.

## 4. Historical records versus current proposal

Several repository documents still describe earlier states. They must be read according to their evidence dates and original scope, not silently rewritten to imply that PR #92 was already effective.

| Repository reference | What it describes | Reconciliation |
|---|---|---|
| `docs/assessments/dev10-linux-libc-dev-risk-decision.md` | 30 October investigation of `7.0.0-42.42` and its 295 source-package advisory matches | Historical evidence; not the 30-finding PR #92 decision |
| `docs/security/dev10-foundation-policy-review.md` | Earlier eight-HIGH `7.0.0-43.43` evidence and run 43829121908 | Historical eight-finding assessment; not current 30-finding evidence |
| `docs/usage/engine-onboarding.md` and `docs/usage/toolchain-upgrade-playbook.md` | Original 295-finding `7.0.0-42.42` treatment and 13 November expiry | Historical scope; must not be cited as authority for #92 |
| `README.md` | Original DEV-10 R4 candidate and the 295-finding/13 November historical boundary | Historical candidate summary; not the #92 decision |
| `.baobab/repository.yaml` | Shared scanner exception text still naming 295 findings on `7.0.0-42.42` with expiry 2026-11-26 | Inconsistent with the historical 13 November wording and not evidence that the 30-finding proposal is active. Its owner-authorized purpose and expiry need explicit reconciliation; this PR does not repurpose it. |
| `.baobab/environment.yaml`, `.devcontainer/devcontainer.json`, and README image references | Different documented image versions (including v1.4.2 and v1.4.4); reviewer also identified v1.5.1 references elsewhere | Image-version metadata is a separate repository consistency issue. The actual currently consumed image must be established from the authoritative configuration and verified workflow evidence before changing these values. |

Historical scan reports, source inventories and assessments must retain the version, date, run ID and conclusions that were true when they were produced. A current status note may supersede their applicability as policy authority; it must not rewrite historical evidence as though it were generated against `7.0.0-44.44`.

## 5. Required follow-up before PR #92 can be considered decision-ready

The following are not completed by this documentation update:

1. **Runtime gate alignment:** independently implement and test the relationship between the active decision record and the Foundation scan gate. The exact candidate must remain inactive until the ADR's approval, custody, merge and provisioning conditions are met. Do not add an unreviewed PR-specific bypass.
2. **Scanner exception metadata:** obtain an explicit owner decision on the purpose and expiry of the legacy `.baobab/repository.yaml` shared-scanner exception. Do not change its inventory to 30 or extend it based only on PR #92's proposed record.
3. **Decision-state representation:** decide whether to retain the current intended-form `approved` status with stronger machine-readable inactive semantics, or change the schema/provisioner/tests together to use a pending state. A prose-only explanation does not eliminate the underlying presentation ambiguity.
4. **Applicability analysis:** update the technical review for all 30 identities, with particular attention to the three CRITICALs. Record Canonical package status, Ubuntu patch/backport evidence, exact installed binary/header correspondence, downstream UAPI/ABI implications and host-kernel separation. Keep unresolved cases `under_investigation`; do not infer `not_affected` from package type or source-path absence.
5. **Image-version metadata:** verify the authoritative dogfooded image version/digest and reconcile README, environment contract and Dev Container references as a separate documented change.
6. **Exact-head governance:** after any content change, rerun all applicable checks on the new PR head and obtain fresh independent review of that exact head. Recheck owner concurrence and contributor independence. Expiry remains 2026-11-26T00:00:00Z with no automatic renewal.

## 6. Explicit non-claims

This document does not assert that the 30 findings are harmless, fixed, non-applicable, or covered by an active exception. It does not assert that the Foundation runtime gate consumes the proposed decision. It does not approve a release, image tag, publication, signing, attestation, promotion, staging or production deployment. The exact inventory and evidence hashes above identify the candidate under review only.
