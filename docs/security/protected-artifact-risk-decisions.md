# DEV-10 protected, artifact-bound security decisions — migration specification

Status: **IMPLEMENTED EVALUATOR / NOT ACTIVATED** (PR #74). No new risk acceptance is issued by this change.

## Policy

PR numbers are review identifiers, **not** vulnerability-risk identities. Risk acceptance shall be scoped to verified findings (CVE, package, installed version and severity), the exact immutable image digest, profile, architecture, development-only environment, expiry, and an independently authenticated approval record. New or changed CVEs, available fixes, secrets, expired/revoked decisions and non-development use must fail closed.

The existing `scripts/dev10_kernel_risk_gate.py` remains unchanged and authoritative until a protected workflow has been connected and independently qualified. In particular, **PR #74 is NOT covered by the existing eight-CVE acceptance** for `linux-libc-dev=7.0.0-43.43`. Do not add PR #74, relax Trivy or create an approval from this specification.

## Implementation supplied

`scripts/evaluate_protected_risk_decision.py` is a reusable, read-only evaluator. It does not contain a PR allow-list and never creates or approves decisions. It verifies a protected policy file against a separately supplied trusted SHA-256, checks the exact immutable image digest, package/CVE inventory, approved context, expiry and revocation status. Its output records the decision identifier and digest. `tests/test_protected_risk_decision.py` covers positive and fail-closed negative cases.

The SHA-256 **must** come from a separately protected trust domain (for example a trusted, protected release workflow that obtains a policy revision from a protected branch or immutable signed policy store). A hash or decision supplied by the same untrusted PR checkout is not authority. A repository JSON file with an `approved_by` string or evidence URL is also **not** authenticated approval by itself.

## Activation prerequisites (not yet satisfied)

1. Reconcile issue #54 and the 12/14 November decision custody discrepancy; appoint and authenticate an independent approver. No retroactive approval is inferred.
2. Store approved decision records outside PR-controlled code and enforce independent approval, immutable policy revision, revocation and expiry. Record trusted SHA-256 from that protected source. Prevent PRs from changing evaluator or policy and approving themselves.
3. Build and scan all four profiles on AMD64/ARM64, preserve unfiltered Trivy reports and independently resolve immutable index/child digests. The evaluator currently accepts one exact image digest per call; the protected orchestration must bind each report to its actual scanned digest.
4. Execute the evaluator in a trusted workflow (not the untrusted PR checkout) using protected policy bytes and trust anchor. Preserve the raw scan, approval evidence, decision bytes/hash, evaluator version, exact digests, source SHA and run IDs.
5. Add connected positive/negative integration tests with real Trivy JSON and GHCR evidence, including no decision, changed CVE, changed package, supported fixed version, expiry, revocation, forged reviewer, wrong digest and malicious PR policy edits.
6. Only then replace the legacy PR-number exception in Foundation and Publish. Protected RC-to-GA promotion, signature/provenance checks and consumer qualification remain independent mandatory gates.

**Important:** A reusable package-level risk policy can support routine PR scanning, but a new release digest is not automatically approved by an earlier exact-digest decision. If automated release authorization is desired, it must be based on a separately authenticated, narrowly scoped policy granting that specific derivation, and generate an independently auditable digest-bound decision. The present evaluator intentionally requires exact digest membership.

## Operating objective

Normal human actions: edit `config/versions.yaml`; review newly detected or changed CVEs; approve/reject necessary bounded security decisions. Clean scans require no risk exception. Genuine engineering failures, security remediations and initial governance setup may still require intervention.
