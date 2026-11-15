# DEV-10 protected, artifact-bound security decisions

Status: REUSABLE POLICY EVALUATOR IMPLEMENTED / NOT ACTIVATED (PR #74).
This change issues no new risk acceptance and does not qualify PR #74.

## Decision model

PR numbers are review-container identifiers, not vulnerability-risk identities.
A reusable risk-policy decision scopes the exact CVE, package ecosystem/type, installed version
and severity; GHCR image repository; permitted profiles and architectures;
development-only environment; independent preparer/checker identities; approval
reference; timestamps; expiry and revocation state.

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
severity identities, maker-checker separation, expiry and revocation. A clean
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

The policy file must live on the protected default branch under
security/decisions/. Its approval record must be attributable through the
repository's protected review process, with an independent reviewer, no
self-approval and auditable review evidence. The preparer and approver must be
different principals. The trust-anchor update must be a separately controlled
administrative operation.

A per-candidate GitHub environment approval is intentionally not used: it
would turn routine artifact qualification into a repeated human gate. Human
approval belongs to the risk-policy decision, not every subsequent matching PR.

## Current authorization remains unchanged

The legacy DEV-10 kernel risk gate remains authoritative for Foundation and
Publish until a protected-policy record and trusted hash exist and a separately
reviewed integration replaces the legacy path.

- PR #74 is not added to the legacy PR allow-list.
- The eight HIGH findings for linux-libc-dev 7.0.0-43.43 are not approved by
  this evaluator implementation.
- The 12 November issue #54 record names PR #62; the later executable gate
  names PR #71. This custody discrepancy remains unresolved.
- The 14 November PR #74 entry is assessment-only, not a risk acceptance.
- No VEX not_affected claim, Trivy suppression, release waiver or promotion
  authority is created here.

A policy record must not be created for the eight findings until the owner and
independent security reviewer reconcile the approval scope and custody
discrepancy in issue #54.

## Activation prerequisites

1. Reconcile issue #54 and the 12/14 November package-version decision custody.
2. Confirm the independent security approver and protected review path.
3. Create the policy record only after an attributable, bounded approval.
4. Set the protected SHA-256 trust anchor through the designated custodian.
5. Add trusted automation that evaluates candidate scan evidence from PR builds
   without executing PR-controlled evaluator or policy code. The current
   workflow is a protected, read-only manual qualification tool, not an
   automatic PR gate.
6. Test real Trivy/GHCR evidence and malicious PR policy edits, wrong child
   digest, architecture drift, new CVEs, package/version/severity changes,
   fixed-version signals, expiry, revocation and secret findings.
7. Keep exact-digest release qualification and protected promotion independent.

## Operating objective

The intended normal human actions remain: update config/versions.yaml,
review new or changed security findings, and approve/reject bounded risk
decisions when necessary. Clean scans and later candidate builds matching an
active approved policy require no repeated risk approval. Genuine remediation,
compatibility and governance exceptions still require engineering intervention.
