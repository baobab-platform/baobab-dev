# PR #74 merge and v1.5.3-rc.1 execution checklist

**Repository:** `baobab-platform/baobab-dev`  
**PR:** [#74](https://github.com/baobab-platform/baobab-dev/pull/74)  
**Branch:** `dev10/v1.5.2-rc-verifier`  
**Reviewed head at checklist preparation:** `63fb63091996e436a2730f905b60dbb254f65544`  
**Proposed RC:** `v1.5.3-rc.1`

This checklist is an execution plan, not evidence that any item has passed. The PR title is intentionally left unchanged because it records the history of the work.

## 0. Release contract and governing specification

- [ ] Confirm release workflow/tag policy accepts `v1.5.3-rc.1` and the intended RC family.
- [ ] Confirm the tag is unused and will resolve to the intended merged commit.
- [ ] Reconcile PR/workflow release-family references where they affect behavior. Do not change the PR title merely to reflect the target RC.
- [ ] Locate and read the authoritative ADR governing the relevant design. **No ADR file was present in the recursive repository tree inspected at the reviewed head**, despite code comments referring to ADR-0001. Identify/restore the authoritative source before claiming ADR conformance.
- [ ] Confirm required profiles and architectures from the release contract.

## 1. Resolve the security decision before relying on an exception

- [ ] Reconcile issue #54 / PR #62 / PR #71 custody discrepancy.
- [ ] Confirm the exact eight-CVE inventory for `linux-libc-dev=7.0.0-43.43` against the retained raw Trivy report.
- [ ] Verify package type, installed version, severity, fixed-version fields and no-secret status.
- [ ] Record the raw source-report SHA-256 and scanner version.
- [ ] Explicitly decide whether PR #74 is in scope. Existing record says assessment-only and excludes it.
- [ ] Explicitly decide whether `v1.5.3-rc.1` and any later RC tags are in scope. Existing decision names only v1.5.0 refs.
- [ ] Enumerate approved profiles and architectures; do not infer the scope from test fixtures.
- [ ] Set a new explicit UTC expiry and reassessment/revocation triggers.
- [ ] Obtain owner attestation and independent security approval from distinct principals.
- [ ] Merge the approved decision through the protected decision path; verify current approval on the merged head.
- [ ] Have the authorized custodian provision the exact policy SHA-256 trust anchor.
- [ ] Verify active ruleset, CODEOWNERS enforcement, trusted reviewer permissions and protected environment settings.
- [ ] Run the live custody verifier and prove that wrong hashes, unapproved reviewers, stale approvals, changed policy bytes and invalid decision scope fail closed.

**Stop:** Until all applicable items above pass, do not treat the proposal as an active exception. The legacy Foundation and Publish gates remain authoritative.

## 2. Correct PR #74 implementation blockers

- [ ] Replace invalid Dockerfile healthcheck exec-form invocations of Compose-only `CMD-SHELL` in every affected profile stage with valid Dockerfile healthcheck syntax.
- [ ] Build all affected profile targets.
- [ ] Verify healthy status while PID 1 is alive and unhealthy status when the expected process is absent.
- [ ] Repair review-transition tests with realistic unique GitHub review IDs and ordered timestamps.
- [ ] Add an equal-timestamp tie-break regression test.
- [ ] Prove a later CHANGES_REQUESTED, COMMENTED or DISMISSED review supersedes an earlier approval.
- [ ] Run the review-state regression through Foundation, locked onboarding and Publish consumers.
- [ ] Run the complete affected unit, lockfile, security-policy and release-eligibility test suites.

## 3. Final-head CI and merge

- [ ] Push the fixes to the existing PR branch; record the resulting head SHA.
- [ ] Confirm all required workflows ran against that exact SHA.
- [ ] Foundation Repository Gates pass.
- [ ] DEV-10 locked onboarding passes, including source and both published-image jobs.
- [ ] Publish frozen-lockfile integrity and release-eligibility checks pass.
- [ ] Security, registry-contract, documentation and relevant consumer checks pass.
- [ ] No required job is skipped, neutralized or bypassed without explicit authorization and recorded rationale.
- [ ] Current independent review approvals satisfy the active branch rules.
- [ ] Merge PR #74 only after all required checks and reviews pass.
- [ ] Record and verify the merge commit SHA.

## 4. Create and qualify v1.5.3-rc.1

- [ ] Confirm tag name is valid, unused and classified as the intended RC.
- [ ] Create the tag from the verified merge commit using the canonical release process.
- [ ] Verify tag-to-commit resolution.
- [ ] Build every required profile for every required architecture.
- [ ] Publish candidate artifacts only through the existing authorized workflow.
- [ ] Record each immutable GHCR child-manifest digest.
- [ ] Run Trivy against each exact remote child digest.
- [ ] Apply the active bounded decision only if its exact PR/tag/package/finding/profile/architecture/time scope covers that artifact.
- [ ] Reject new/changed findings, fixed-version signals, secrets and all out-of-scope findings.
- [ ] Generate and verify SBOMs and provenance.
- [ ] Verify Cosign signatures and attestations against expected source and signer identity.
- [ ] Verify OCI metadata and artifact contracts.
- [ ] Run consumer qualification and runtime tests, including non-root Playwright Chromium execution.
- [ ] Retain sanitized, digest-bound qualification evidence.

**Stop:** A successful build or a skipped scan/promotion job is not RC qualification.

## 5. Protected promotion and digest continuity

- [ ] Verify protected promotion authority and independent reviewer configuration.
- [ ] Verify each promoted artifact is byte-for-byte the already qualified RC digest.
- [ ] Confirm promotion performs no rebuild or digest substitution.
- [ ] Verify signatures, SBOMs and provenance remain valid and refer to the same digest.
- [ ] Verify registry immutability controls or document the enforceable alternative.
- [ ] Close all findings or show they remain covered by a currently valid, exact-scope decision.
- [ ] Obtain separate independent authorization for promotion and any subsequent GA release.

## Required evidence bundle

- [ ] Approved decision PR, reviewer identity and merged-head approval evidence.
- [ ] Policy JSON SHA-256 and trust-anchor provisioning evidence.
- [ ] Admin ruleset, CODEOWNERS and protected-environment verification.
- [ ] PR #74 final head, CI run URLs and merge commit.
- [ ] RC tag and resolved commit.
- [ ] Per-profile/per-architecture image digests and remote scan evidence.
- [ ] SBOM, provenance and signature verification outputs.
- [ ] Runtime and consumer qualification results.
- [ ] RC-to-GA digest continuity evidence and separate promotion authorization.
