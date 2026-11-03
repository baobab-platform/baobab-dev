# DEV-10 R5 — Release Pipeline Hardening

**Status:** Adopted workstream; implementation in stacked draft PR.
**Stack:** PR #57 `feat/dev10-r4-lts-multiarch-candidate` → this PR, never directly against `main` before #57 merges.
**Governing gates:** EA v2.3; DEV-10/DEV-14; protected release, immutable artifacts, independent acceptance.

## Required sequence

1. **Exact image:** all eight target × platform images must undergo a positive, unfiltered Trivy HIGH/CRITICAL + secret scan. On stable tag pushes, the final registry **digest**, not a local rebuild or equivalent Dockerfile, must be scanned, with identity and source commitment recorded. Tag creation must not precede exact-image release approval.
2. **Fresh intelligence:** the cached Trivy vulnerability and Java DB must be refreshed (or metadata shown fresh) on every scan. Stale/absent/malformed database metadata, download failure, missing evidence or unknown risks must fail closed. Never use a broad restored-cache prefix as justification for unconditional `--skip-db-update`.
3. **Privilege separation:** PR/main qualification has no `packages: write`; release registry credentials and OIDC signing exist only in tag-only jobs after completed validation and owner approval. Stable publication is an independent promotion operation.
4. **Registry durability:** improve `registry-integrity.yml` to reject incomplete/duplicate release contracts, verify all four exact published targets and both platform+attestation references, include source/provenance identity, verify independently of the triggering PR source, and retain diagnostic evidence.
5. **Only then:** extract/refactor the 1,700+-line publish pipeline for maintainability, speed and cost; no blanket rearchitecture before core safeguards pass.

## Architectural correction and migration constraint

The R4 workflow pushes **untagged release image content** to GHCR in the broad eight-way build matrix before local Trivy. It later creates mutable version tags before completing Sigstore signing and verification. Untagged digests are still addressable; tag publication is therefore a **promotion boundary**, not a substitute for qualification.

R5 separates the read-only **validation build** from a privileged **digest publication** job: validation never pushes; a tag-only job rebuilds from pinned source only after all validations succeed, then scans the **actual** remote digest and exports its verified digest artifact. Manifest creation/signing must consume **only** those verified digests. A failed remote scan is a release failure: even if untagged blobs exist, no consumer-facing release tags or GitHub Release may be created. The optional stronger future design uses a physically restricted quarantine registry and digest-preserving promotion after signed verification; it needs dedicated infrastructure and authorization, not guessed CI permissions.

A successful validation build and a remote digest scan are both required: a local image may differ in bytes from the separate release build. A change that skips the remote digest scan is a release regression.

## Evidence and controls

- Retain workflow+head SHA, exact target/platform digest, scan report, db metadata and tool version.
- Fail on stale DBs, incomplete matrix, missing per-platform evidence, unknown scan errors, untrusted release provenance, registry drift or incomplete signatures.
- No `v1.5.0` tag or protected promotion when the DEV-10 kernel-risk exception remains applicable; the exception is **development-only**.
- No preemptive production/staging approval; real Codespaces/private-package consumer and full multiarch qualification remain independent.
- CI must pass on the final R5 head. The R5 PR stays **draft** until gate-by-gate evidence is accepted.

## Registry-integrity audit — confirmed baseline concerns

- The current workflow parses the free-form GitHub Release body, accepts **one or more** records (does not require the 4 known target contracts), and selects the **first** per-platform descriptor (duplicates may pass).
- `workflow_run` fires whenever the entire Publish workflow completes, including PR and failed runs; it independently checks the latest stable release instead of the triggering digest, creating redundant checks and potentially noisy failures.
- Signature verification uses a broad organisation-prefix OIDC identity regexp; attestations are verified by *existence*, not demonstrably by both architecture and precise originating release workflow.
- Exact platform/SBOM/provenance coverage and immutable signed machine-readable release manifest should be strengthened. No registry mutation is appropriate in this independent read-only monitor.

## Exit criteria

Strict current-head CI + eight-image AMD64/ARM64 tests, actual SHA-pinned build/scan, Trivy freshness and negative tests, private-package consumer qualification, signed provenance and SBOM readback, failure injection for incorrect tag/digest/arch and stale DB, and a full protected-release dry run. No claim of these results is made by source changes alone.
