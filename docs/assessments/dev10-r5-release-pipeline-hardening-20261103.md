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

## Implementation inventory — 3 November 2026

Source-level changes are in stacked **draft PR #58**, based on PR #57. They do not qualify an actual GA tag, and there has been **no R5 registry publication or merge**.

| R5 requirement | Implemented source | Remaining proof/control |
| --- | --- | --- |
| Read-only eight-leg validation | `publish.yml/build`: `contents: read`, no GHCR login, no digest push | Fresh end-to-end eight-image PR/head scan and consumer qualification |
| Privileged exact-digest publication | `release-digests` depends on successful entire validation matrix; tag-only, native AMD64/ARM64; registry image child digest readback and exact-content remote Trivy + smoke; only passing digest artifacts are exported | Protected tag dry run required; remote digest scan is not executable on PR event without publishing |
| Fresh security intelligence | `scripts/verify_trivy_db_freshness.py` checks both vulnerability and Java DB `Version`, `UpdatedAt`, `DownloadedAt` and `NextUpdate`; `publish.yml` runs both official update commands before any scan, then reuses the verified DB for the scan | Read back real vendor metadata in all eight images; stale/expired/invalid negative tests must remain passing |
| Deferred official version tags | `publish` builds unique run-scoped candidate index and signs two platform provenance and SBOM predicates; *no official version tags* are set. `promote` applies official tags only when every candidate verifies | Owner must configure GitHub Environment `dev10-release-promotion` with independent required reviewers, allowed deployment tag rules and `DEV10_R5_PROMOTION_APPROVED=true`. The workflow deliberately FAILS CLOSED without that variable. A YAML `environment:` reference alone does not configure GitHub approvals |
| Exact release signer identity | `scripts/verify-image.sh` requires GitHub Actions signer identity for precisely `baobab-platform/baobab-dev/.github/workflows/publish.yml@refs/tags/vN.N.N`; caller propagates release tag; CLI-argument negatives in tests | Real GHCR/Sigstore certificate subject and signed platform-level predicates must pass on release image |
| Registry integrity | `registry-integrity.yml` rejects fewer/more than four release contracts, wrong expected tags/digests, missing/duplicate image and attestation descriptors, and checks actual per-arch retrieval and exact Sigstore identity; limits `workflow_run` to successful push events. PR event exercises read-only released-contract verification | Long-lived independently retained evidence and signed machine-readable release manifest are not yet qualified; release body remains human-readable source of record |
| Negative controls | `tests/test_trivy_db_freshness.py`, `test_verify_release_contracts.py`, `test_verify_image_identity.py` run before lockfile resolution in PR publish sanity check | CI must succeed on R5 final head; tests do not substitute real hosted registry/approval proof |

**Evidence so far:** a read-only `Verify Released GHCR Contracts` PR run [41596119254](https://github.com/baobab-platform/baobab-dev/actions/runs/41596119254) completed successfully on an **earlier** R5 head; the earlier R5 `Frozen Lockfile Integrity` also passed its Python negative tests. These are **not final-head acceptance**. Later pushes cancel superseded PR build legs by design; cancellation is not a completed eight-image PASS.

**Important inherited security restriction:** `scripts/dev10_kernel_risk_gate.py` explicitly restricts the short-lived, **development-only** CVE treatment to PR #48/#50/#57 or permitted development main, not the new PR #58. This R5 PR must not quietly expand that approval scope to make CI green. Unless the vendor remediation is available or a new independently attributable, scoped **development** risk decision is obtained, its affected CVE gates may legitimately block and MUST be reported as such. This is separate from the stricter NO-exception stable-tag rule.

**Residual public-registry boundary:** untagged content and `r5-candidate-*` tags may still be readable within GHCR's existing repository permissions after the exact digest validation. Stable consumer-facing version/major/`latest` tags wait for protected promotion; a truly **private quarantine registry** is future infrastructure work requiring its own custody and permission design. Do not describe a run-scoped GHCR candidate tag as a private repository.

**Next gate:** obtain current-head eight-image tests, provider Trivy database readbacks, latest-release integrity check, exact digest/attestation/consumer dry run, and independently protected environment configuration. **Defer broad 1,700-line workflow modularisation and performance work until those safety controls have evidence.**

## Exit criteria

Strict current-head CI + eight-image AMD64/ARM64 tests, actual SHA-pinned build/scan, Trivy freshness and negative tests, private-package consumer qualification, signed provenance and SBOM readback, failure injection for incorrect tag/digest/arch and stale DB, and a full protected-release dry run. No claim of these results is made by source changes alone.

## 3 November 2026 — R4 synchronization and R5 hardening follow-up

The R5 review branch now has **the current R4 branch as an ancestor**,
including the Maven 3.10.0 Guava-guard correction, `tmux -V` doctor readback,
and a security-focused checkout test that checks every checkout independently
rather than insisting the publishing workflow contain exactly four checkouts.
The original [R5 failure 41596743784](https://github.com/baobab-platform/baobab-dev/actions/runs/41596743784)
therefore must not be reinterpreted as a failure of this synchronized tree.
Fresh **final-head** CI is required for any R5 PASS claim.

### Added source controls

- `scripts/verify_release_environment.py` uses the real GitHub REST
  Environment and selected deployment-tag policy responses. Promotion denies
  missing independent required reviewers, self-review permission, absent
  selected tag rules, broad/mixed branch policies, mismatched environment,
  prerelease refs, or lack of a policy matching the exact release tag.
  A deployment job merely naming an Environment is **not** proof its
  settings were configured. `tests/test_verify_release_environment.py`
  provides positive/negative policy fixtures.
- `scripts/promote_release_tags.sh` performs independent candidate-tag and
  digest preflight, forbids remapping an existing immutable stable-version tag,
  creates and checks **four** version tags before touching twelve mutable
  aliases, snapshots previous alias pointers, rechecks for concurrent changes,
  and attempts reverse-order compensation if a later alias update fails.
  The journal is exported even for failed jobs. `tests/test_release_promotion.py`
  runs the success, idempotent retry, immutable-tag-rebind and partial-failure
  recovery paths against a disposable mock CLI. No real GHCR state is changed
  by these unit tests.
- `tests/test_r5_release_boundaries.py` locks the new invariant that
  eight-leg validation remains read-only, while only stable-tag digest
  publication, signing, independently protected promotion and release have
  the necessary privileges and correct dependencies.

### Registry non-atomicity is an explicit remaining operational risk

GHCR offers **no atomic transaction for four separate image version tags and
twelve moving aliases**. Compensation can restore a previous moving alias
when one existed; it cannot safely erase a previously absent alias or delete
a newly created version tag without risking shared OCI manifest content.
Therefore a failed promotion may expose partially staged version tags. The
workflow **fails**, suppresses GitHub Release, retains a recovery journal,
and requires independent inspection before reattempt. Neither the job nor
the runbook should claim an *atomic* registry cutover.

### Acceptance remains HELD

The R5 branch is **not entitled** to PR #57's temporary 295-CVE development
allowance. On the earlier R5 scan the rejection was correct: 12 CRITICAL and
283 HIGH matches on `linux-libc-dev=7.0.0-42.42`; the restriction must
not be altered by ordinary CI remediation. There is no owner-authorized
v1.5.0 release waiver. Source tests and read-only published-contract
checks are not substitutes for a complete protected release exercise,
which remains prohibited without its independent approvals.

The signed SBOM/provenance verification still needs **content-level**
confirmation of both platform-specific statements and source/material
commit identities, beyond proof that matching OIDC-signed attestations
exist. Hosted Codespaces/private-package and native consumer proof also
remain separate DEV-10/DEV-14 holds. **Do not start the broad publishing
workflow modularisation until these release-safety controls are qualified.**
No PR merge, release tag, or image publication is authorized by this entry.

### Signed native artifact content binding — later R5 source addition

`scripts/verify_signed_release_predicates.py` now compares the **two distinct
verified Cosign in-toto SLSA v1 predicates** and **two verified SPDX predicates**
against the exact AMD64/ARM64 BuildKit predicates extracted from the candidate
OCI index. A missing, duplicate, substituted, wrong-type or malformed signed
payload fails closed. `tests/test_signed_release_predicates.py` exercises
positives/negatives with synthetic DSSE envelopes, without faking external
Sigstore evidence.

The tag-only `release-digests` job also pulls the **exact remote child digest**
and verifies the OCI revision label equals the immutable `GITHUB_SHA`.
The `publish` job verifies signature/OIDC as before and additionally runs
the signed-content comparison **before exporting candidate records**,
retaining an evidence manifest for each target.

**Still unqualified:** no actual R5 stable-tag GitHub Environment / GHCR /
Sigstore release run has exercised this newly added parser. Its real Cosign
output encoding, full two-platform roundtrip and signed source/material identity
must be demonstrated on a controlled non-GA test before approval. Synthetic
unit tests are not a replacement. The independent 295-CVE release block and
owner-authorised staging/production governance remain unchanged.

## 3 November 2026 — #57 merged; #58 independent native-registry verification

- R4 PR #57 merged to `main`. GitHub automatically retargeted stacked R5
  PR #58 to `main` after a direct base-change attempt was refused while
  its parent PR was still registered in the stack. No branch rewriting,
  release tags, registry writes or #58 merge were performed for this follow-up.
- A source regression test previously expected malformed
  `CHILD_DIGEST` GitHub expression syntax; corrected it to the actual
  secure `${{ steps.exact.outputs.child }}` expression without weakening
  the remote-digest scan.
- `registry-integrity.yml` now checks all four advertised release contracts
  with a separate read-only verification helper and retained evidence.
  That helper insists on **both** AMD64/ARM64 native image manifests,
  manifest-linked BuildKit attestation siblings, source commit labels,
  SLSA v1 and complete-package SPDX predicates, independent Cosign
  validation and exact signed predicate content per architecture.
  The verifier regenerates exactly the documented file-trimmed SPDX
  projection; it does **not** remove any package inventory.
- `verify_signed_release_predicates.py` now additionally requires every
  signed DSSE statement's subject SHA-256 to match the exact immutable OCI
  index under review. A signature for an unrelated digest must fail even if
  the signer, predicate schema and predicate hashes otherwise match. Unit
  tests include wrong-subject and cross-platform substitution negatives.
- GitHub source CI on R5 head `ab2ab97` successfully ran the new Python
  unit controls in DEV-10 onboarding. The live read-only registry-integrity
  run [41616115702](https://github.com/baobab-platform/baobab-dev/actions/runs/41616115702)
  verified all v1.4.4 tag digests, both image/attestation descriptors and
  signatures, but **DENIED exact BuildKit-to-signed SLSA predicate binding**
  for all four published profiles. This is an **open integrity finding**, not
  evidence of confirmed compromise or an acceptable PASS. The historical
  v1.4.4 publish path might have transformed its attested predicates, but
  a signed-content inconsistency cannot be assumed benign.
- Added redacted SHA-256 fingerprint diagnostics and bounded DENIED evidence
  files (no full provenance, tokens, source or private dependency details).
  The negative check remains blocking. Reconcile archived v1.4.4 signing
  semantics using actual hashed predicate evidence; do not grandfather
  old releases into the stronger R5 contract silently. The old
  signature-existence-only check independently passed, which does **not**
  demonstrate content equivalence.
- R5 still carries **no development CVE exception**, and no protected
  stable-tag GHCR/Sigstore end-to-end proof. A failed PR CVE gate must
  not be fixed by extending #57's risk scope without a separate
  attributable decision. R5 remains unmerged; release/promotion held.
