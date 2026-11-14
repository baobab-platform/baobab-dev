# DEV-10 repository-wide assessment and PR #74 remediation

**Assessment date:** 14 November 2026  
**Repository:** `baobab-platform/baobab-dev`  
**Target:** PR #74, branch `dev10/v1.5.2-rc-verifier`  
**Disposition:** Remediation in progress; do not merge, tag, publish, or promote until final-head CI and independent security qualification are complete.

## 1. Executive assessment

The history from PR #48 through PR #71 shows that the most expensive failures were not missing scripts; they were incorrect assumptions about what the scripts, APIs, build artifacts, and release identities actually represented. The successful fixes used real installed-package metadata, actual GitHub API payloads, immutable OCI digests, exact workflow identities, and negative tests. Several later regressions occurred because one workflow or verifier retained an older assumption after another part of the system had evolved.

PR #74 should therefore be treated as a release-system qualification change, not a routine CI repair. The immediate code/test defects have been corrected on the PR branch, and the GA signer identity flow has been strengthened. The Foundation security gate remains a deliberate blocker: PR #74 is in assessment scope only and is not authorised for the existing eight-CVE development risk exception.

## 2. Historical PR findings: challenges and solutions that worked

The closed-PR search in the requested range identified the following engineering PRs and dependency-maintenance PRs. Numeric gaps in the range did not resolve to closed PR records and are not treated as pull requests here.

| PR | Challenge observed | Solution / lesson retained |
|---|---|---|
| #48 | Trivy reported 295 kernel-source advisories against Ubuntu `linux-libc-dev`. A headers-only binary package did not prove the host kernel was safe or that every advisory was irrelevant. | Preserve full unfiltered scans, exact package/file inventories, Canonical and upstream CVE evidence. Keep each disposition under investigation; no blanket VEX or scanner suppression. Separate container headers from the host kernel. |
| #49, #51, #56, #60, #63 | Routine Dependabot dependency updates. | Keep these changes narrow and validate the relevant lockfiles/workflows; do not mix unrelated dependency churn into release-policy changes. |
| #50 | DEV-14 doctor/Codespaces qualification needed to validate the actual shared development environment, not just static configuration. | Use the real pinned Shared checkout/toolchain, preserve consumer-owned authentication boundaries, and distinguish source/doctor checks from a real fresh Codespace qualification. |
| #57 | Node 26 no longer bundled Corepack; pnpm 12 changed package-manager bootstrap/patch behaviour; consumers had mixed toolchain baselines. | Pin exact Node/pnpm versions, provision Corepack separately, remove pnpm-11-only patch assumptions, test cold network bootstrap followed by disconnected frozen install, and qualify consumers before release. |
| #58 | Release workflows mixed building, scanning, signing, and registry mutation; a successful build was being treated as release proof. | Build without publishing, scan actual local and exact remote digest content, create signed provenance/SBOM evidence, and keep GHCR mutation in a separate protected promotion job. |
| #62 | Shared checkout provenance and Go dependency vulnerabilities were not sufficiently bound to a deterministic source state. Build-cache export failures also affected reliability. | Verify exact Shared source commit and clean checkout state, remediate the actual affected binaries/module graph, and keep cache export best-effort rather than allowing cache failure to become a release failure. |
| #64 | Tag rules had become version-specific and drifted between release workflow and verifier scripts. | Establish canonical SemVer/RC policy and protected release/promotion boundaries. Keep security eligibility separate from syntactic tag validity. |
| #65 | Protected promotion approval evidence was not independently captured before registry mutation. | Read native GitHub deployment approval records and fail closed when independent approval is absent, rejected, wrong-environment, or self-approved. |
| #66 | Pending protected deployments lacked deterministic reminders/escalation. | Add a read-only scheduled monitor; it may notify/escalate but must never approve, cancel, or bypass a deployment. |
| #67 | GA rebuilt images after RC qualification. Same source does not imply the same OCI digest. | Make GA reuse the exact four qualified RC digests; verify source SHA, workflow identity, artifact records, and digest continuity before mutation. |
| #68 | The approval verifier required `submitted_at`, which the actual GitHub approvals API did not return; it also had to distinguish a human reviewer from a bot wait timer. | Use the real API schema, exclude bot records, require a different human reviewer and exact protected environment, and test real-shaped positive/negative fixtures. |
| #69 | The independent promotion runner did not have Cosign installed, although the build/signing runner did. | Install the same SHA-pinned Cosign release in the promotion runner; do not disable signature/provenance checks to make promotion pass. |
| #70 | GA emitted `ga-reused-candidates`, but release assembly downloaded RC `published-info-*` artifacts. | Select artifacts by channel and require exactly four well-formed target records; do not rewrite an immutable GA tag to repair a tagged workflow. |
| #71 | The verifier accepted v1.5.0 RC tags but rejected the explicitly approved v1.5.1 RC family. | Update tag inference and explicit digest verification together, preserve exact OIDC identity, add positive/negative regression tests, and cut a new RC tag after the fix rather than rewriting the old tag. |

### Cross-PR lessons

1. **An implementation is not evidence that the control works.** A safeguard must be exercised against the real external system and real output format.
2. **One source of truth is required for versions and release identity.** Duplicated regular expressions and hand-maintained lock values caused drift.
3. **The artifact, not the tag name, is the release unit.** RC-to-GA continuity must be digest-based.
4. **Approval evidence must be authenticated and independently attributable.** A reviewer name or evidence URL in JSON is not proof of an authorised approval.
5. **Negative tests must fail for the intended reason.** A timeout, missing binary, fixture mutation, or API-schema assumption must not be mistaken for a valid security denial.
6. **Do not repair a red security gate by broadening an exception.** A policy denial can be the correct outcome.

## 3. PR #74 CI root causes and remediation

The first PR #74 CI inspection identified independent failures. The following changes have been made on the PR branch; the new final-head workflows must still prove them.

| Failure | Root cause | Change made |
|---|---|---|
| Release-identity shell regression exited 126 | The test invoked `verify-image.sh` directly although the file is not executable in the checkout mode. | The test now invokes the verifier explicitly through Bash. |
| RC identity regression | A stale test still expected `v1.5.2-rc.1` to be rejected even though PR #74 adds that RC family. | Positive/negative test cases now match the intended release policy. |
| Security-decision unit fixture mismatch | A negative test mutated a shared global package fixture, contaminating the subsequent positive test. | Each decision fixture now receives its own package-inventory object. |
| Frozen lock drift | `config/versions.yaml` pinned pnpm 12.21.0 and Playwright 1.65.0 while the generated `config/versions.lock` still contained 12.16.1 and 1.64.1. | The lock values have been synchronized. The resolver now downloads both official pnpm Linux assets, verifies GitHub SLSA provenance against the exact `pnpm/pnpm` release workflow and `refs/tags/v12.21.0`, and recomputes each SHA-256 before accepting the lock. The final-head resolver job must still execute this check. |
| Published-image onboarding tested a stale image and initially used the wrong registry tag spelling | `dev10-onboarding.yml` exercised 1.4.4 even though v1.5.1 is the current stable release. The first native ARM64 run then confirmed that the GHCR tag is `1.5.1`, not the Git release tag spelling `v1.5.1`. | The workflow now resolves `ghcr.io/baobab-platform/baobab-dev:1.5.1` to an immutable OCI index digest, verifies exactly one linux/amd64 and one linux/arm64 manifest, then runs the same lifecycle suite on native `ubuntu-26.04` (amd64) and `ubuntu-26.04-arm` (arm64) runners using that exact digest. |
| GHCR observer rejected stable GA signatures | GA reuses the qualified RC digests. Their Cosign certificate identity is the RC tag, not the later GA alias. The observer incorrectly required the GA tag as signer identity. | The observer now parses declared signer metadata, resolves the exact signer tag to the GA source SHA, validates the actual GitHub Actions run API record (completed/success, push event, exact tag, SHA and canonical publish workflow), then verifies exact OIDC identity and native signed artifacts. |
| Version-specific verifier drift | The release-contract and registry observers still encoded earlier RC families after the release policy had evolved. | The image verifier now calls the shared canonical `release_tag_policy.py`; release-contract, registry-attestation and signer-resolution logic use the same strict SemVer/RC grammar. Security release eligibility remains a separate gate. |

### GA signer continuity now enforced

- GA candidate records carry the exact `signer_tag` and `signer_run_id` from the qualified RC workflow.
- The GA artifact contract requires all four profiles to agree on that signer tag and run ID.
- The GitHub Release body displays the signer source and qualified run; its Cosign examples use the signer tag, not the GA alias.
- The registry observer checks the Git tag object resolves to the release source SHA, checks the actual GitHub Actions run record, then checks exact Cosign workflow identity, issuer, native image revision labels, SLSA provenance, and SPDX content.
- Old releases without signer metadata are resolved by a fail-closed same-version RC tag lookup; zero or multiple matching RC tags are denied.

This is a correction to the release observer, not proof that the live registry has passed. The GitHub tag ruleset itself was not readable through the available repository interface and remains an owner/admin verification item; a SHA check is not a substitute for server-enforced immutability. The updated `Verify Released GHCR Contracts` workflow must succeed against the actual v1.5.1 release.

## 4. Security gate: intentionally unresolved

The current PR #74 Foundation evidence contains eight HIGH Trivy findings for `linux-libc-dev=7.0.0-43.43`:

- CVE-2022-50240
- CVE-2025-40190
- CVE-2026-68103
- CVE-2026-72198
- CVE-2026-74578
- CVE-2026-89805
- CVE-2026-98376
- CVE-2026-98420

The raw Trivy report lists no fixed version for these findings. The executable `scripts/dev10_kernel_risk_gate.py` scopes this additional package/CVE set to PR #71 only. Issue #54 explicitly adds PR #74 to review scope **without** extending the exception. Therefore the PR #74 denial is correct and must not be changed to make CI green.

There is also an approval-custody documentation discrepancy: the visible 12 November issue #54 decision records the 7.0.0-43.43/eight-CVE amendment for PR #62 only, while the current executable gate names PR #71 only. The gate comment says an owner-authorised amendment exists, but the retrieved issue/PR record does not contain the corresponding exact PR #71 authority. This requires owner reconciliation; do not infer or fabricate approval.

No new VEX, scanner ignore, package suppression, CVE allow-list extension, or release exception was added for PR #74. The image is a development toolchain, but that does not make kernel findings disappear or establish host-kernel safety. A separate per-CVE source/patch and exact binary-package applicability review, independent reviewer approval, and digest-scoped decision are required before changing this gate.

## 5. Performance, code-quality and architecture recommendations

### Already working in the right direction

- The Docker build uses BuildKit cache mounts for package-manager caches.
- The pnpm provisioning test performs a real cold network bootstrap followed by a disconnected frozen install, and asserts the lockfile is unchanged. The new publisher-asset test also covers old GH CLI rejection, attestation failure, digest mismatch and exact source-workflow binding.
- The build/publish boundary separates read-only candidate builds and scans from protected GHCR promotion.
- Cache export is non-blocking, so a cache backend outage does not become a release-integrity bypass or a false build failure.
- The post-create/update-content lifecycle deliberately reuses one implementation so Codespaces prebuilds capture dependency installation while post-create remains a correctness safety net.

### Further improvements, in priority order

1. **Keep cache trust boundaries.** Evaluate `mode=max` intermediate-layer caching only for trusted main/release builds, with cache scopes separated by image profile and architecture. Do not grant PR build jobs registry write access merely to improve cache hit rate. Keep cache export best-effort and never make a cache hit a correctness requirement.
2. **Preserve lockfile-first dependency layers.** For any future workspace dependency installation in an image build, use a lockfile-only fetch layer followed by offline/frozen installation. The existing pnpm cold-bootstrap/offline-replay test is the acceptance contract; do not replace it with an unrepresentative one-line lockfile fixture.
3. **Consolidate release policy.** Continue removing duplicated tag grammars from shell/workflow scripts. Canonical syntax belongs in one policy module; security approval of a version/ref remains a separate signed decision.
4. **Move risk decisions out of code constants only after trust is established.** The durable design is a signed, expiring, revocable decision record bound to repository, event/ref, package version, CVE IDs, severity, fixed-version status, image digest, profiles, architectures, evidence hashes and independent reviewer identity. The current repository has no committed production trust key or independently appointed reviewer; do not substitute an unsigned JSON name/URL.
5. **Refactor workflows only after their gates are qualified.** Extract stable reusable composite actions for artifact contracts, digest verification and evidence upload after the connected workflows pass. Premature workflow modularization makes it harder to identify which gate produced a failure.
6. **Retain actual external-output fixtures.** Keep captured GitHub API approvals, GHCR OCI manifests, Trivy JSON and Cosign/SLSA/SPDX payloads as versioned, provenance-labelled test fixtures. Handcrafted fixtures remain useful for negative tests but must not be the sole evidence.
7. **Make evidence completeness machine-verifiable.** Every gate should emit source SHA, workflow/run ID, image index and child digests, architecture, scanner database/version, raw report hash, decision ID, and explicit pass/deny reason. Missing evidence must remain a denial.

## 6. Acceptance criteria

PR #74 remains open and unmerged until all of the following are satisfied:

- [ ] Final-head source unit tests and shell syntax checks pass.
- [ ] `config/resolve.sh --locked` and upstream checksum validation pass against the synchronized lock.
- [ ] DEV-10 onboarding passes against the immutable v1.5.1 OCI index digest on both native architectures.
- [ ] DEV-14 developer doctor and all required Foundation/Publish/security workflows pass.
- [ ] The registry observer verifies all four live v1.5.1 image digests, both architectures, exact signer tag, successful publish run, exact OIDC identity, SLSA provenance and SPDX inventory.
- [ ] PR #74's eight-CVE package scope receives a separate, attributable security decision or the underlying package findings are remediated. No implicit extension from PR #71 or PR #62.
- [ ] A repository administrator independently confirms an active GitHub tag ruleset prevents update and deletion of every `refs/tags/v*` release tag. The recovery script and remote-SHA check do not replace server-enforced immutability.
- [ ] The four image profiles and both architectures have reproducible consumer qualification evidence; a source test is not a substitute for an actual Codespaces/consumer test.
- [ ] One consolidated qualification report records source SHA, image digests, test runs, evidence hashes, approvals, exceptions and unresolved items.

**No release action has been performed:** no tag was created or moved, no image was published or promoted, and PR #74 was not merged. The CI state at the time of this report is pending requalification of the latest PR head.


### Research references

- Docker BuildKit external cache and `mode=min`/`mode=max`: https://docs.docker.com/build/cache/backends/ and https://docs.docker.com/build/cache/backends/registry/
- pnpm's CI/Docker guidance recommends a lockfile-only `pnpm fetch` layer for ephemeral builders, followed by install/build layers: https://pnpm.io/docker
- GitHub documents cache poisoning risks and the read/write trust boundaries for workflow caches: https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching
- BuildKit's concurrent build-graph solver and unused-stage elimination: https://docs.docker.com/build/buildkit/


A local harness mirroring the five pnpm-attestation test cases was run against the verifier shell logic with mocked GitHub CLI and download responses; all five passed. The cases cover exact signer-workflow/source-ref arguments, old-CLI rejection, attestation failure, checksum mismatch and malformed-input denial. This is not a final-head run of the repository's complete test suite and does **not** prove the live pnpm release assets or their real attestations; the final-head resolver workflow must perform that external verification.

Additional primary references for the publisher check:

- GitHub CLI attestation verification flags: https://cli.github.com/manual/gh_attestation_verify
- pnpm v12.21.0 release workflow and its `actions/attest-build-provenance` step: https://github.com/pnpm/pnpm/blob/v12.21.0/.github/workflows/release.yml
- pnpm's release-asset verification guidance: https://get.pnpm.io/README.md
- GitHub CLI signer-workflow prefix-match fix (minimum enforced by the verifier): https://github.com/cli/cli/security/advisories/GHSA-wjmr-j3rp-mh2g
- GitHub CLI case-insensitive source-ref comparison fix (same minimum): https://github.com/cli/cli/security/advisories/GHSA-4mq3-hpgx-9cx8


### Final-head execution status

At the time of this update, PR #74 head is `6addb6b4d9db2eec4a3a60026f9d94ff354c4bd6`. The GitHub Actions connector returned no workflow runs or combined status checks associated with that head or its PR merge ref. Earlier runs were queued/cancelled and do not qualify the later code changes. The PR remains draft; do not interpret the absence of checks as a pass. Final-head workflow execution is still required.
