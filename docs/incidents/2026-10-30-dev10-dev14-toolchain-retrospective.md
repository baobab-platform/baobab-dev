---
title: DEV-10 / DEV-14 Developer Toolchain Retrospective
description: Evidence-based 2026 lessons from Baobab Dev Containers, Codespaces, vulnerability scans and multi-architecture qualification.
---

# DEV-10 / DEV-14: developer toolchain lessons learned

**Recorded:** 30 October 2026  
**Repositories:** Baobab Dev PRs [#48](https://github.com/baobab-platform/baobab-dev/pull/48) (DEV-10) and [#50](https://github.com/baobab-platform/baobab-dev/pull/50) (DEV-14)  
**Purpose:** permanent, evidence-backed reference; see the [upgrade playbook](../usage/toolchain-upgrade-playbook.md).

## Executive conclusion

Baobab Dev was challenging because one shared image is **simultaneously** a cross-language toolchain, an Ubuntu software distribution, a multi-arch OCI product, a supply-chain security boundary and a contract consumed by separate repositories. A tool passing its own version check does **not** prove that consumers can use it; a successful source test does **not** establish that the built image is secure; and a green scanner check only establishes that the **policy then in effect** passed.

**Rule established:** resolve and pin before building; verify the actual installed bytes and non-interactive lifecycle; test all profiles and CPU architectures; verify registry and consuming repos independently; treat development risk, independently demonstrated non-applicability and protected release approval as different decisions.

## Observed challenges and corrective lessons

| Failure | Evidence-based cause | Correction / future control |
| --- | --- | --- |
| GHCR frontend tag disappeared post-release (13 Sep) | `1.3.0-frontend` tag and digest had been verified on publication, but ZuriBeans Codespaces later received `No manifest found` and booted an Alpine **recovery** container. Deletion actor unverified. [Incident](2026-09-13-ghcr-v1.3.0-frontend-manifest-loss.md) | Revalidate published tag→digest and both OCI child manifests on schedule, not just at release. Never diagnose the recovery shell as the intended image. |
| Codespaces Corepack prompt (18 Sep) | Floating image pnpm disagreed with consumer `packageManager: pnpm@11.24.0`; unattended lifecycle waited for download confirmation. Disabling network alone broke Corepack's Known Good Release lookup. [Incident](2026-09-18-codespaces-corepack-interactive-prompt.md) | Pin the **same exact** pnpm version; use `COREPACK_ENABLE_NETWORK=0` **and** `COREPACK_DEFAULT_TO_LATEST=0`; run stdin-closed, timed, `--frozen-lockfile` installs. |
| Playwright browser not found | Image's floating Playwright CLI and consumer's `@playwright/test` expected different browser revisions. [Recurrence](2026-09-18-codespaces-corepack-interactive-prompt.md) | Global browser downloader and project test runner are a coupled contract: pin together and run a real browser launch. |
| DEV-10 onboarding false green | An old test wrapper did not reliably propagate the real Node workspace-membership check; Python installed-audit incorrectly mixed `pip-audit --path` with requirements-only `--disable-pip`. [DEV-10](../usage/dev10-locked-onboarding.md) | Execute the real check and preserve exit status; prove missing workspace and verifier-exit-42 negatives; audit lock source and installed distributions separately. |
| Vulnerable libraries embedded inside healthy-looking tools | npm and pnpm bundled distinct undici copies; pip vendored urllib3, msgpack and setuptools/pkg_resources; Maven included Guava; compiled Go CLIs contained their own dependency graphs. [Python](../usage/image-python-security.md), [CLI](../usage/cli-security-rebuilds.md) | Read actual image modules/JARs/Go build info; checksum-pin source, rebuild with compatible vendoring and run functional tests. Parent package version alone is insufficient. |
| Multi-architecture image scan mechanics | Buildx's provenance-bearing OCI index could not be treated like a local single-manifest image. Trivy `--input` required the extracted OCI **directory**, not the raw exported tar; final image also had runner disk constraints. [Publish workflow](https://github.com/baobab-platform/baobab-dev/blob/47f76836854d42b7f08b2ee1796d2c902706dacc/.github/workflows/publish.yml) | Qualify a specific local image per profile/architecture; unpack the `final` OCI layout, free temporary space, separately read back the published index/digest and SBOM/signatures. |
| Previously green security CI concealed wider exposure | The historical v1.4.4 scans used `--ignore-unfixed` and path skips. A present-day unfiltered replay on eight immutable historical images returned 441–501 HIGH/CRITICAL matches (including 398 kernel-header package matches). [Comparison](../assessments/dev10-v144-retrospective-pnpm12.md) | Record exact scanner flags, exclusion policy, vulnerability DB date, digest and inventory. A historical green check does not mean “zero vulnerabilities.” |
| Current strict scan failed all profiles | Unfiltered Trivy found **295** Ubuntu `linux-libc-dev 7.0.0-42.42` advisories (283 HIGH, 12 CRITICAL) brought in by the native compiler dependency chain. Package inspection showed 1,039 UAPI headers and two documentation files, **no executables**. Canonical kernel-source status was **287 pending / 8 needed**. [Investigation](../assessments/dev10-linux-libc-dev-risk-decision.md) | Do not remove required compiler headers or blanket-suppress scans. Compare upstream and Ubuntu source, shipped binary and host kernel separately; make per-CVE decisions. |
| Upstream file-path evidence was misread as permission | Upstream Linux CNA records showed 248 implementation-only paths and 47 kernel-private-header paths, with no direct matching shipped UAPI header. Ubuntu patch/backport and downstream ABI consequences were **not** fully verified. [Review register](../assessments/dev10-cve-applicability-review-register-20261030.tsv) | `not_affected` is an evidence-backed technical conclusion, not an inference from a package name or header count. Retain `under_investigation` when uncertainty remains. |
| CodeQL HIGH cache-poisoning | Privileged Publish workflow could check out dispatch-selected source and execute `config/resolve.sh --locked` with shared caches. [CodeQL resolution](../assessments/dev10-codeql-cache-poisoning.md) | Use immutable `github.sha`, no persisted checkout credentials, manual main-only validation, and tag-push-only release privileges; run source-level negative tests. |
| Stacked GitHub PR workflow blocked merging | #50 was based on an older #48 head. Direct merge, auto-merge and dependent base retarget were rejected by GitHub's stacked PR rules. | Incorporate upstream source without force-pushing `main`; verify the intended downstream diff, run **new final-head CI**, and merge using GitHub's stack-supported flow. |
| Owner-directed development risk was not a real VEX | Shared's pinned Foundation implementation could only skip the scan via a declared exception. The responsible security personnel was designated **Wekhaso Nabusiu**; the user directed bounded development residual-risk acceptance, not a signed or independently verified `not_affected` decision. [Issue #54](https://github.com/baobab-platform/baobab-dev/issues/54) | Apply a replacement **unfiltered** Foundation scan and all eight unfiltered Publish scans, with exact-package/CVE scope and expiry. Deny other CVEs/packages/secrets/versions/PRs/tag releases; retain residual risk and remediation review. |

## Why source tests were not sufficient

The acceptance boundaries are distinct:

1. **Configuration:** `config/versions.yaml` → `config/resolve.sh` → committed `config/versions.lock`; `resolve.sh --locked` must refuse drift.
2. **Installed bits:** base OS packages, nested npm/pnpm modules, Python system/pipx/Poetry, vendor libraries and compiled CLI modules checked in the built image.
3. **Lifecycle:** real `baobab-post-create`, noninteractive frozen project install, workspace membership, original exit code and missing-tool denial.
4. **Multi-arch:** `final`, `infra`, `frontend`, `frontend-e2e` on both linux/amd64 and linux/arm64.
5. **Security:** unfiltered vulnerability evidence, immutable identity, separate development risk versus technical VEX and protected release.
6. **Distribution:** published GHCR tag/index/child digests, provenance, signature, post-publication integrity and consumer pullability.
7. **Adoption:** real fresh private Codespaces, authentication to GitHub Packages, consumer tests and rollback; DEV-14 doctor output is a **toolchain observation**, not native ENG-ONB execution.

### A specifically deferred upgrade: pnpm 12.16.1

A two-architecture diagnostic of pnpm 12.16.1 passed on a **small frozen offline workspace fixture**. That did not justify changing the adopted default `pnpm 11.24.0`. Nabhold, ZuriBeans, Thamani and baobab-cp still had exact pins/bootstraps, and real Corepack and consumer lifecycle migration was unqualified. A promising smoke test is **not** a cross-repo release decision. See [pnpm retrospective](../assessments/dev10-v144-retrospective-pnpm12.md).

## Verified snapshot and explicit limitations

At the time of this record:
- PR #48 head `47f76836854d42b7f08b2ee1796d2c902706dacc` passed its [DEV-10](https://github.com/baobab-platform/baobab-dev/actions/runs/41050318591), [Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/41050320067) and [eight-image Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/41050318668) workflows, plus Security/CodeQL and diagnostic checks.
- PR #50 head `54febc3f26d97d27588c0adb6644d694a7cd55f9` passed [DEV-14 doctor](https://github.com/baobab-platform/baobab-dev/actions/runs/41055743303), [Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/41055744850) and [Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/41055743241), plus DEV-10/Security/CodeQL.
- **Both were open and unmerged.** No protected release, production certification, Codespaces-fleet migration, new live provider acceptance, or durable independent VEX clearance was proven.
- Temporary **development-only risk** scope covered PR #48, dependent PR #50 and untagged main; exact package and 295 known CVEs only, expiry **2026-11-13 00:00 UTC** (repository exception expires 2026-11-12). All technical CVE dispositions remain reviewable. It is not a vendor fix or protected-release exception.
- GitHub Actions artifacts in the investigation were observed with a **15-day** retention cap. Preserve audit-critical evidence in separately governed durable custody. Sanitized Trivy JSON excludes secret payloads; unfiltered original scan runs and failed receipts remain linked.

## Institutional prevention actions

| Control to institutionalize | Accountable function | Required proof |
| --- | --- | --- |
| Cross-repository version/ABI compatibility inventory | DevEx and each consumer owner | pnpm/Playwright/Java/Go/Rust/Python/Node lock and image-digest matrix |
| Frozen, real, noninteractive onboarding and denial tests | CI + Codespaces maintainers | Cold install, exit-code propagation, workspace and private package auth |
| Embedded/vendored dependency and image security qualification | Security + build engineers | Actual installed bytes, source provenance, scanner flags, all 8 images |
| CVE exception expiry and host-kernel separation | Wekhaso Nabusiu, designated security risk owner | Scope-specific risk register, independent patch/ABI disposition, expiry and revocation |
| GHCR release durability and recovery | Release engineering | Tag/digest and child index scheduled checks; known-good rollback |
| Consumer and stack-aware merge gates | Repository and consumer owners | Final-head CI, accepted stack merge, actual Codespaces rollout receipts |

These are **recommendations / outstanding controls**, not a claim they have already all been delivered.

**Operating lesson:** learn from established toolchains, reuse proven controls, question partial evidence, re-engineer failed paths and document the evidence. Future maintainers should start with the [repeatable upgrade playbook](../usage/toolchain-upgrade-playbook.md), not reconstruct this incident from 100+ commits.
