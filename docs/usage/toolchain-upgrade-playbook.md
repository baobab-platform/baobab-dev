---
title: Developer Toolchain Upgrade Playbook
description: Mandatory repeatable procedure for changing Baobab Dev Container runtimes, packages, security patches and consuming repositories.
---

# Developer toolchain upgrade playbook

**Owner:** Baobab Dev / Developer Experience + relevant engine or digital-estate owner  
**Applies to:** `baobab-platform/baobab-dev` toolchain, Dev Containers and GitHub Codespaces, profiles `final`, `infra`, `frontend`, `frontend-e2e`.  
**Why:** [DEV-10/DEV-14 lessons learned](../incidents/2026-10-30-dev10-dev14-toolchain-retrospective.md).  
**Principle:** **Resolve once, consume everywhere; qualify the actual image and actual consumer.**

## 0. Change proposal — required before implementation

Create one PR or tracked change package with:

| Field | Required record |
| --- | --- |
| Why now | Vulnerability ID, compatibility demand, end of support or measured defect |
| Current → proposed | Exact version, archive SHA256, source location, installed path and image profile |
| Affected components | Native compiler, embedded dependencies, OS packages, Java/Go modules, Corepack, browser revisions |
| Consumer owners | Nabhold, ZuriBeans, Thamani, CP, IAM, CMS, Pulse, Payments, ERP etc. **only when actually impacted** |
| Baseline | Current released image **digest** per profile and architecture, old tool lock and actual CI policy |
| Qualification | Exact source SHA, candidate digest, installed and source audits, negative tests, real Codespace plan |
| Security | Original findings, Canonical/upstream status, independent remediation or bounded risk case |
| Rollback | Previously qualified digest + consumer lock + known-good lifecycle, database backup when relevant |
| Governance | Development / staging / release scope; approval identity and expiry where applicable |

**Never upgrade several loosely related tool families just because new versions exist.** Split the work when their acceptance criteria differ.

## 1. Inventory the two sides of every version contract

The image is not the sole authority for project dependencies. For each planned change, check:

- `config/versions.yaml` and committed `config/versions.lock` in baobab-dev.
- Consumer `.devcontainer/devcontainer.json` image reference, `package.json.packageManager`, `pnpm-lock.yaml` / `package-lock.json` / `yarn.lock`, Python `uv.lock` / `poetry.lock`, Playwright test-runner revision, language/toolchain files and bootstrap commands.
- Any engine-owned JDK/Go/Rust/Python requirements that the shared image intentionally does not supply.
- All supported target profiles and AMD64/ARM64 support.
- Private GitHub Packages authentication and expected user/UID context.

**Coupled tools must move together.** pnpm image cache ↔ consumer `packageManager`; global Playwright browser download ↔ project `@playwright/test`; PostgreSQL client 17 ↔ server migration (separate, not implied). Node 24 and Python 3.14.x are platform baselines, but project requirements still govern their own locks.

A native pnpm 12.16.1 offline fixture passed on both architectures in October 2026; the **default remained 11.24.0** pending coordinated Nabhold, ZuriBeans, Thamani and CP adoption. Do not treat a fixture as approval for a four-repository migration.

## 2. Resolve without drift

Follow existing [version management](../architecture/version-management.md):

```bash
# After editing config/versions.yaml for a reviewable proposal:
./config/resolve.sh

# After committing the exact intended lock, CI/check-only path:
./config/resolve.sh --locked
```

Require checksum provenance and no dirty regenerated lock. Treat the lock as **data**, not executable shell. Select a supported upstream release, verify archive digest on **both** CPU architectures, and record original and replacement versions. Any mismatch fails.

If a published tool is being rebuilt to fix embedded dependencies, retain the upstream source release and explicit Baobab patch provenance; do not mislabel a rebuilt binary as an untouched upstream distribution.

## 3. Inspect actual dependency contents

Before and after the change, audit:

1. OS packages installed in the final image (including `linux-libc-dev` and library dev packages).
2. System Python, pipx-shared install and Poetry virtual environment **using installed metadata** (e.g. `pip-audit --path`); separately audit committed locked requirements and vendored packages.
3. npm's bundled modules **and** the independent Corepack pnpm distribution; distinguish duplicate `undici` copies.
4. Maven JARs and license files, compiled Go binary build information, embedded Java/Go source modules and plugin sources.
5. Any dependencies installed transiently to bootstrap an optional PPA or runtime: remove them when not needed and confirm this in the final built image.

Evidence must include **observed installed versions**, not simply a successful package-manager command. In October the outer pip/Poetry urllib3 fix left vendored urllib3 inside pip until pip's own vendoring process was used. See [Python](image-python-security.md) and [CLI source rebuilds](cli-security-rebuilds.md).

## 4. Qualify the native lifecycle (including failures)

Use the checked-out lifecycle code, the actual non-root Dev Container user, frozen repositories and stdin closed. In source/unit and disposable image tests prove:

- `uv sync --locked --no-managed-python` / exact Python lock selection, or the adopted locked equivalent.
- JavaScript `pnpm install --frozen-lockfile`, `npm ci` or immutable Yarn as dictated by the consumer, **never unlocked fallback**.
- Root workspace membership checks really run; a missing frontend entry fails rather than accidentally installing a nested package.
- `COREPACK_ENABLE_NETWORK=0` **and** `COREPACK_DEFAULT_TO_LATEST=0`; exact baked and project pnpm versions match. Version mismatch returns a bounded error, never a prompt.
- `baobab-verify` checks exact pnpm and the Node major; failure at any late lifecycle stage propagates the original nonzero exit code. Use a known fault-injection case such as exit 42.
- Actual Playwright browser launch with the consumer's exact test-runner version (where relevant).
- Native compiler/UAPI, Terraform, Java, Rust, Go and Docker/Compose smoke checks appropriate to the changed stage; no fictional missing toolchains.

DEV-14 `scripts/dev14-doctor.py` is intentionally **non-mutating**. It can report `LOCAL_TOOLCHAIN_OBSERVED`, not IAM/CP authority, runtime ENG-ONB cases or provider acceptance.

## 5. Build all candidate images; retain both passes and failures

The mandatory matrix is:

| Profile | linux/amd64 | linux/arm64 |
| --- | --- | --- |
| `final` | Build, smoke, Trivy and provenance | Build, smoke, Trivy and provenance |
| `infra` | Build, smoke, Trivy and provenance | Build, smoke, Trivy and provenance |
| `frontend` | Build, frozen Corepack, smoke, Trivy | Build, frozen Corepack, smoke, Trivy |
| `frontend-e2e` | Build, browser/frozen install, smoke, Trivy | Build, browser/frozen install, smoke, Trivy |

Buildx images with provenance/SBOM can be OCI indexes. For the local final-image scan, first unpack the OCI tar into a real `oci-layout / index.json / blobs/` **directory**, then point Trivy at the directory. Do not interpret the archive as a Docker save tar. Clean up temporary OCI tar/layers after validation to avoid runner disk exhaustion.

Pin SHA-based GitHub Actions and tool releases. Protect publish/signing permissions: a manually selected untrusted `workflow_dispatch` tag/ref must never control checkout before privileged execution. Use immutable `github.sha` and release-tag **push** gates. Keep CodeQL on.

## 6. Security and risk decision tree

First execute and retain the **unfiltered** HIGH/CRITICAL scan: all OS/library paths, secret detection, exact scanner version, actual target identity, CVE metadata, exit status and normalized sanitized reports.

| Condition | Required action |
| --- | --- |
| CVE affects installed executable or embedded dependency, supported fix exists | Patch/rebuild; verify installed bytes; rerun whole image matrix |
| Kernel source-package CVE matches userspace development headers | Check exact binary file manifest, Canonical/source fix/backport, UAPI/inline/macro/ABI and downstream use; **do not** infer kernel execution from a header package |
| Not enough code-path/vendor evidence | Mark `under_investigation`; escalate; do not assert `not_affected` |
| Verified not-applicable to exact image/product | Use approved, attributable, digest-scoped and expiring VEX per security governance, with negative tests |
| Development-only residual risk accepted | Record owner, exact package/version/CVE set, affected dev refs, expiry, preserved raw findings and deny rules; keep release controls independent |
| New CVE, other package/version, secrets, expired acceptance or protected release | **Fail closed**; start a new security decision instead of broadening an existing rule |

**Historical October 2026 decision:** developer-only treatment for the known 295 Ubuntu `linux-libc-dev 7.0.0-42.42` matches, PR #48/#50 and untagged dev main, expires **2026-11-13 00:00 UTC** (repository exception **2026-11-12**). Reusable Foundation used its exception mechanism, but a **replacement unfiltered Foundation scan** remained mandatory, as did all eight unfiltered Publish scans with an exact-CVE risk gate. This is **not** a release exemption, approved `not_affected` classification or proof of Ubuntu remediation. Issue [#54](https://github.com/baobab-platform/baobab-dev/issues/54) tracks continued vendor and security review.

Never set a blocking scanner to `--exit-code 0`, add broad ignore rules, drop native compilers, or declare vendor advisories fixed merely to obtain a green badge.

## 7. Qualify consumer reality, not only CI fixtures

For every impacted consumer, create a **fresh, run-owned** private Codespace/Dev Container using the candidate **immutable digest** and exact lock. Prove:

- Image actually pulled and started (not Codespaces recovery).
- Real credentials can access approved private GitHub Packages without exposing tokens.
- Noninteractive lifecycle completes with frozen locks and correct UID/caches.
- The consumer's actual build, typecheck, unit/integration tests and Playwright tests where applicable pass.
- Language/engine-specific additions (e.g. Java 21 or Rust) are present only where owned and required.
- Cleanup removes only run-owned resources; rollback reverts **both** image digest and consumer pins/lockfiles.

Do not use a PostgreSQL 17 client upgrade as permission to reuse an incompatible physical database volume; back up and qualify the **server migration separately**.

## 8. Distinguish PR, staging and release gates

The DEV-10/DEV-14 GitHub Actions green matrix is a **development-engineering** result. Before declaring a release:

- Check final **source SHA**, required CI and review threads; all tests must run on that actual head.
- Resolve stacked GitHub PRs using supported stack-aware merge operations; do not force-update `main` or assume old head results transfer.
- Independently qualify the intended promotion digest, signatures, attestations, SBOM and host/kernel boundary.
- Obtain any required staging/production security, operator and legal/provider certification; do not reuse a temporary development-only exception.
- Publish from reviewed tag push only, record image tag→digest/child manifests and perform independent readback.
- Retain past failure receipts, evidence artifacts and release rollback mappings in durable custody. Scheduled registry-integrity checking detects disappearance after release.

## 9. Upgrade PR acceptance checklist

- [ ] Change purpose, affected repositories and owner documented.
- [ ] Current and proposed exact versions, checksums and digests recorded.
- [ ] Consumer coupling assessed and coordinated.
- [ ] `resolve.sh --locked` passes; no unsolicited lock drift.
- [ ] Actual installed and embedded dependency inventories verified.
- [ ] Real frozen lifecycle and failure-injection cases pass.
- [ ] All eight images and Foundation container gate pass with evidence.
- [ ] CodeQL, security and supply-chain checks pass on final head.
- [ ] CVE findings remediated or **explicitly** scoped and authorised for correct environment; new risks denied.
- [ ] Private Codespaces/consumer qualification and rollback proved if adopting a new digest.
- [ ] Stacked PR dependencies merged/rebased through supported operations.
- [ ] Release permissions, digest provenance, registry readback and promotion authority verified.
- [ ] Retrospective/evidence index updated before closing the change.

**If a checkbox is outstanding, record “not yet demonstrated” with owner and gate.** Do not replace it with a source-only test or a management assertion.

## 10. Required evidence record for next time

Copy these fields into each upgrade PR:

```text
Change / owner / reason:
Base image tag and immutable digest:
Source PR head / target branch / base branch:
Version manifest + lock checksum:
Old → new tool version / archive SHA256:
Consumers and their exact compatibility pins:
Embedded OS/Go/Python/Node/JAR dependencies checked:
AMD64 / ARM64 profile matrix job URLs:
Source tests, frozen lifecycle, negative tests:
Trivy scanner version, flags, DB date and full inventory artifact:
CVE review / approved disposition or temporary risk reference + expiry:
CodeQL / release trust boundary check:
Fresh Codespaces / private package / consumer tests:
Published digest + index and attestation verification:
Rollback target + test:
Unresolved items, owners and re-review triggers:
Final-head CI / branch protection / reviewers / merge status:
```

See the [October DEV-10/DEV-14 retrospective](../incidents/2026-10-30-dev10-dev14-toolchain-retrospective.md), [Corepack incident](../incidents/2026-09-18-codespaces-corepack-interactive-prompt.md) and [version-management architecture](../architecture/version-management.md) before starting the next major upgrade.
