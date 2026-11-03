## 2026-11-03 — Maven 3.10.0 GA candidate pin

The owner explicitly selected the latest stable Maven 3.10.x, resolved to
**Apache Maven 3.10.0**. PR #57 now pins that exact version in
`config/versions.yaml` and the Apache-published SHA-512 in
`config/versions.lock`. This is a reproducible dev-image candidate upgrade,
not proof of Maven 3.10 compatibility in the ERP release-13 native OSGi
runtime, Subscriptions JVM reactor, Codespaces, or protected delivery.
Current-head CI, raw image scans and independent owner-consumer evidence
remain mandatory. Maven 4 RC was not adopted.

# DEV10-R4 — Node 26 / pnpm 12 / Java 21 / Python 3.14 candidate

**Status: CANDIDATE, NO MERGE/RELEASE ACCEPTANCE.** Based on merged #48/#50.
A full new immutable digest does not exist yet; this is a source-only engineering
change until both architectures produce independently scanned images and all
affected owners execute real native acceptance.

| Toolchain | Candidate |
| --- | --- |
| Ubuntu | 26.04 |
| Python | 3.14.10 built from PSF source tarball with public sha256 |
| Node | 26.13.0 Active LTS from NodeSource signed apt, exact runtime assertion, libatomic1 |
| pnpm | 12.16.1 native executable through separately installed Corepack 0.36.0 |
| Java | Temurin 21 default for iDempiere v13 and Subscriptions |
| PostgreSQL | client 17 only; physical migration separately owned DEV-12 |
| Playwright | 1.64.1 with exactly matching browser binaries |

Important mechanical differences: Node 26 does not bundle Corepack; pnpm 12's
native layout does not contain pnpm 11's vendored undici path, so the old
hard-coded undici hotpatch cannot be applied. The candidate replaces this
with exact pin enforcement and strict unfiltered dependency/image scanning,
not a generic CVE exemption.

Retain all prior v1.4.4 source/image/consumer pins. Candidate images must
not use the normal publish/release tags or be treated as deployment authority.

## Exit criteria

1. Resolver --locked exact-source consistency, Node 26 version, Corepack/pnpm
   exact and noninteractive offline behavior (including malformed pins).
2. Actual full and frontend-e2e native amd64/arm64 Docker builds; Python
   3.14.10, Java21, PostgreSQL17 and Playwright1.64.1 readback.
3. Strict raw Trivy scans, provenance/SBOM/signing, no protected scan waiver.
   PR #57 inherits only the exact 295 `linux-libc-dev 7.0.0-42.42` findings
   as an expiring **development-only** risk treatment (through 13 Nov 2026 UTC).
   No VEX `not_affected`, vendor remediation, staging, tag or production waiver.
   Any new CVE, severity, package version, secret or fix signal still blocks;
   `v1.5.0` tag pushes remain fail-closed pending separate release authority.
4. Fresh Codespaces user-image and npm-package permission as that user,
   post-create completed before ready, private forwarded ports.
5. Consumer-specific immutable-upgrade branches: Trade/Medusa, ERP, Subscriptions,
   Payments/Rust, CP/Go, Pulse/Python/Qdrant, Nabhold, ZuriBeans, Thamani, Shared.
   BXS private archive and Playwright browser revisions must align.
6. Exact rollback of image+lock tuple; independent PostgreSQL physical migration
   or safe restore, never a blind volume swap.

If any native engine cannot pass, document that precise incompatibility, owner
evidence and the isolated temporary pin; do not silently downgrade the platform.

## 2026-11-02 correction — publisher binary / Corepack precedence

GitHub Actions owner probes reproduced a global Corepack shim that tried to
fetch the **existing pnpm 11.24.0 project pin** despite installation of the
pnpm 12 npm package. This is a test failure, **not compatibility evidence**.
The candidate now verifies publisher-provided SHA-256 for separate pnpm 12.16.1
native x64/arm64 release archives and places that binary ahead of Corepack;
Corepack 0.36.0 remains a separately pinned Yarn tool. No unidentified npm
postinstall scripts, abandoned pnpm 11 vendored-undici patch, or disabled
security scans are permitted. R3 checks install these identical immutable
pnpm release bytes in disposable CI workspaces.

pnpm 12.17.0 was released 30 October but is still under npm's `next-12`
channel; `12.16.1` is the current published `latest` as observed 2 November.
No prerelease-channel promotion without a later explicit decision.

## Java 21 shared default (issue #52; iDempiere v13)

Temurin **21** is the only JDK installed by the full candidate image and
the default `JAVA_HOME=/opt/java`. iDempiere's official prerequisites
document a JDK >=17 and use Java 17 as an example, not as a maximum.
Actual iDempiere v13 OSGi/JVM bundle startup, database integration and
owner build on Java 21 must still pass in the consuming engine; avoid
claiming native acceptance based on a version floor alone.

```sh
java --version
javac --version
mvn --version
./mvnw verify
```

The source checks the running JVM's Java specification version **21**,
`javac 21` and the original `JAVA_HOME` contract. Actual Subscriptions
`./mvnw verify` with PostgreSQL 17 in a disposable Codespace, iDempiere v13
native tests, private package access and AMD64/ARM64 image readback remain
qualification requirements. Do not mark issue #52 closed on image-source
checks alone.

## 2026-11-03 — pnpm 12 offline bootstrap qualification correction

Run 41575370514 established a new, separate provisioning failure. The
native pnpm 12.16.1 binary passed tool readback, and both AMD64 frontend
images built and passed their image vulnerability scans. Their CI fixture
nonetheless failed with `ERR_PNPM_BAD_CONFIG_DEP` before testing frozen
install: pnpm 12 records the `packageManager` pin as a configuration
dependency and cannot bootstrap a fresh lockfile under `--offline` against
an empty local registry mirror. Corepack was not the executing binary.

The corrected CI performs a bounded, noninteractive first install with
network available, captures its lock and pnpm metadata/store, then proves
a separate `--network none` frozen offline install preserves the exact
lock bytes. The image's `pnpm_config_pm_on_fail=error` avoids automatic
manager-switching while enforcing exact pin agreement; wrong pin and
bad-lock cases are required negatives. This repairs a **test design error**,
not a pnpm dependency incompatibility. Final-head Actions and real
Codespaces/private-package consumer checks remain outstanding until
independently recorded.

## Security disposition and v1.5.0 release boundary

Issue #54's explicitly provided executive **development** direction has
been extended to PR #57; no independently authenticated release signature
or 295 per-CVE `not_affected` determinations have been supplied.
The same immutable 295-CVE inventory, package/version/severities, expiry,
unfiltered Foundation/Publish scans and negative cases are unchanged.
**A tag push must still fail** if high/critical findings remain; do not
alter release workflows to obtain a cosmetically green release.
Before the owner creates `v1.5.0`, independently qualify final-head CI,
complete the Codespaces/consumer matrix (#55), and obtain a separately
attributable, digest/CVE-scoped **release** risk determination or vendor fix.

## 2026-11-03 final-head CI and remediation

The 3 November GitHub Actions run
[41557252699](https://github.com/baobab-platform/baobab-dev/actions/runs/41557252699)
built both platforms for the relevant profiles. Three build-matrix gates
showed independent defects, not successful qualification:

- **Frontend and frontend-e2e AMD64:** the CI-only test created an
  incomplete `lockfileVersion: 9.0` file for a pnpm 12 manifest.
  The frozen install rejected it with
  `ERR_PNPM_FROZEN_LOCKFILE_WITH_OUTDATED_LOCKFILE`. The rehearsal now
  initially attempted to generate a fixture lock entirely offline; that
  attempt failed on pnpm 12's new cold bootstrap metadata requirement.
  The later two-stage correction and its pending verification are recorded
  above. This paragraph documents the superseded test, not a PASS. Consumer
  repositories must still commit their OWN correctly regenerated locks.
- **Full AMD64/ARM64:** Trivy detected a **296th** HIGH finding,
  `CVE-2025-47273`, on setuptools **70.3.0**, which exceeded the
  exact development-only 295-CVE allowance and correctly blocked CI.
  The independently exported scanner artifact identified the package
  in the residual Ubuntu `/usr/local/lib/python3.14/dist-packages/pip-26.3`
  installation. The source already patched the separate /opt Python and
  pipx shared pip copies; this change installs the same source-revendored,
  checksum-built patched wheel in the distro interpreter and asserts
  its installed version. The CVE is fixed in setuptools >=78.1.1.
  Do not add the finding to the risk exception.
- **Validation needed:** repeat final-head image build, fresh Trivy and
  installed pip/setuptools checks on both CPUs, native consumer tests,
  private-package Codespaces, teardown and release-specific security
  disposition. A source patch is not a passing scan.

No change was made to Ubuntu 26.04, security scanning thresholds, the
release trigger, protected tags or the signed-artifact requirements.
