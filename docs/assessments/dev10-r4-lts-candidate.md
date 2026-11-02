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
| Java | Temurin 17 default for ERP + explicit Temurin 21 Subscriptions overlay |
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

## Java 17 / Java 21 compatibility separation (issue #52)

The full-profile default JAVA_HOME remains `/opt/java` → `/opt/java17`
for native iDempiere/ERP. Both `/opt/java17` and `/opt/java21` come from
Temurin's signed apt repository. Subscriptions may opt into Java 21 in its
owner devcontainer, without changing the group-wide default:

```sh
JAVA_HOME=/opt/java21 PATH=/opt/java21/bin:$PATH ./mvnw --version
JAVA_HOME=/opt/java21 PATH=/opt/java21/bin:$PATH ./mvnw verify
```

The source verifies both `javac` majors, the original default symlink and
Maven. Actual owner Subscriptions `./mvnw verify` with PostgreSQL 17 in a
new disposable Codespace, private package access and AMD64/ARM64 image
readback remain qualification requirements. Do not mark issue #52 closed
on image-source checks alone.

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
