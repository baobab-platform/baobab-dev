# DEV10-R4 — Complete non-Ubuntu toolchain review and Maven 4 compatibility

**Assessment date:** 2026-11-02 (Africa/Johannesburg). **Owning PR:** [baobab-dev #57](https://github.com/baobab-platform/baobab-dev/pull/57). **Baseline:** accepted EA v2.3 / EA-DEV DEV-10/DEV-14, and #52/#54/#55.

**Decision:** REVIEW ONLY; no runtime major-version promotion, release tag, container publish, security waiver, or native consumer certification. All 33 non-Ubuntu entries in `config/versions.yaml` were inventoried against `config/versions.lock`; not all external registry freshness queries yielded a verified latest patch. Ubuntu stays exactly 26.04 and is excluded from this exercise. The version manifest declares policy (including `latest` and `system`); the lock captures the exact resolved state, and only an **installed-image read-back** proves the actual binaries.

## 3 November 2026 — adopted Maven 3.10.0 source candidate

Owner directed upgrading baobab-dev PR #57's `config/versions.yaml` from
Maven **3.9.16** to **3.10.0 GA**; `config/versions.lock` now carries the
same exact version and Apache-published SHA-512 digest
(`908b1501bfb420bf7c8affb855534a9c407fd6099367bfb9f2f2dcb8e9799102bffb84518cde74c679bd76870247c6528683abdd620581bffa90f95d92d175aa`).
The authoritative sources are
[Apache release history](https://maven.apache.org/docs/history.html) and
[official SHA-512 sidecar](https://archive.apache.org/dist/maven/maven-3/3.10.0/binaries/apache-maven-3.10.0-bin.tar.gz.sha512).
This supersedes the older `retain 3.9.16` recommendation **for the
development-image candidate only**. The historical table below remains
the 2 November baseline comparison, not the current pinned configuration.

Maven 3.10.0 uses Resolver 2.x; final-head eight-image AMD64/ARM64 builds,
security scans, tool readback, Codespaces and private-package consumers, and
ERP/Subscriptions Java21/PostgreSQL17 qualification are **not implied by
changing a version pin**. Maven 4 remains an unapproved prerelease. No
release or production approval follows from this manifest update.

## 1. Maven 3.10 GA vs Maven 4 RC

- Apache's [release history](https://maven.apache.org/docs/history.html) lists **3.10.0** (GA, released 2026-10-01) and **3.9.16** as supported stable Maven 3 series; **4.0.0-rc-7** (2026-09-24) is **not GA**. [Apache's Maven 4 migration guide](https://maven.apache.org/guides/mini/guide-migration-to-mvn4.html) calls for a parallel build, plugin audit and compatibility evidence before switching the default.
- **Baobab ERP custom six-module reactor:** `baobab-erp/idempiere/extensions/pom.xml` packages ordinary JARs with **Bnd 7.4.0**, Maven Shade 3.6.2 (integration module), JAR 3.5.1 and Surefire 3.6.1. It is **not** an upstream Tycho reactor. Maven 4 compatibility is plausible but **untested**: require full `mvn -B -f idempiere/extensions clean verify`, native PostgreSQL 17 finance negatives and OSGi bundle-manifest / shaded dependency checks. Changing Maven does **not** automatically change `maven.compiler.release=17` in the ERP POM; the Java **runtime** remains Java 21 for the shared image, and compiled bytecode target must be changed only by ERP owner review.
- **Upstream iDempiere 13 core build:** the actual upstream [`release-13/org.idempiere.parent/pom.xml`](https://github.com/idempiere/idempiere/blob/release-13/org.idempiere.parent/pom.xml) sets **`tycho.version=4.0.8`**, `jdk.version=17`. Apache Maven 4's [compatibility notes](https://github.com/apache/maven/releases) identify **Tycho pre-5.0** incompatibility and recommend 5.0.3+. Therefore a *full upstream* Maven 4 core build is **BLOCKED pending an upstream-supported Tycho 5 migration and actual `./mvnw verify` proof**, not certified by the independent Baobab extension build. Do not fork iDempiere core to force a global toolchain decision.
- **Baobab Subscriptions:** `baobab-subscriptions/pom.xml` has `maven.compiler.release=21`, Enforcer `requireMavenVersion=[3.9,)`, compiler 3.16.0, Surefire 3.6.0, Dependency 3.11.0 and Jar 3.5.1; its **Maven wrapper already pins 3.10.0**, but the build Dockerfile uses **`maven:3.9-eclipse-temurin-26`** and a separate **Temurin 25 JRE**. CI uses **Java 21** and `./mvnw verify` against PostgreSQL 17. These are real owner-version divergences and should be reconciled independently; do not mark them qualified merely because the shared image has Java 21. Isolated Maven 4 RC testing is appropriate for this project after baseline 3.10.0.
- **Kill Bill upstream server / plugins:** the Baobab Subscriptions `KillBillAdapter` is an HTTP integration, **not the Kill Bill upstream Maven reactor**. The [Kill Bill development documentation](https://docs.killbill.io/latest/development) specifies Maven 3.5.2+ but does **not guarantee Maven 4**. Upstream `killbill/pom.xml` inherits `killbill-oss-parent` (its master POM observed 0.147.36), with a broad set of build plugins including Maven Bundle and non-Apache extensions. Require an exact Kill Bill **release-tag/parent/plugin-version-pinned**, disposable Maven 3.10.0 vs Maven 4 RC full build/test and OSGi/plugin packaging checks. The Java 21 JDK selection alone proves neither Maven 4 plugin compatibility nor an actual Kill Bill runtime.

**Recommendation:** qualify **Maven 3.10.0 as the default-upgrade candidate**, retaining `3.9.16` until actual owner tests pass. Evaluate Maven `4.0.0-rc-7` in a separate, **non-release**, clearly reported comparison; no promotion of a release candidate to `v1.5.0` by default.

### Maven comparison acceptance matrix

| Target | Maven 3.9.16 baseline | Maven 3.10.0 stable candidate | Maven 4.0.0-rc-7 experimental |
| --- | --- | --- | --- |
| Java 21 + `mvn -version` / clean locked source | Preserve | Must pass | Experimental must report real output |
| Baobab ERP six-module Bnd/OSGi extension build | Preserve | Required PASS | Required before qualification; no inferred PASS |
| ERP native finance tests on PostgreSQL 17 | Preserve | Required PASS incl negatives | Required PASS incl negatives |
| iDempiere 13 full upstream Tycho P2 reactor | Independent baseline | Verify vendor wrapper | **BLOCKED Tycho 4.0.8** until upstream-supported 5.0.3+ migration |
| Baobab Subscriptions `./mvnw verify` on PG17 | Wrapper already selects 3.10 | Required PASS + Docker consistency | Required full PASS incl Enforcer, Surefire, packaged JAR |
| Kill Bill upstream core and supported plugins | Vendor baseline | Need pinned release/parent full build | **UNPROVEN**, full extension/plugin tests required |
| Multiarch, reproducible Maven bytes, dependency scan, Codespaces | Current receipts | Fresh independent receipts | No release decision from source-only tests |

## 2. All `versions.yaml` entries — current lock and disposition

Legend: **HOLD** means retain existing lock pending owner evidence; **TEST** means a newer candidate is known but not adopted; **REVALIDATE** requires trustworthy fresh metadata/signatures; **SYSTEM** is Ubuntu-repository controlled and cannot be changed by editing a version string alone.

| Area | Tool | `versions.yaml` intent / current locked version | Disposition and reason |
| --- | --- | --- | --- |
| Languages | Python | 3.14.10 exact PSF build | **HOLD.** Python 3.15.2 GA is available but Django, Pulse, Haystack, native wheels, ABI and downstream constraints need separate Python-major qualification; no silent major bump |
| Languages | Node | major 26, exact 26.13.0 | **HOLD.** Current Node 26 LTS, but Nabhold/ZuriBeans/Thamani/CP `engines` currently exclude major 26; explicit owner migrations required |
| Languages | Flutter | latest stable → 3.47.8 | **HOLD / REVALIDATE** 3.50 only once an actual stable release is verified; Android/iOS and both native CPU installs, Flutter Git ref and hashes must match |
| Languages | Java | Temurin 21 major | **HOLD.** Java21 default per ERP/Subscriptions owner directive; exact patch currently selected by signed apt, verify installed JVM/JDK and owner build, not just major label |
| Database | PostgreSQL | client major 17 | **HOLD.** PostgreSQL 18 exists but server migrations, PITR/restore, extensions, roles and per-engine acceptance are DEV-12; do not infer server version from CLI |
| Package managers | uv | latest → 0.13.5 | **TEST 0.13.6**: published 2026-10-26, verify AMD64/ARM64 signed assets, Python3.14 frozen projects and cache behavior |
| Package managers | Poetry | latest → 2.5.1 | **HOLD**; currently observed stable, test Python3.14/pipx and resolver security |
| Package managers | pnpm | explicit 12.16.1 | **HOLD**; 12.17.0 exists but is tagged `next-12` (not default npm `latest`); only test separately. Existing Node24/pnpm11 consumers must migrate in lockstep, with SHA256 per arch, cold/offline and negative tests |
| Package managers | Corepack | 0.36.0 | **HOLD** current observed; Node26 needs separate installation, Yarn shim must not shadow native pnpm |
| Package managers | npm | latest → 12.2.1 | **HOLD** current observed npm `latest`; audit embedded dependencies, not just parent binary |
| Package managers | npm bundled tar | latest → 7.5.22 | **HOLD** current observed; verify exact embedded installed archive and independent CVE scan |
| Utilities | Task | latest → 3.54.0 | **HOLD**; nightly 3.55.0 is not an accepted stable release |
| Utilities | ripgrep | latest → 15.2.0 | **HOLD** current observed, test both architectures |
| Utilities | fd | latest → 10.5.0 | **HOLD** current observed, test both architectures |
| Utilities | bat | latest → 0.26.1 | **HOLD / REVALIDATE** signed release and stable metadata, especially asset checksums |
| Utilities | eza | latest → 0.23.5 | **HOLD** current observed; check signer/key provenance and both arch binaries |
| Utilities | jq | system / apt | **SYSTEM**; record `dpkg-query`, binary version and OS security updates |
| Utilities | yq | latest → 4.54.1 | **HOLD** current observed, verify exact binaries/arch SHA |
| Utilities | fzf | system / apt | **SYSTEM**; record `dpkg-query` and CLI smoke |
| Utilities | tree | system / apt | **SYSTEM**; confirm installed version |
| Utilities | unzip | system / apt | **SYSTEM**; security scan and actual archive parsing smoke |
| Utilities | zip | system / apt | **SYSTEM**; integrity/runtime smoke |
| Utilities | xz | system / apt | **SYSTEM**; supply-chain and actual extraction smoke |
| Development | Docker | latest from Docker repo (no exact lock) | **REVALIDATE / PIN** Docker CLI, Compose, Buildx separately; Docker 29.9.2 Engine security fixes exist, but installed CLI and daemon are distinct, and Codespaces host engine is outside image. Record immutable installed version and signed package provenance |
| Development | GitHub CLI | 2.102.1 explicitly pinned | **HOLD for security**; upstream 2.103.2 is newer but owner assessment identified vulnerable embedded Go/x/net. Inspect new actual binary with Go build info/Trivy before promotion |
| Development | Maven | explicit 3.9.16 | **TEST 3.10.0 GA**; Maven 4.0.0-rc-7 is isolated experimental only. Never infer iDempiere upstream Tycho compatibility from Baobab reactor |
| Frontend | Turbo | latest → 2.11.10 | **HOLD** current observed stable; cold builds and invalidation tests |
| Frontend | Playwright | explicit 1.64.1 | **HOLD**; browsers revision-coupled to every consumer `@playwright/test`; no partial image upgrade |
| Frontend | Sharp | latest → 0.35.5 | **HOLD** current observed; verify native Node26 libvips and ARM64 |
| Frontend | Lighthouse | latest → 13.5.0 | **TEST 13.6.0**; published new release, compare scoring/report output and keep CSS/JS/performance budgets unchanged |
| Security | Cosign | latest → 3.1.4 | **HOLD** current observed; v3 signature/bundle validation and rollback/negative tests mandatory |
| Infra | Terraform | explicit 1.17.1 | **HOLD** current observed stable; `terraform init -lockfile=readonly`, plan and protected apply policies |
| Infra | AWS CLI | explicit 2.36.38 | **REVALIDATE** latest AWS-published official release and PGP-signed AMD64/ARM64 archives; do not take version numbers from third-party mirrors |

**Release metadata and upstream sources:** [Python 3.14.10](https://www.python.org/downloads/release/python-31410/), [Python 3.15](https://www.python.org/downloads/), [Node 26 LTS](https://nodejs.org/en/blog/release/v26.13.0), [PostgreSQL versions](https://www.postgresql.org/support/versioning/), [uv](https://github.com/astral-sh/uv/releases), [pnpm npm dist-tags](https://www.npmjs.com/package/pnpm?activeTab=versions), [Corepack](https://github.com/nodejs/corepack/releases), [npm](https://www.npmjs.com/package/npm?activeTab=versions), [Task](https://github.com/go-task/task/releases), [ripgrep](https://ripgrep.dev/changelog/), [fd](https://github.com/sharkdp/fd/releases), [bat](https://github.com/sharkdp/bat/releases), [eza](https://github.com/eza-community/eza/releases), [yq](https://github.com/mikefarah/yq/releases), [Maven](https://maven.apache.org/docs/history.html), [GitHub CLI](https://github.com/cli/cli/releases), [Terraform](https://github.com/hashicorp/terraform/releases), [Playwright](https://www.npmjs.com/package/playwright?activeTab=versions), [Lighthouse](https://www.npmjs.com/package/lighthouse), [Sharp](https://www.npmjs.com/package/sharp), [Cosign](https://github.com/sigstore/cosign/releases), [Flutter archive](https://docs.flutter.dev/install/archive), [Docker Engine 29](https://docs.docker.com/engine/release-notes/29), [AWS CLI documentation](https://docs.aws.amazon.com/cli/latest/userguide/).

### 3. Decisions and merge/release gates

1. **Low-coupling candidate pilots first:** Maven **3.10.0**, uv **0.13.6**, Lighthouse **13.6.0**. Each requires a reviewed source/lock change, checksum and actual current-head AMD64/ARM64 image+consuming repo evidence; no automatic acceptance merely from registry version.
2. **Independently qualified majors:** Python 3.15, PostgreSQL 18 (not an immediate DEV-10 client bump), Maven 4 RC, new Java JDK major, pnpm 12.17 from `next-12`, any Docker/Compose/Buildx major.
3. **Source/consumer drift to repair:** ERP main `upstream.lock.yaml`, CI and root wrapper still refer to Java 17 / Maven 3.9.11 while baobab-dev candidate defaults to Java21; Subscriptions wrapper=3.10.0, Docker builder=3.9+Java26, runtime=Java25, CI=Java21. These are **consumer-owned** changes, not blanket `versions.yaml` edits.
4. **DEV-10/14 gates:** immutable binaries and verified provenance, full eight-image matrix with installed version read-back, strict Trivy, controlled dependency changes, Codespaces non-root/private packages + real owner project commands and independent teardown, current-head CI, rollback tuple. Use `config/resolve.sh --locked` to verify source vs committed lock.
5. **Protected release boundary:** issue #54's 295-CVE `linux-libc-dev=7.0.0-42.42` acceptance was extended to **untagged PR #57 only**; it expires 2026-11-13 00:00 UTC and **does not permit v1.5.0 tag pushes**. An independent, attributable release-scoped risk decision with per-CVE/digest evidence or vendor remediation is still required; preserve all unfiltered scanning and never publish with a silently relaxed gate.

**Evidence status at writing:** This register is an upstream/source investigation; it does **not** claim any Maven 4 reactor PASS, new Codespaces run, native iDempiere/Kill Bill rebuild, currently green eight-image CI, or production acceptance.
