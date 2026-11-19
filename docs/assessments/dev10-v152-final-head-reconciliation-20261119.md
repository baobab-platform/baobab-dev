# DEV-10 v1.5.2 final-head reconciliation

19 November 2026 · [baobab-dev #74](https://github.com/baobab-platform/baobab-dev/pull/74)

**Release readiness — BLOCKED.** The requested toolchain versions are preserved. The unfiltered scans refuse the candidate. Independent current-head authorization and effective main and release-tag enforcement are also unresolved.

## 1. Architectural reconciliation

The initial audit fetched main at **bc6ca0a9f7d28c8baa41a903642ff808c99e84f2** and #74 at **f72f377106a751c0b761588179cfc47a1eb2f4da**. It covered the 171-file diff, 78 discussion comments, 24 reviews and 21 review threads. Subsequent CI evidence is identified by its own SHA. [Initial source](https://github.com/baobab-platform/baobab-dev/commit/f72f377106a751c0b761588179cfc47a1eb2f4da) · [Predecessor identity and release audit](dev10-pr74-identity-release-reconciliation-20261119.md)

| Authority | Acceptance boundary |
| --- | --- |
| [#95](https://github.com/baobab-platform/baobab-dev/issues/95) | Manifest-driven lock generation, native qualification, exact OCI evidence and authorized publication |
| [#81](https://github.com/baobab-platform/baobab-dev/issues/81) | Typed identities, independent reviews and effective write controls |
| [#54](https://github.com/baobab-platform/baobab-dev/issues/54) | Independently authorized residual-risk scope and expiry |
| [#93](https://github.com/baobab-platform/baobab-dev/issues/93) | Ubuntu binary identity and exact ancestry/backport technical evidence |
| [#55](https://github.com/baobab-platform/baobab-dev/issues/55) | Real Codespaces, private-package and consumer acceptance |

The repository's four published targets match the Shared profile scheme. Dockerfile target **final** corresponds to **full** and has the unsuffixed version tag. DEV-14 and #55 establish the run and adoption evidence in each consuming repository. [Shared EA v2.3](https://github.com/baobab-platform/shared/tree/75b1fa96462f5e5148f842c47ace805ec8e679b5/docs/architecture) · [Shared environment contract](https://github.com/baobab-platform/shared/blob/75b1fa96462f5e5148f842c47ace805ec8e679b5/contracts/development-environment/schema.yaml)

## 2. Manifest and lock conformance

| Capability | Candidate and observed lock identity |
| --- | --- |
| Ubuntu | 26.04, OCI index sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db. Native linux-libc-dev 7.0.0-43.43. |
| Python | 3.14.10, source SHA-256 de414a57119abef52784d8993e341d53aed635fc2b05c2607d9f98a2c5b72032. The generated .python-version deliberately selects minor 3.14. |
| Node.js and package managers | Node.js 26.13.1, native pnpm 12.21.0, Corepack 0.36.0, Yarn 4.18.1, npm 12.2.1 and vendored npm tar 7.5.22. |
| Java and PostgreSQL | Temurin JDK 21, AMD64 package 21.0.13.1.0+2-0 and ARM64 package 21.0.13.0.0+9-0. Maven 3.10.0, PostgreSQL 17 client 17.12-1.pgdg26.04+1. |
| Browser testing | Playwright 1.65.0 with package-determined browser revision and actual non-root Chromium smoke. |
| Infrastructure and CLI | Terraform 1.17.1, AWS CLI 2.36.38, GitHub CLI 2.102.1, Task 3.54.0, yq 4.54.1 and Docker CLI 5:29.10.0-1~ubuntu.26.04~resolute. |
| Other resolutions | Flutter 3.47.8, uv 0.13.9, Poetry 2.5.1, Cosign 3.1.4, Turbo 2.11.10, Sharp 0.35.5, Lighthouse 13.5.0, ripgrep 15.2.0, fd 10.5.0, bat 0.26.1 and eza 0.23.5. |

The native pins capture versions and bytes already observed in the candidate. Both Linux header binaries, NodeSource, Temurin JDK, PostgreSQL and Docker package identities were corroborated against publisher metadata. The frozen resolver and generated lock share the same assignment grammar. The native pnpm path keeps per-architecture SHA-256 and release asset attestations. Python, Maven, AWS CLI and source-rebuilt CLI verification retain publisher checks, required source identities and executable readback. Other Ubuntu APT dependencies, some global npm transitive resolutions and build timestamp inputs still limit repeat-build byte equivalence. [Manifest](../../config/versions.yaml) · [Lock](../../config/versions.lock) · [Build source](../../.devcontainer/docker/Dockerfile)

The independently identified inputs at the hosted 167b962 source were manifest SHA-256 **c174893e4be060e5df8b55845a80ab3374ae13f0d19f288357bc3dd42ac6d922**, lock SHA-256 **d7896fb72f2b3e90a9cfe9a698f0317d85503c2ffce459b1a92b56c2ae7d8b3b** and Python selector SHA-256 **a876e0b10411037a012498b9fe18d9bc1df32ed8b722a13564dc944ddcfd9135**. [Hosted frozen lock evidence](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14549777976)

The succeeding candidate manifest SHA-256 is **011eed6960b9971b487ae5518e8492a6929bdfc906a69d05551e7b53b5161e24** and its lock SHA-256 is **53ecbf8ff68d464c0b3a6e61222524256196f345dd27949fc9167003292094e1**. This change records the Temurin binary digests observed in the existing two native builds while retaining their versions. [AMD64 readback](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/job/135699234713) · [ARM64 readback](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/job/135699234845)

## 3. Workflow treatment

| Step | Treatment | Contract |
| --- | --- | --- |
| Manifest and lock | RETAIN | One resolver and two generated files. The same-branch writer still needs its protected GitHub App and a witnessed manifest-only/no-op PR. |
| Ordinary PR and Foundation | REFACTOR | Compare runtime with the same validated container. Foundation retains its separate unfiltered enforcement under the current Shared check arrangement. |
| Release build and scan | CONSOLIDATE | Each native build exports one attested local OCI layout. The same child supplies the scanner and native test. Qualification has no registry write permission. |
| Registry transfer and signing | REFACTOR | All eight checks and independent protected approval precede the first registry write. Cosign and embedded SBOM/provenance verification remain mandatory. |
| Mandatory numbered RC | REPLACE | A stable family can qualify directly. An existing same-source RC can be reused only with exact source, family, successful run and artifact proof. |
| Historical exception code | RETIRE | Historical disclosure only. Current release policy blocks residual High, Critical and secret findings. |
| Registry, source and rollback evidence | RETAIN | Keep exact digest readback, bounded retries, source lineage diagnostics and protected alias recovery. |

The release trigger still requires a reviewed canonical main merge and an authorized tag. Automatic publisher activation after merge remains unqualified. The GitHub deployment review history has run-level custody, so a rerun needs fresh attempt-specific authority before the workflow permits writes. [Publish workflow](../../.github/workflows/publish.yml) · [Rollback](../usage/immutable-rc-recovery.md)

## 4. GII-01–GII-14

| Control | Implementation or evidence | Classification |
| --- | --- | --- |
| GII-01 actor separation | Exact run, typed immutable actors, protected reviewer appointments and source contributor exclusion | IMPLEMENTED BUT UNQUALIFIED |
| GII-02 live fallback | Authenticated REST/GraphQL service-committer corroboration at the pinned #76 commit | ACCEPTED for historical fixture |
| GII-03 governance | Public main has no effective protection rules and detailed readback returned 403 | BLOCKED |
| GII-04 custody | Current-head independence, exact bytes, separate owner concurrence and idempotent protected variable verification | IMPLEMENTED BUT UNQUALIFIED |
| GII-05 #76 collision | Contributor 356890520 excluded. Reviewer 356900102 approved the exact head. Owner 49340314 concurred. | ACCEPTED for historical evidence |
| GII-06 transport diagnostics | Shared read transport emits bounded status and request IDs. Unsafe targets, redirects and malformed responses fail closed. | IMPLEMENTED BUT UNQUALIFIED |
| GII-07 exact metadata | Committer-only fallback joins the exact SHA, typed ID and raw name, email and time. | IMPLEMENTED BUT UNQUALIFIED |
| GII-08 service identity | GitHub service User 19864447 remains a contributor and cannot authorize release. Unknown identities are refused. | IMPLEMENTED BUT UNQUALIFIED |
| GII-09 live API evidence | Live schema, exact service commit and 94 #76 commits observed. A protected #74 event still needs its own evidence. | IMPLEMENTED BUT UNQUALIFIED |
| GII-10 volume | Seven successful recorded calls including two REST committer lookups, with rate-limit fields retained | ACCEPTED for measured fixture |
| GII-11 role boundaries | Live code uses distinct role-specific inputs. #89's broader classifier remains a prototype. | IMPLEMENTED BUT UNQUALIFIED |
| GII-12 branch and bypass | Correct effective tag namespace, main protection and bypass scope require verified administrator readback. | BLOCKED |
| GII-13 negative cases | Contributor collision, stale approval, head change, pagination, malformed/duplicate type and ID, API mismatch, missing owner, unauthorized write, redirects and rerun refusal | IMPLEMENTED BUT UNQUALIFIED |
| GII-14 caller closure | Common bounded GitHub transport across policy custody, committer fallback and diagnostics | IMPLEMENTED BUT UNQUALIFIED |

## 5. Security regression and evidence

Independent download verified ZIP SHA-256 **f2eb46751ba495aaf36e6b669c1b897312b869892d7d6661cabf90de2de1b33a** for authenticated historical custody. Approval 5932308847 covers exact head **f9fd73d4e848a7c4d3bcfbe28651e06149cdcb6d** and service commit **dad5dc64031d05b7e7d93345f1ea553abea6c70e**. [Hosted receipt](https://github.com/baobab-platform/baobab-dev/actions/runs/44561067917/artifacts/14548747253)

The release environment readback has four numeric reviewer appointments, prevents self-review and disables admin bypass. Repository tag rules use the literal doubled prefix **refs/tags/refs/tags/v***. It misses ordinary release refs. The custodian must establish the actual main and tag rules and authorize this exact release source. [Repository tag rules](https://github.com/baobab-platform/baobab-dev/rules/20470719)

Local regression covers modified OCI bytes, wrong source, wrong scanner config identity, residual High findings and exact immutable transport. The checksum-verified crane transferred the fixture index by digest and read back the identical digest from a disposable loopback registry. Hosted PR preflight separately exercises real BuildKit OCI export and Docker import. The HEALTHCHECK, legacy exception refusals and two API cleanup findings were checked in the actual diff. The open threads remain recorded pending review of the replacement head.

## 6. CVE and decision register

| Inventory | Verified disposition |
| --- | --- |
| Historical 295 | linux-libc-dev 7.0.0-42.42, 12 Critical and 283 High. Keep the historical package and inventory distinct. [Historical inventory](dev10-kernel-cves.tsv) |
| 298 under investigation | linux-libc-dev 7.0.0-43.43, Canonical Ubuntu-7.0.0-43.43 at f53b359683af7918c5436499948763cb726d5082. Earlier path corroboration returned 289 full correspondences and nine discrepancies. The ancestry audit enumerated 1,458 unique candidate commits. Unfinished results remain explicit. [298-source inventory](dev10-kernel-cves-298.tsv) |
| Initial current scanner scope | Nine digest-verified artifacts report identical 52 findings for 7.0.0-43.43, 3 Critical and 49 High. Normalized inventory SHA-256 b85a53603ecdf87e5ff96109f87f31e6c404117955a5a027787a29632b21198f. [Profiles](https://github.com/baobab-platform/baobab-dev/actions/runs/44510229590) · [Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/44510231018/artifacts/14522648642) |
| Remediation trial | Both official 7.0.0-44.44 binaries verified against signed Ubuntu metadata. Package-only Trivy 0.73.0 returned the same 52 identities on both versions and architectures, with no fixed version reported. The existing version remains pinned. DB SHA-256 923c9ac4d894e62da8020926c64e7bbff80f2562944708ac6804388eb1debec9. |
| Draft #92 | Includes 11 of the 52 kernel findings. Picomatch does not appear in this inventory, leaving 41 outside the proposal. The proposal expires 26 November 2026 at 00:00 UTC. Approvals and protected digest are pending. [Decision PR](https://github.com/baobab-platform/baobab-dev/pull/92) |
| Release | BLOCKED by unfiltered security policy. The eight-finding development decision and the draft cannot authorize GHCR release. |

The independent readback of the eight 167b962 scanner artifacts and the dedicated Foundation artifact verified all nine ZIP digests. Each retained the same exact 52 identities. The compact JSON array of sorted [CVE, package, version, severity] records hashes to **ab69f19d2186b6febcb1712bdbd343a34d133407d41d7c2d888a3455cc4ac2d1**.

| Profile and architecture | Scan artifact | ZIP SHA-256 |
| --- | --- | --- |
| dev10-foundation-container-risk | [14550423636](https://github.com/baobab-platform/baobab-dev/actions/runs/44563109091/artifacts/14550423636) | sha256:b72cef29617f75f0c4c8e454ff292fb94a4fc4c090d8e9fce2eebcb4a4792968 |
| trivy-final-amd64 | [14552605932](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14552605932) | sha256:072f5462ca6fcf1cfa55a818459624ac0df0bc3fcc6911defedaf380e43a59f2 |
| trivy-final-arm64 | [14549679738](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14549679738) | sha256:22f844ac9c4747919764aec862b8c3e3c25fb1a33762e5cf2fb1a35e96ddc5db |
| trivy-frontend-amd64 | [14551278238](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14551278238) | sha256:cc73566936c7f3950f7ba07c3f7d5048988f432b2afc834c3fb28fd3f42ed3d8 |
| trivy-frontend-arm64 | [14551591911](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14551591911) | sha256:e17d12dbc54728856ef62e6053b7736f6de41db1d417c084fc5044d6ab4a735e |
| trivy-frontend-e2e-amd64 | [14550864733](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14550864733) | sha256:ecd613c42d0b9d8446cc90c9061687b682e5e80ffed097062f335df036b224cf |
| trivy-frontend-e2e-arm64 | [14552066584](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14552066584) | sha256:0ecd4d8968457681a05247183ac3638c11be7abf5d4a92474314f13422e02eef |
| trivy-infra-amd64 | [14550969145](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14550969145) | sha256:6ab09beb43536275b9e5f9d0dcf27ee0f5e99b2695b4fbc97134b4bac12cf6cc |
| trivy-infra-arm64 | [14550733676](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14550733676) | sha256:6934cde3f7fb30b02c82d9926fac416c6cdb8546657c333452538f292a30a72e |

**Exact CVE identities for linux-libc-dev 7.0.0-43.43 on each profile and architecture**

- CRITICAL — CVE-2026-99287, CVE-2026-99306, CVE-2026-99310
- HIGH — CVE-2022-50240, CVE-2025-40190, CVE-2026-100081, CVE-2026-68103, CVE-2026-72198, CVE-2026-74578, CVE-2026-89805, CVE-2026-98376, CVE-2026-98420, CVE-2026-98869, CVE-2026-98890, CVE-2026-99083, CVE-2026-99109, CVE-2026-99110, CVE-2026-99116, CVE-2026-99117, CVE-2026-99126, CVE-2026-99128, CVE-2026-99138, CVE-2026-99147, CVE-2026-99152, CVE-2026-99153, CVE-2026-99154, CVE-2026-99164, CVE-2026-99166, CVE-2026-99167, CVE-2026-99185, CVE-2026-99203, CVE-2026-99212, CVE-2026-99213, CVE-2026-99218, CVE-2026-99227, CVE-2026-99231, CVE-2026-99236, CVE-2026-99239, CVE-2026-99260, CVE-2026-99270, CVE-2026-99272, CVE-2026-99274, CVE-2026-99275, CVE-2026-99282, CVE-2026-99284, CVE-2026-99288, CVE-2026-99290, CVE-2026-99292, CVE-2026-99295, CVE-2026-99302, CVE-2026-99304, CVE-2026-99311

The source verifier now preserves the original Resolute updates observation and validates the exact .deb hash from the current security pocket separately. The historical case evidence lock and risk-decision records retain their original bytes. [Exact package capture](https://github.com/baobab-platform/baobab-dev/actions/runs/44558261972/artifacts/14546278211)

## 7. Native qualification

| Target | AMD64 | ARM64 |
| --- | --- | --- |
| final | Build and non-root native smoke passed | Build and non-root native smoke passed |
| frontend | Build and non-root native smoke passed | Build and non-root native smoke passed |
| frontend-e2e | Build and native browser smoke passed | Build and native browser smoke passed |
| infra | Build and non-root native smoke passed | Build and non-root native smoke passed |

This matrix describes PR head **167b962305a01c489f1b1d9f543f35a77a6fb758** and synthetic checkout **d8ebb82e3f92a1e0c0d5e55a61ba413b5de84b2a** at observation. The dedicated Foundation container gate refused the same candidate. The initial reconciled head had eight builds and six native smoke passes, with both final-profile smoke tests skipped before the archive handling correction. [Hosted matrix](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235) · [Full AMD64 native proof](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14551034744) · [Full ARM64 native proof](https://github.com/baobab-platform/baobab-dev/actions/runs/44563107235/artifacts/14551927233) · [Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/44563109091)

## 8. GHCR release evidence

| Required v1.5.2 tag under ghcr.io/baobab-platform/baobab-dev | State |
| --- | --- |
| 1.5.2 | BLOCKED |
| 1.5.2-frontend | BLOCKED |
| 1.5.2-frontend-e2e | BLOCKED |
| 1.5.2-infra | BLOCKED |

Git had no v1.5.2 tag or GitHub Release at check time. Anonymous registry access was denied. The protected workflow will independently check existing registry tags and refuse conflicting digests. A successful run retains release-evidence.json with all four signed indices, native manifests, SBOM/provenance, exact security and approval evidence, source and lock hashes and tag readback. The release evidence manifest is pending publication.

## 9. Consumer qualification

| Consumer | Current repository evidence and required acceptance |
| --- | --- |
| Nabhold, ZuriBeans, Thamani | Node 24 and pnpm 11.24.0 with separately pinned Playwright versions. Run frozen installs, builds and their browser suites on the candidate. |
| Baobab CP | Bootstrap pins Node 26.13.0. Candidate uses 26.13.1. Test CP's intended Node patch and pnpm 12 compatibility independently. |
| Baobab Pulse | Python capability declared. Exercise its locked application under 3.14.10. |
| Baobab ERP | Execute real iDempiere native JVM and OSGi verification against the candidate JDK and Maven. |
| Baobab Subscriptions | Java 21, Maven and PostgreSQL 17 declared. Run its committed Maven wrapper and database tests. |
| Infrastructure | Terraform and infrastructure profile declared. Verify native init, validate, plan and AWS tooling. |

Disposable fresh Codespaces, authenticated pulls, real GitHub Packages, consumer builds and verified teardown remain **BLOCKED** on the qualified image release. No consumer pin was migrated. [Acceptance contract](https://github.com/baobab-platform/baobab-dev/issues/55)

## 10. PR consolidation

| PR and head | Disposition |
| --- | --- |
| [#83](https://github.com/baobab-platform/baobab-dev/pull/83) 3ccc7a6 | Already closed. Sanitized API transport retained in #74. |
| [#84](https://github.com/baobab-platform/baobab-dev/pull/84) 2c2bdc7 | Already closed. Typed reviewer and duplicate identity checks retained. |
| [#85](https://github.com/baobab-platform/baobab-dev/pull/85) a2d603f | Already closed. Historical custody carried in #86. |
| [#86](https://github.com/baobab-platform/baobab-dev/pull/86) 814a43e | Keep the historical #76 investigation and receipt. |
| [#87](https://github.com/baobab-platform/baobab-dev/pull/87) fd1b06e | Consolidated runtime transport and fallback. Keep open pending final-head review and qualification. |
| [#88](https://github.com/baobab-platform/baobab-dev/pull/88) 3b05f65 | Preserve live authenticated evidence and measured API receipt. |
| [#89](https://github.com/baobab-platform/baobab-dev/pull/89) a41e57b | Prototype remains separate pending accepted role authority. |
| [#90](https://github.com/baobab-platform/baobab-dev/pull/90) 4fb14d0 | Preserve unique regressions and unresolved effective rules. |
| [#91](https://github.com/baobab-platform/baobab-dev/pull/91) fcdb0c3 | Preserve 298-source evidence and bounded ancestry in #93. |
| [#92](https://github.com/baobab-platform/baobab-dev/pull/92) 8b13bb8 | Keep separately governed as a blocked draft. |

## 11. Deliverable status

| Deliverable | Classification |
| --- | --- |
| Architectural reconciliation | ACCEPTED as the audit record |
| Manifest and lock conformance | IMPLEMENTED BUT UNQUALIFIED for whole-image repeat-build equivalence |
| Release workflow treatment | ACCEPTED as the architecture record |
| GII-01–GII-14 matrix | IMPLEMENTED BUT UNQUALIFIED |
| Security regression and evidence register | IMPLEMENTED BUT UNQUALIFIED for protected release |
| CVE and risk register | BLOCKED |
| Multi-architecture qualification | IMPLEMENTED BUT UNQUALIFIED |
| GHCR release evidence | BLOCKED |
| Consumer and Codespaces qualification | BLOCKED |
| PR consolidation register | IMPLEMENTED BUT UNQUALIFIED pending final-head closure tests |
| Residual risk and readiness | BLOCKED |

Publication requires effective branch and release protections, a qualifying #74 source and protected independent approval, complete exact-image security evidence, successful registry readback and genuine consumer qualification. The 52 findings and unverified governance independently prevent release.
