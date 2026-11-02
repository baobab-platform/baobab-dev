# Baobab DEV-10 / PR #48 — Linux development-header advisory decision register

**Assessment:** 30 October 2026 | **Governing gate:** strict, unfiltered Trivy HIGH/CRITICAL, exit 1
**Scope:** Ubuntu 26.04, `linux-libc-dev 7.0.0-42.42`, the four baobab-dev image profiles on AMD64 and ARM64
**Decision:** **SECURITY HELD — exception NOT approved.** Not a waiver or release certificate.

## 1. What is established

1. Trivy Foundation run [41023886081](https://github.com/baobab-platform/baobab-dev/actions/runs/41023886081) reported exactly **295 distinct CVEs**, 12 critical and 283 high, against the Ubuntu `linux-libc-dev` package. There was no listed fixed version in that Trivy result. The [full inventory](dev10-kernel-cves.tsv) is preserved with original Trivy titles.
2. In an actual `ubuntu:26.04` container, the **exact pinned package version** `7.0.0-42.42` was installed from the Ubuntu archive and its `dpkg-query -L` manifest inspected. It contains **1,041 regular files: 1,039 `.h` headers plus two documentation files** (`changelog.Debian.gz`, `copyright`), with **zero ELF, PE or shebang executable files**. Diagnostic run: [41026633079](https://github.com/baobab-platform/baobab-dev/actions/runs/41026633079). The observed kernel implementation code, running kernel image, and kernel modules are *not* packaged as binaries inside `linux-libc-dev`. This is package-specific evidence, **not** a statement about the host kernel.
3. The [Canonical per-CVE audit](https://github.com/baobab-platform/baobab-dev/actions/runs/41026867063) queried **all 295** official `https://ubuntu.com/security/cves/CVE-NNNN-NNNN.json` records, selecting `packages[].name == "linux"`, `statuses[].release_codename == "resolute"`, and `pocket == "security"`. All **295 vendor records** were retrieved and matched. **287 `pending`**, **8 `needed`**, **zero `released`** and zero `not-affected` for the Ubuntu *kernel source package*. Canonical's source-package status does not independently establish applicability of executable kernel vulnerabilities to this headers-only binary subpackage. The exact case-by-case status is [here](dev10-canonical-cve-status-20261030.tsv).
4. The eight `needed` kernel source issues are: `CVE-2022-50240`, `CVE-2025-40190`, `CVE-2026-68103`, `CVE-2026-72198`, `CVE-2026-74578`, `CVE-2026-89805`, `CVE-2026-98376`, `CVE-2026-98420`. All other source CVEs are pending. Canonical's data reports versions including `7.0.0-43.43` as **pending**, not available fixes.
5. The current official Ubuntu `resolute-updates` archive lists `linux-libc-dev 7.0.0-42.42`; `7.0.0-43.43` occurs in the Canonical kernel team *proposed PPA*, **not** as an approved security update. Do not install a PPA/proposed package to turn a scanner green without ordinary release qualification.

## 2. Per-CVE applicability: bounded statement, no blanket exemption

Every advisory in the linked register has an independently sourced Ubuntu source status and a *binary applicability review pending* marker. The **candidate non-applicability** is that the vulnerabilities described concern Linux kernel implementation code, whereas this binary package contains only UAPI development headers and documentation. A kernel bug is not executable from the header package simply because its Ubuntu `linux` source package also builds a vulnerable kernel. However:

- User-accessible *header inline functions, macros or UAPI definitions* could still affect code compiled against those headers; keyword-only classification would miss this. **No per-CVE patched-source file-diff review has yet established that these cases do not affect the shipped headers.**
- A container shares the host kernel. This inventory does **not** assess vulnerabilities in GitHub-hosted/ Codespaces host kernels. That is a separate operator assurance boundary.
- No safe conclusion can be drawn about arbitrary resulting C/C++ binaries without examining how headers are used.
- The 295 upstream kernel-source vulnerabilities are **real vendor-tracked issues**. Calling them all false positives without scope and code-path evidence would be inaccurate.

**Preliminary technical assessment:** the 295 reported matches are *kernel-source-level* advisory matches against an installed **header-only** binary; package runtime exploitability is **not demonstrated**. This supports a *request for case-specific applicability review*, not a final `not_affected` decision.

## 3. Security authority decision and permitted routes

**Current enforceable decision: no exception; PR #48 remains HELD by Foundation and Publish Trivy.** Existing `--exit-code 1`, `--ignorefile /dev/null`, full-file coverage and no `--ignore-unfixed` remain unchanged.

Before any CVE-specific `not_affected`/OpenVEX decision is adopted:
- Security reviewer must compare each CVE's actual kernel patch paths against the installed `dpkg-query -L` header inventory. For any changed `include/uapi/*` or compiler-visible inline/macro code that ships in the binary, assess the downstream userspace exposure rather than waiving it.
- Obtain independent, attributable **security approval** for the exact image digest(s), CVE IDs, reviewed patch paths, justification and expiry/re-review trigger; protect the decision from self-approval. Keep the actual underlying vendor CVE status intact.
- If a vulnerability truly applies to shipped functionality, use Canonical's supported patched package when released, rebuild both architectures, repeat the entire scanning/functional suite and reject a `not_affected` assertion.
- If approved as `vulnerable_code_not_present`, issue scoped and reviewable VEX statements using normal policy controls, **not** `.trivyignore`, `--skip-files`, `--ignore-unfixed` or dropping necessary headers. Independently qualify VEX input, age, exact image identity, and scanner interpretation before changing any blocking CI semantics.
- Independently verify the Codespaces/CI host's kernel security lifecycle; never use this headers-only result as host-kernel clearance.

The current source-level CodeQL finding (#2, cache poisoning) was separately remediated in [commit 1611c30b](https://github.com/baobab-platform/baobab-dev/commit/1611c30be679462dfcab1daf5279038274d2af42); its check passed with zero new alerts. This does not clear the separate Trivy gate.

## 4. Reproducible evidence and custody

- Scanned CVE IDs/titles: `docs/assessments/dev10-kernel-cves.tsv`
- Canonical source-by-source statuses (all 295): `docs/assessments/dev10-canonical-cve-status-20261030.tsv`
- Vendor retrieval script: `scripts/audit_ubuntu_linux_headers.py`
- Canonical full description evidence artifact (30-day Actions retention): [run 41026867063](https://github.com/baobab-platform/baobab-dev/actions/runs/41026867063), `canonical-cves.json`
- Exact package content log: [run 41026633079](https://github.com/baobab-platform/baobab-dev/actions/runs/41026633079)
- Ubuntu package archive: https://packages.ubuntu.com/en/resolute-updates/amd64/devel/ ; Canonical API: https://ubuntu.com/security/api/docs
- Canonical VEX semantics: https://documentation.ubuntu.com/security/security-updates/vex/

**Reassessment triggers:** new Ubuntu 26.04 security package / USN, changed C UAPI headers, changes to toolchain/kernel privileges, new devcontainer image digest, altered Trivy data or new CVEs, and before staging/production promotion.

## 5. Additional upstream CVE source-path qualification (in progress)

The upstream Linux CVE team publishes affected source-file paths in its official
CVE CNA records. A **read-only, PR-scoped** qualification job records a pinned
upstream repository commit and compares all 295 affected-file claims against
the exact Ubuntu 26.04 linux-libc-dev 7.0.0-42.42 installed package manifest.
The review distinguishes source paths containing ".h" from implementation-only
paths, but both remain PENDING_INDEPENDENT_SECURITY_REVIEW. Missing data fails
closed; a matching header is escalated. This is an upstream affected-files
**triage**, not an Ubuntu-specific patch-diff or independent VEX attestation.

Code: scripts/audit_kernel_cve_paths.py; conservative tests:
tests/test_kernel_cve_paths.py; workflow:
.github/workflows/dev10-kernel-paths.yml.

A reviewed final disposition still requires the Canonical-specific patches
and shipped-header diff analysis for every CVE, host-kernel separation, bounded
image identity, accountable independent approval, and expiry/re-review controls.
No policy or scanner exemptions are authorized by this added evidence.

### Completed upstream Linux CVE affected-path classification — 30 October 2026

**Evidence run:** [41032607645](https://github.com/baobab-platform/baobab-dev/actions/runs/41032607645) (PASS). All **295/295** official Linux CNA JSON CVE records were retrieved at immutable upstream commit `604accad567eb6e7fb4c7fdc422470c25f35f467` and cross-checked against the actual Ubuntu `linux-libc-dev=7.0.0-42.42` binary's `dpkg-query -L` manifest (1,039 shipped headers). Every binary disposition remains `PENDING_INDEPENDENT_SECURITY_REVIEW`.

| Source path classification | CVEs | Meaning |
| --- | ---: | --- |
| Implementation-only affected paths | **248** | No `.h` paths in upstream CNA affected-file list |
| Internal kernel header paths | **47** | 4 CRITICAL, 43 HIGH; all outside `include/uapi/*` |
| Direct matching shipped UAPI headers | **0** | No affected-file path directly corresponds to an installed `/usr/include` header |
| Unverified/missing upstream records | **0** | All 295 records retrieved with exact SHA-identified source |
| Approved security exceptions / VEX | **0** | None authorized or applied |

The 47 cases include `CVE-2026-89659` (`fs/nfsd/netns.h`), `CVE-2026-89708` (`fs/nfsd/state.h`, `fs/nfsd/trace.h`), `CVE-2026-98621` (`include/net/gue.h`), and `CVE-2026-98503` (`include/linux/skbuff.h`). The complete 295-row list, all 47 header names, Canonical status and upstream paths are retained in the evidence artifact `affected-source-files.json`.

**Evidence hashes/custody:** `affected-source-files.json` SHA256
`bd2730b71a5dc7302373a7953d67dfbbe37a44ae2ede01039a63ba2df00398d4`;
actual `installed-paths.txt` SHA256
`688453ae46c07ec19b3bf6734eb2f23b0dfe5625c16d76d75149b8194da91fa3`.
The artifact also includes `upstream-commit.txt`. Source and regression tests are committed as `scripts/audit_kernel_cve_paths.py` and `tests/test_kernel_cve_paths.py`; the read-only workflow is `.github/workflows/dev10-kernel-paths.yml`.

**Decision remains SECURITY HELD.** The Linux CNA `programFiles` entries are upstream affected-file assertions, not complete Canonical-specific patch diffs. No direct UAPI path match supports a bounded `vulnerable_code_not_present` *candidate*, not a final exploitability verdict. An independent security reviewer must verify the Ubuntu 26.04 patch changes and binary-package derivation, indirect UAPI/ABI effects, host-kernel separation, exact resulting image digest, and an accountable expiring CVE-by-CVE decision. No blanket VEX, scanner ignores, relaxed HIGH/CRITICAL exit codes or release approval is justified by these observations.

## Development-only executive risk acceptance (30 October 2026)

**Authorisation source:** the user's explicit 30 October 2026 executive instruction to consider security approval granted and permit bounded governance overrides, recorded transparently in [issue #54](https://github.com/baobab-platform/baobab-dev/issues/54). The named responsible security personnel is **Wekhaso Nabusiu**. The instruction is recorded as **user-attested**, not as a forged GitHub-authenticated Wekhaso signature, Ubuntu remediation, or CVE-specific OpenVEX not-affected conclusion.

**Decision type:** a *temporary DEV-only ACCEPTANCE OF RESIDUAL RISK* for already identified advisory matches; this does **not** change the vendor CVE statuses, scientific per-CVE applicability state (all still under investigation), or the release security requirement.

**Exact limited scope:**
- Repository: baobab-platform/baobab-dev; specifically PR #48, the dependent DEV-14 doctor PR #50, and untagged development-main. All other PRs and version-tag release/staging/production are outside this temporary scope. The PR #50 extension does not extend the 2026-11-13 expiry or broaden the permitted CVE/package set.
- Image profiles: final, infra, frontend and frontend-e2e; architectures: AMD64 and ARM64.
- Package: Ubuntu 26.04 linux-libc-dev **7.0.0-42.42 only**.
- CVE allow-set: exactly the original 295 entries from docs/assessments/dev10-kernel-cves.tsv, pinned to Git blob SHA1 a98090feb9e3df2d9df72654516df69c64daf50e (12 CRITICAL, 283 HIGH). Partial remediation naturally reduces the permitted subset. No newly discovered CVEs, other packages, changed versions, changed severity or supported-fixed versions are accepted.
- Expiry: 2026-11-13 00:00 UTC. Repository exception expires 2026-11-12; renewal requires a new explicit security decision.
- Preserve unfiltered Trivy scan output and sanitized retained evidence. Trivy continues to run with --exit-code 1. Development risk evaluation only follows a vulnerability-triggered exit 1 and is fail closed on scanner/runtime errors or missing evidence.
- No accepted secret findings, no release-tag exception. Source-level tests cover denial cases.

**Implementation:** .baobab/repository.yaml records a temporary **existing Shared Foundation container-scan implementation exception**, because the pinned reusable gate cannot natively consume a package-specific risk decision. Instead of leaving an unscanned gap, .github/workflows/foundation.yml defines a **replacement unfiltered DEV-10 / Foundation container CVE gate** that builds and scans the actual Foundation image and applies the same bounded policy as the eight .github/workflows/publish.yml image scans. The policy is in scripts/dev10_kernel_risk_gate.py with negative tests in tests/test_dev10_kernel_risk_gate.py.

**Verification and escalation:** both replacement Foundation and Publish remain required to pass on the final PR head, including raw vulnerability evidence and all negative tests. The independent signed not-affected/VEX path remains unactivated and reserved for a genuine, evidence-complete decision. No runtime claim or production safety is derived from this temporary DEV risk acceptance. Issue #54 remains open for patch-level applicability, supported remediation and durable governed approvals.

**Risk owner:** Wekhaso Nabusiu, designated by the user. **Approval authentication:** chat-level user direction only; GitHub account binding and cryptographic signature have not been independently verified, and must not be portrayed as such.
