# PR #74 — kernel package remediation investigation (2026-11-21)

**Follow-up acquisition result:** no Canonical-supported fixed Resolute package was obtained; public catalogue and CVE tracker evidence are recorded in [Canonical fixed-package acquisition result](dev10-pr74-canonical-fixed-package-acquisition-20261121.md). The lock remains unchanged and all 30 findings remain blocking.

## Decision

**No package-version change is justified by the available Canonical evidence. Keep the current package pin and keep the security gate blocking.**

The investigated package remains `linux-libc-dev=7.0.0-44.44`. The current retained Foundation and eight Publish Trivy reports identify 30 findings on that exact package, with no scanner fixed-version values. The two newly reconciled findings, CVE-2026-99312 and CVE-2026-99317, are included in that 30-finding set but remain without completed binary-applicability assessments.

No newer Canonical-supported `linux-libc-dev` binary version with fixes for this finding set was established by the retained signed Resolute archive-index evidence. The existing applicability evidence records:
- Resolute Updates: `7.0.0-44.44` for amd64 and arm64.
- Resolute Security: `7.0.0-43.43`.
- The current 44.44 amd64 and arm64 DEBs match the signed package-index entries and the committed version lock.
- No newer supported package or fixed-version signal was present in the checked archive indexes.

A newer upstream Linux commit, a newer kernel source tag, a package in `-proposed`, or a version string alone is not a supported binary remediation. Do not promote a proposed package or substitute a custom kernel/header build without a separately verified Canonical publication and exact architecture payload provenance.

## Exact locked package identities

Checked against `config/versions.lock` at PR head `b40563004eed4ad0b8fc1ec75da186dff81b57df`:

| Field | Value |
|---|---|
| Ubuntu release | 26.04 LTS (Resolute) |
| Binary package | `linux-libc-dev` |
| Version | `7.0.0-44.44` |
| AMD64 DEB SHA-256 | `b1bd69037483894be260e934503e8c99debebb6d622e3d5010e79fea4108ee43` |
| ARM64 DEB SHA-256 | `4c9e3d5345e22876a4c2b3631dc2011c8e79228e6cd0d8020ad01663e31e306e` |
| Canonical source tag | `Ubuntu-7.0.0-44.44` |
| Source tag commit | `70d93713221b617bdb0f55289ffb52b99f2038cf` |

The package/source evidence and signed-index digest details are retained in [the binary applicability evidence record](dev10-ubuntu-44.44-binary-applicability.md). That record also explicitly leaves independent verification of the tag signer's key and comparison of the source archive against the Git tree open. Those provenance gaps are not waived here.

## Canonical vulnerability status cross-check

Canonical's Ubuntu Security Tracker does not support treating the additional CVEs as cleared:

| CVE | Canonical Resolute status | Consequence |
|---|---|---|
| [CVE-2026-99312](https://ubuntu.com/security/CVE-2026-99312) | Needs evaluation | Not an unaffected or fixed disposition; binary applicability remains unresolved |
| [CVE-2026-99317](https://ubuntu.com/security/CVE-2026-99317) | Vulnerable | Explicitly remains a security finding |
| [CVE-2026-99287](https://ubuntu.com/security/CVE-2026-99287) | Vulnerable | Critical finding remains unresolved |
| [CVE-2026-99270](https://ubuntu.com/security/CVE-2026-99270) | Vulnerable | High finding remains unresolved |

The Canonical tracker describes CVE-2026-99312 as a KVM nested-SVM INIT/MMU-context issue and links upstream fixes, but its Resolute status is still **Needs evaluation**. That is not evidence that the exact Canonical binary contains the fix. CVE-2026-99317 is marked **Vulnerable** for Resolute. The Canonical tracker status and the Trivy binary-package result are separate evidence streams; neither is silently substituted for the other.

The nine retained Trivy reports remain the controlling current-image inventory evidence: all nine report the same 30 CVEs for `linux-libc-dev=7.0.0-44.44`, all with status `affected` and no fixed version. See [the retained scan reconciliation](dev10-pr74-30-finding-scan-reconciliation-20261121.md).

## Engineering action

- **Do not change** `LINUX_LIBC_DEV_APT_VERSION` or either architecture SHA-256 in `config/versions.lock`.
- Do not change `.devcontainer/docker/Dockerfile` package verification, Trivy thresholds, ignore lists, VEX, or protected decision data to make the scans pass.
- Do not infer that the upstream fix references for CVE-2026-99312 or CVE-2026-99317 are present in the Canonical binary.
- Preserve all 30 findings as blocking. The 28-record applicability register remains incomplete for the two new CVEs; they must be separately examined using authoritative CNA/Ubuntu source evidence and exact package payloads.
- Revisit the package pin only when Canonical publishes a supported Resolute binary package whose signed amd64 and arm64 indexes, DEB hashes, source identity and changelog establish the candidate version. Then build all eight native profile/architecture images and retain fresh native payload manifests and unfiltered Trivy reports before assessing the remaining findings.

## Acceptance result

| Criterion | Result |
|---|---|
| Exact current package/version identified | Pass — `linux-libc-dev=7.0.0-44.44` |
| Both architecture payload hashes identified | Pass — exact locked SHA-256 values recorded above |
| Canonical-supported newer fixed package established | **Not established** |
| Package pin changed | No — intentionally unchanged |
| 30-finding security block preserved | **Yes — all 30 remain blocking** |
| New native scans after package update | Not applicable — no supported fixed package was identified and no package update was made |
| Security approval or risk acceptance | None granted |

This is a remediation-investigation result, not a CVE disposition, risk acceptance, waiver, release qualification or approval. It does not make PR #74's security checks legitimately green.
