# PR #74 — retained scan inventory reconciliation

## Result

At PR head `513d53d6088e52c0bb6baa0979307a10c4d7e281`, the retained Foundation scan and all eight Publish profile/architecture scans agree on the exact package finding set:

- Package: `linux-libc-dev`
- Installed version: `7.0.0-44.44`
- Ecosystem: Ubuntu
- Findings per scan: **30 unique CVEs**
- Severity: **3 CRITICAL, 27 HIGH**
- Status: `affected` for all 30; scanner fixed version: none
- Consistency: all nine scans have identical CVE sets and matching package/version/severity/status fields.

The former 28-row inventory was incomplete. The two findings absent from its detailed applicability register are **CVE-2026-99312** and **CVE-2026-99317**. Both are recorded in the current inventory as `blocked_unassessed`. This reconciliation does not establish binary applicability, remediation, VEX status, risk acceptance or release authority.

## Retained raw scan artifacts

The artifact SHA-256 values below are GitHub's retained workflow-artifact archive digests. The raw-report SHA-256 values identify the Trivy JSON member inside each archive.

| Workflow | Profile | Platform | Artifact ID | Artifact SHA-256 | Raw Trivy JSON SHA-256 |
|---|---|---|---:|---|---|
| Foundation Repository Gates (run [44858284325](https://github.com/baobab-platform/baobab-dev/actions/runs/44858284325)) | foundation | linux/amd64 | 14689106900 | `efcec8a887460f55a718fb17667bf5539ba5939ad0ca5406a8a3d7622e2da0ee` | `dece0c0607b4aeb9eb2f6f9868053c4e084ec7feafdeef0634d0799528a4bd14` |
| Publish (run [44858283649](https://github.com/baobab-platform/baobab-dev/actions/runs/44858283649)) | final | linux/amd64 | 14689441394 | `b72b51b4653aece3d4e0b8a24c8af747baaf840bff15baa3b6bb1a0da882c3ec` | `5e7cd783386810fa71f159c935d074f797dbeecf33830625ee6f870e4cca5015` |
| Publish | final | linux/arm64 | 14689006797 | `21a10216b4c80badad60b36738cc5e627b88f5f04db5627dfab67ad1a869d52c` | `fdc01716419d9509661f0bf3c3423e1ea79547dca0c3230d3aeaf42cf23e054a` |
| Publish | frontend | linux/amd64 | 14688672787 | `1055c2c46613835d5375a5d804801dd646f28edbb18edd42497415d0e75cee23` | `edf636face1cabbc063b4e2bc5c2a428e5e2c17daa727b38e3394fb7e13dba93` |
| Publish | frontend | linux/arm64 | 14689100324 | `3b61532aa3a059b9a4669191e23d514109e4cdabac3722d5153937b3eb4d75bf` | `921cc5b68164cf9011c40a050538a1577cbab4d62bfd0e30da0e0b4aed18d4d4` |
| Publish | frontend-e2e | linux/amd64 | 14689610691 | `57ade9d36872c0c720e36c631f1b0ab280c17057d32c664f8d1579ae268ab7d2` | `127aa087762dcf3d6e1e7775bf7fb9ac2b63e4e4b25ca4b8cc2d546d52568de1` |
| Publish | frontend-e2e | linux/arm64 | 14689211402 | `7734278d8ca03073f0365c273f33f500d297a4afcfad3e53e5ad1e37a6e590e2` | `35ad39abee96f40f8f433a36e41aef4ccbd841d37c6236fde2c001a3d8b61621` |
| Publish | infra | linux/amd64 | 14688504730 | `17daeb8b5fa2b1067664734cc99d90a49064bab021c9f7fdec18d030519cce0f` | `f43dd20625168e1f52e1c8665b0efb27296165d3b634814fe49a6b294df9be3f` |
| Publish | infra | linux/arm64 | 14688464551 | `5dcafcbc423b53d37479896f9573fd30385f85a4c37b535677596bc2480e2b0d` | `c9368486e04376b81d5e511d28618b546725966e7c9dd362d69ffdfd347e52ef` |

## Exact reconciled inventory

Every row below was present in each of the nine retained raw reports with package `linux-libc-dev`, installed version `7.0.0-44.44`, ecosystem `ubuntu`, status `affected` and no scanner fixed version.

| CVE | Package | Installed version | Severity | Scanner status | Fixed version |
|---|---|---|---|---|---|
| CVE-2022-50240 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2025-40190 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-100081 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-68103 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-72198 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-74578 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-89805 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-98376 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-98420 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-98869 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-98890 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99239 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99260 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99270 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99272 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99274 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99275 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99282 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99287 | linux-libc-dev | 7.0.0-44.44 | CRITICAL | affected | none |
| CVE-2026-99288 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99290 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99292 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99295 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99302 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99304 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99306 | linux-libc-dev | 7.0.0-44.44 | CRITICAL | affected | none |
| CVE-2026-99310 | linux-libc-dev | 7.0.0-44.44 | CRITICAL | affected | none |
| CVE-2026-99311 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99312 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |
| CVE-2026-99317 | linux-libc-dev | 7.0.0-44.44 | HIGH | affected | none |

## Assessment boundary and next required work

The existing detailed binary-applicability JSON has 28 records. It has no records for CVE-2026-99312 or CVE-2026-99317. This change corrects the scan inventory and makes that gap explicit; it does not fabricate CNA/source-path evidence for the missing records. Those two CVEs require their own authoritative advisory/source evidence and review before any applicability or risk disposition is proposed.

The 30 findings remain blocking. No scanner threshold, ignore rule, VEX statement, protected decision, approval, or release gate was changed.
