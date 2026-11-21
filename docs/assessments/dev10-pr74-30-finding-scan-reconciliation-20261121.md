# PR #74 — 30-finding scan inventory reconciliation

## Verified scan matrix at `331f98e`

Foundation and all eight Publish scans completed at PR head
`331f98ef2fc3a8bb74b219aa341a829dc766c91a`, merge checkout
`1a58a74370b69dd234451c99bfe02253587b95e8`. All nine retained archives match
their GitHub transport digests. Their sanitized Trivy reports, normalized
results and review-only inventories agree on the same 30 findings, with 27
HIGH, three CRITICAL, all `affected` and no fixed version. The canonical
inventory SHA-256 is `6f95364a4c221519d29e6a95458e04918ee2495b4ae16dc6b1f272e8b84663f3`.
[Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/44891218175) ·
[Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/44891217409) ·
[Verified scan evidence](dev10-pr74-331f98e-scan-evidence.json)

The scan ran to completion. The security gates then failed during custody
verification because the post-handover owner check was applied to the
historical #76 decision. The archive inventories contain no effective
decision for these findings.

## Verified scan matrix at `6c285e49`

Foundation run [44877264266](https://github.com/baobab-platform/baobab-dev/actions/runs/44877264266)
and Publish run [44877263421](https://github.com/baobab-platform/baobab-dev/actions/runs/44877263421)
completed for PR head `6c285e49a37beebb4a9dcade2f1d3ff9351ad957`, tested at
merge checkout `ae0832986cd4d2a087586b63941de79575427df9`. The Foundation
scan and all eight Publish scans denied the same 30 `linux-libc-dev=7.0.0-44.44`
findings. Each reported 27 HIGH and three CRITICAL findings, all `affected`,
with empty fixed-version fields. The eight native Publish jobs passed their smoke
checks and retained their installed-file manifests. Security qualification stays
blocked.

The [scan evidence](dev10-pr74-6c285e4-scan-evidence.json) records the verified
GitHub archive SHA-256, retained Trivy JSON SHA-256, normalized output digest,
image identity and exact finding inventory for each job. Each archive's digest
matched the Actions API, and the retained Trivy JSON, normalized JSON and
review-only inventory agreed. The workflows keep the potentially secret-bearing
raw JSON on the runner. Its SHA-256 is recorded as reported by the workflow;
the retained, sanitized report bytes were independently rehashed.

## Earlier result at `513d53d`

At PR head `513d53d6088e52c0bb6baa0979307a10c4d7e281`, the retained Foundation scan and all eight Publish profile/architecture scans agree on the exact package finding set:

- Package: `linux-libc-dev`
- Installed version: `7.0.0-44.44`
- Ecosystem: Ubuntu
- Findings per scan: **30 unique CVEs**
- Severity: **3 CRITICAL, 27 HIGH**
- Status: `affected` for all 30; scanner fixed version: none
- Consistency: all nine scans have identical CVE sets and matching package/version/severity/status fields.

The earlier 28-row inventory omitted **CVE-2026-99312** and **CVE-2026-99317**.
The [binary applicability register](dev10-ubuntu-44.44-binary-applicability.json)
now includes both findings and keeps their disposition under investigation.

## Earlier retained scan artifacts

The artifact SHA-256 values below are GitHub's retained archive digests. The
report digests identify the sanitized Trivy JSON member inside each archive.

| Workflow | Profile | Platform | Artifact ID | Artifact SHA-256 | Retained Trivy JSON SHA-256 |
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

Every row below was present in all nine reports at each recorded head with
package `linux-libc-dev`, installed version `7.0.0-44.44`, ecosystem `ubuntu`,
status `affected` and no scanner fixed version.

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

The subsequent [kernel package remediation investigation](dev10-pr74-kernel-package-remediation-20261121.md) found no evidence-backed newer Canonical-supported fixed package for this inventory. The exact amd64/arm64 package pins remain unchanged; all 30 findings remain blocking.

The [development risk assessment](dev10-ubuntu-44.44-development-risk.md)
records package, source and exposure evidence for all 30 findings. Each
one remains blocking pending remediation or a substantiated disposition and
its required approvals.

## Closure sequence

| Gate | Status at the audited head |
| --- | --- |
| 1. Reconcile current-head scans | Foundation and all eight Publish scans completed. The nine retained reports agree on 30 blocking identities. |
| 2. Complete per-CVE evidence | All 30 have a technical record, including the two omitted CVEs. Applicability and host controls remain under investigation. |
| 3. Check supported remediation | Six signed Canonical indexes confirm the newest supported binary is the locked 44.44 build. The generic Resolute `linux` tracker still records fixes needed for all 30. |
| 4. Freeze an approval-ready residual scope and obtain concurrence | Blocking evidence remains for the 27 holds and each of the three earlier conditional candidates. The owner's earlier concurrence addressed only the 28-finding scope at `513d53d`. |
| 5. Verify independent approval and activate | Blocked on a supported decision scope and the final decision-PR review. Decision PR #76 covers the older `7.0.0-43.43` inventory. |
| 6. Qualify the final source | Pending remediation or an effective exact-scope decision. The checks at `6c285e49` establish the present failure and provide comparison evidence for the next qualification. |
