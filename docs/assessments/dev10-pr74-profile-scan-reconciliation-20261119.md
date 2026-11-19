# PR #74 exact profile/architecture scan reconciliation — 2026-11-19

## Decision boundary

This is an evidence reconciliation, not a VEX statement, remediation assertion, risk approval, or release qualification. Finding identity is the exact tuple `(CVE, package, installed version, severity, type)`; profile and architecture are retained as scan provenance.

## Result

The retained scan set contains **12 unique findings**, not 52. The earlier 52-finding count was an incorrect aggregation and must not be used for #92's scope. All eight normalized `findings.json` artifacts were downloaded and inspected. Their outer ZIP SHA-256 values match the corresponding artifact digests already recorded in `security/evidence/dev10-kernel-evidence.lock.json`.

- 11 unique Ubuntu `linux-libc-dev=7.0.0-43.43` HIGH findings occur in all eight profile/architecture artifacts.
- One unique npm `picomatch=4.0.5` HIGH finding (CVE-2026-112366) occurs in final, frontend and frontend-e2e, on both architectures. It is absent from both infra artifacts.
- The union across all eight artifacts is exactly 12 unique finding identities.
- Every listed finding has Trivy status `affected` and `fixed_version: null` in the normalized records. This is scanner evidence only; it does not prove upstream or vendor fix status.

## Exact eight-artifact matrix

| Profile | Architecture | Artifact ID | ZIP SHA-256 | linux-libc-dev | picomatch | Total |
|---|---|---:|---|---:|---:|---:|
| final | linux/amd64 | 14410162334 | `bf84ec7debcf4063a519095c0a99205cec59d6bd37a5d4cf13d2a42d3fb144e6` | 11 | 1 | 12 |
| final | linux/arm64 | 14409828180 | `216213895d2305ff197819ab68c3f0c938baeac4331f5c3f9fde7a0ef900f6d2` | 11 | 1 | 12 |
| frontend | linux/amd64 | 14409114266 | `5a503f8aba34dea18bfff717d51004fc0807b7a3497f86f5790b28275bf16977` | 11 | 1 | 12 |
| frontend | linux/arm64 | 14409493397 | `1fcee6f58efa2f53643f2b0ce018f84f7097ff1a456f9413055cb41ef979b334` | 11 | 1 | 12 |
| frontend-e2e | linux/amd64 | 14409399064 | `8d0ce55480d49ab896526877675550a245d3ac0aed2dd66e8898888dfe3f86ff` | 11 | 1 | 12 |
| frontend-e2e | linux/arm64 | 14410810129 | `f71c837c32e2a79228140f31a10e5cf4c4da34050a58bba88e512b0b1d7a6732` | 11 | 1 | 12 |
| infra | linux/amd64 | 14410191777 | `652fc27821e383980ed001a1cad8f471cdf4cd5290c46a8d2a3df47d45c25af9` | 11 | 0 | 11 |
| infra | linux/arm64 | 14410525385 | `c8c2c038ecc47931ff3fb14b34eeda4baa48c796cc7c3a58a52d23037fe4e549` | 11 | 0 | 11 |

Run: `44264450503` (historical PR #74 profile scan). The ZIP digests above were independently recomputed from the downloaded artifact bytes and match the evidence-lock pins.

## Exact unique finding inventory

| CVE | Package | Installed version | Severity | Type | Profiles |
|---|---|---|---|---|---|
| CVE-2022-50240 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2025-40190 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-68103 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-72198 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-74578 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-89805 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-98376 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-98420 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-98869 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-98890 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-99083 | linux-libc-dev | 7.0.0-43.43 | HIGH | ubuntu | all 8 |
| CVE-2026-112366 | picomatch | 4.0.5 | HIGH | node-pkg | final, frontend, frontend-e2e (both architectures) |

## picomatch scope decision

CVE-2026-112366 belongs in the **developer-image inventory and the proposed development-only decision**. It is present in six of eight exact image scans, including final and frontend profiles, at the nested npm CLI path:

`usr/lib/node_modules/npm/node_modules/tinyglobby/node_modules/picomatch/package.json`

Trivy reports PURL `pkg:npm/picomatch@4.0.5`, advisory `GHSA-fc5q-39xc-vjpf`, HIGH, and no fixed version. The finding is not present in infra, which is a legitimate subset of the exact 12-finding policy scope. Its presence does not establish application bundling, exploitability in a particular workflow, or remediation. Do not remove it from the decision merely because it is absent in infra; do not suppress or upgrade it without a tested and evidence-backed fix.

## 298-CVE source/binary analysis boundary

The separate 298-record kernel source inventory is not the image scan inventory. It preserves 295 historical 7.0.0-42.42 records plus three 7.0.0-43.43 kernel CVE extensions. The 11 kernel findings above have been joined to the 298-record source/applicability register. That register currently records all 298 as `under_investigation`, with no approved disposition.

For the 11 scanned kernel CVEs:
- all 11 are scanner-observed on the installed `linux-libc-dev=7.0.0-43.43` package;
- direct executable presence was not observed in the exact binary manifest;
- no direct UAPI manifest path match is recorded;
- shipped-header byte comparison, indirect UAPI/ABI exposure and downstream compilation remain under investigation;
- Ubuntu fix-commit, backport provenance and security-pocket fixed-version verification remain false/unverified;
- path presence in the Ubuntu tag is non-dispositive. Three have upstream path discrepancies: CVE-2022-50240, CVE-2026-72198 and CVE-2026-98376 among the original eight, plus CVE-2026-98869 among the three extensions (four scanned CVEs total).

The exact source tag is `Ubuntu-7.0.0-43.43` at `f53b359683af7918c5436499948763cb726d5082`; the upstream Linux CNA snapshot is `604accad567eb6e7fb4c7fdc422470c25f35f467`. The exact binary manifest SHA-256 is `688453ae46c07ec19b3bf6734eb2f23b0dfe5625c16d76d75149b8194da91fa3` (1,102 paths; 1,039 headers).

The source-history/backport workflow run `44597449221` was still executing at the time this reconciliation was written. Its fix-history artifact must be reviewed before any ancestry/backport statement is upgraded. No CVE is marked fixed or not affected here.

## Evidence-lock binding

The exact SHA-256 of `security/evidence/dev10-kernel-evidence.lock.json` at this branch head is:

`db53b7f55f2ce287f764a031656fd7e57c5e5cd06ad7dc07d9a25c790bf0cb80`

This is the digest required in the 12-finding decision's `evidence_lock_sha256` field. It binds the reviewed inventory, canonical snapshot, Ubuntu tag, binary manifest and eight profile/architecture scan artifact digests. If any locked evidence input changes, recompute this value and update the proposed decision; do not retain a stale digest.

## Disposition

- Scan reconciliation: **complete for the retained historical eight-artifact run**.
- Picomatch image scope: **confirmed; six of eight scans**.
- Evidence-lock hash: **computed from exact lock-file content; CI regression verification remains required**.
- Source history/backport and binary applicability: **not complete**. All 11 kernel findings remain under investigation until the current fix-history run is complete and an independent technical review resolves source and shipped-header exposure.
- No VEX, risk activation, release, publication or promotion authorization is created by this report.
