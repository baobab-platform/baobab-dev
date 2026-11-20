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

`f15ad8d9ded6db5d9e023faa8193eb466682fd91d364261e883530b436e05c30`

This is the digest required in the 12-finding decision's `evidence_lock_sha256` field. It binds the reviewed inventory, canonical snapshot, Ubuntu tag, binary manifest and eight profile/architecture scan artifact digests. If any locked evidence input changes, recompute this value and update the proposed decision; do not retain a stale digest.

## Exact Ubuntu source-history and binary evidence — 2026-11-19

### Reproducible evidence run

The consolidated read-only workflow completed as run `44597449221` against:
- Ubuntu source repository: `https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute`
- Exact tag: `Ubuntu-7.0.0-43.43`
- Exact tag commit: `f53b359683af7918c5436499948763cb726d5082`
- Complete, non-shallow history: 1,444,815 reachable commits
- Upstream Linux CNA snapshot: `604accad567eb6e7fb4c7fdc422470c25f35f467`
- Canonical Ubuntu OSV snapshot: `88c00a77a1247172dd107f5dd3f24a1e1d1f57b2`, retrieved at `2026-11-19T19:22:16Z`

The 298-record fix-history report is SHA-256 `dc3be4f27ff331e0a4e9dd5ba20f6b486592d25bc8bcc925535be7def6569758` (artifact 14568208232; outer ZIP SHA-256 `8216df836347d7630318f7fc5670bfd9b967eafe7056d0c8474659902b36f3ca`). The source/binary evidence bundle is artifact 14568158229; outer ZIP SHA-256 `5c91b285f91fc559ab32036e84435fa691443c10a50eb92ff87c5cc8a620bee3`. The report sidecar matched the inner report digest.

The first history run's 1,200-second analysis budget was exhausted. It enumerated 1,458 candidate commits and returned 1,434 `ANALYSIS_BUDGET_EXHAUSTED`, 20 `DOWNSTREAM_PATCH_EVIDENCE_INCOMPLETE`, three `EXACT_UPSTREAM_COMMIT_IN_UBUNTU_ANCESTRY`, and one `PATCH_SEARCH_TRUNCATED_INCOMPLETE` candidate assessments. All 298 records remain `under_investigation`.

### Scanned kernel CVE source-history results

| CVE | Exact upstream fix commit in Ubuntu tag ancestry | Patch-ID correspondence observed | Path discrepancy | History conclusion |
|---|---|---|---|---|
| CVE-2022-50240 | `a43cfc87caaf46710c8027a8c23b8a55f1078f19` | Three stable candidate references match the same Ubuntu commit patch ID | `drivers/android/binder_alloc_selftest.c` absent | Upstream fix ancestry evidenced; remaining candidate/path review incomplete |
| CVE-2025-40190 | `57295e835408d8d425bef58da5253465db3d6888` | Seven stable candidate references match the same Ubuntu commit patch ID | None | Upstream fix ancestry evidenced; remaining candidate/path review incomplete |
| CVE-2026-68103 | None proven | None | None | Two candidates incomplete |
| CVE-2026-72198 | `7ffa8f3d30236e0ab897c30bdb01224ff1fe1c89` | None | `fs/ntfs/attrib.c` absent; same-basename lead `fs/ntfs3/attrib.c` | Exact candidate ancestry evidenced; path search truncated/incomplete |
| CVE-2026-74578 | None proven | Two candidate references match Ubuntu commit `04ee0ee4f87b62284c84f064a6607a0f33820a03` | None | Patch-ID leads recorded, but full candidate/path analysis incomplete |
| CVE-2026-89805 | None proven | None | None | Two candidates exhausted analysis budget |
| CVE-2026-98376 | None proven | None | `tools/testing/selftests/bpf/prog_tests/percpu_array_inner_map.c` absent | Candidate analysis exhausted budget |
| CVE-2026-98420 | None proven | None | None | Two candidates exhausted analysis budget |
| CVE-2026-98869 | None proven | None | `kernel/bpf/fixups.c` absent (3/4 upstream paths present) | Candidate analysis exhausted budget |
| CVE-2026-98890 | None proven | None | None | Seven candidates exhausted analysis budget |
| CVE-2026-99083 | None proven | None | None | Five candidates exhausted analysis budget |

A candidate commit being an ancestor or a patch ID matching is source-history evidence only. The incomplete searches and absent path records must not be converted into a general fixed/not-fixed statement. In particular, the two exact source-ancestry results plus the CVE-2026-72198 ancestry result do not establish that the installed binary package contains a relevant shipped header fix. The two CVE-2026-74578 patch-ID matches are not a completed backport verdict because the search is incomplete.

### Installed binary package and Canonical OSV cross-check

The workflow captured and verified the actual installed amd64 package:
- Installed package: `linux-libc-dev=7.0.0-43.43`, status `install ok installed`
- Source package: `linux=7.0.0-43.43`
- Downloaded .deb SHA-256: `3a3adc14e3332fc017b1d0e4e39655298a2a977d51db6e80de533ac60137b07f`
- Installed-path manifest: 1,102 paths, SHA-256 `688453ae46c07ec19b3bf6734eb2f23b0dfe5625c16d76d75149b8194da91fa3`
- Installed-content manifest: SHA-256 `fd5030d2d8ac2f356122e09dddfed651dd781fe140e9dfc035ad23ce450442e6`
- Ubuntu base image: `ubuntu@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db`

APT reported installed `7.0.0-43.43`, candidate `7.0.0-44.44`; the exact installed 43.43 package was in `resolute-security`, while 44.44 was in `resolute-updates`. This identifies an available newer candidate for remediation testing; it does not establish that 44.44 fixes each of these 11 advisories. The source tag and binary evidence remain pinned to 43.43.

The pinned Canonical OSV snapshot classifies the 11 scanned kernel CVEs as follows:
- **Six list the exact `linux-libc-dev=7.0.0-43.43` binary version as affected:** CVE-2026-89805, CVE-2026-98376, CVE-2026-98420, CVE-2026-98869, CVE-2026-98890 and CVE-2026-99083.
- **Five list the Ubuntu `linux` source version as affected but do not list the exact `linux-libc-dev` binary version:** CVE-2022-50240, CVE-2025-40190, CVE-2026-68103, CVE-2026-72198 and CVE-2026-74578.

The five missing binary-version entries are evidence requiring review, not proof of non-affectedness. Canonical's OSV evidence reports no fixed versions for these records in this snapshot.

The exact installed content manifest contains no matching shipped file for the identified kernel-private affected headers:
- CVE-2022-50240: `drivers/android/binder_alloc.h`
- CVE-2026-98420: `fs/smb/server/connection.h`, `fs/smb/server/mgmt/user_session.h`, `fs/smb/server/smb2pdu.h`, `fs/smb/server/stats.h`
- CVE-2026-98869: `include/linux/bpf_verifier.h`

The upstream affected-file records for the other eight scanned kernel CVEs do not identify an affected header. No direct UAPI path match was found for any of the 11 CVEs. This supports the conclusion that the scanner's source-package findings do not correspond to a directly observed affected source file in the installed header payload. It does **not** resolve indirect UAPI/ABI exposure, inline/macro effects, downstream userspace compilation, or shipped-header byte equivalence. Those checks remain explicitly unverified in the register; no VEX `not_affected` is justified.

### Extended history run

The workflow's bounded analysis window has been increased from 1,200 to 3,300 seconds. Follow-up run `44604258567` was in progress when this report was updated. Its result must replace the first run's incomplete candidate assessment only after its final artifact is downloaded, digest-checked, schema-validated and reviewed. The 3,300-second limit is not a promise that all 1,458 candidates will finish; any remaining budget-exhausted or truncated result stays unresolved.

## Disposition

- Scan reconciliation: **complete for the retained historical eight-artifact run**.
- Picomatch image scope: **confirmed; six of eight scans**.
- Evidence-lock hash: **computed from exact lock-file content; CI regression verification remains required**.
- Source history/backport and binary applicability: **not complete**. All 11 kernel findings remain under investigation until the current fix-history run is complete and an independent technical review resolves source and shipped-header exposure.
- No VEX, risk activation, release, publication or promotion authorization is created by this report.


## Follow-up run 44604258567 — 2026-11-20 review

### Execution result and history failure

Run [44604258567](https://github.com/baobab-platform/baobab-dev/actions/runs/44604258567) completed with job conclusion `failure`. The evidence-lock load and offline regression suite passed, including all five `test_dev10_evidence_lock.py` tests and all 17 `test_dev10_ubuntu_kernel_fix_history.py` tests. Binary provenance, Canonical OSV validation, upstream CNA path reproduction and Ubuntu source-path corroboration also completed.

The failure is specifically the step **Materialize complete blobless Ubuntu tag history**. Its 25-minute step timeout fired while Git delta resolution was at approximately 86% (8,510,980 of 9,807,866 objects). The subsequent fix/backport assessment, exact join and final applicability-register schema validation were skipped. The fix-history JSON and its SHA-256 sidecar were not created; the corresponding upload step correctly warned that no files were found. The 3,300-second analysis budget therefore never started and must not be described as exhausted or completed in this run.

The retained source/binary artifact is ID `14572291876`, outer ZIP SHA-256 `4ce0ceb594f51bad411f7fc5f68ace4cbe47c6a8eedcebdb851f6e3e34d2af19`. The downloaded ZIP independently hashes to the same value. It contains the source-path, affected-source-file, Canonical OSV, binary provenance and package payload evidence, but no new candidate-history assessment.

### Additional exact binary-payload verification

I extracted the amd64 `linux-libc-dev_7.0.0-43.43_amd64.deb` from artifact 14572291876 and independently verified its SHA-256 as `3a3adc14e3332fc017b1d0e4e39655298a2a977d51db6e80de533ac60137b07f`, matching the package provenance record and binary evidence lock. I then extracted the .deb and compared every row of the captured installed-content manifest against the extracted package payload:

- 1,102 manifest entries checked.
- Zero missing entries.
- Zero file-content SHA-256 or symlink-target mismatches.
- The manifest covers 1,039 headers and 1,102 total paths.

This establishes byte-for-byte agreement between the captured installed amd64 package content and the exact downloaded .deb payload. It does **not** establish equivalence between those shipped headers and the Ubuntu source-tag headers, prove whether an inline/macro/ABI effect is reachable, or establish downstream compilation impact.

The affected-source-file record still identifies no direct shipped UAPI path match for any of the 11 kernel CVEs. The three named private-header groups (CVE-2022-50240, CVE-2026-98420 and CVE-2026-98869) are absent from the package payload. The remaining indirect UAPI/ABI, compiler-transitive and downstream-consumer exposure questions remain unresolved. This run captures only amd64 binary payload evidence; the arm64 package hash remains separately pinned in the binary evidence lock but was not re-captured in this run.

### Current closure state

- Evidence-lock regression: **passed in run 44604258567**.
- Source-path and exact amd64 package provenance: **captured and digest-verified**.
- Installed amd64 package versus downloaded .deb payload: **all 1,102 manifest entries match**.
- Full Ubuntu commit ancestry and candidate fix/backport analysis: **not run; history materialization timed out before analysis**.
- Five Canonical OSV records without an exact binary-version entry: **still require source-to-binary applicability review**.
- Indirect UAPI/ABI and downstream compilation exposure: **still under investigation**.
- Arm64 binary payload re-capture and comparison: **not performed in this run**.

No CVE disposition changes. All 11 kernel CVEs remain under investigation; no VEX `not_affected`, fix, backport, risk acceptance or release authorization is inferred.
