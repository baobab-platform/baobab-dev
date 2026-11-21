# DEV-10 v1.5.2 release remediation

The inventory baseline was PR #74 head `3cf5ec558c8f44657f1b8422d3861c321316fd36` and tested merge commit `0cd745bb0675ef1143e81ecfe5b3e4a482f38e76`. The release remains held.

## 1. Reconcile the failing gates

The [blocking inventory](dev10-pr74-blocking-inventory-20261120.tsv) records 53 unique findings from nine digest-verified image scan artifacts and the failing source-graph log. All eight Publish image builds reached their scan. Each image and the Foundation image reported 52 Ubuntu header findings, including 24 HIGH with a listed fix and 28 without one. Foundation and the four final/infra image configurations also reported CVE-2026-95839 in both Docker plugins. The Security job reported the same CVE in the Buildx and Compose source graphs. The other two Go graphs and the independent Python audit passed. None of the nine image reports contained a secret finding or a picomatch finding.

- [Foundation run](https://github.com/baobab-platform/baobab-dev/actions/runs/44728551182)
- [Publish run](https://github.com/baobab-platform/baobab-dev/actions/runs/44728549298)
- [Security dependency audit](https://github.com/baobab-platform/baobab-dev/actions/runs/44728550204/job/136262077146)

## 2. Fix the installed dependencies

Ubuntu Resolute Updates publishes `linux-libc-dev=7.0.0-44.44` for both architectures. The package SHA-256 values in `config/versions.yaml` match the native DEBs and their package indexes. Both indexes match the SHA-256 entries in their respective InRelease files, verified against Canonical's published archive-key fingerprint. The shared image layer consumes the generated lock and verifies the native package identity.

The Buildx and Compose dependency graphs now select containerd v2.4.2, the upstream fix on the same minor line. Both graphs were regenerated using Go 1.27.4 and verified against the Go checksum database. The current Buildx and Compose upstream releases remain pinned. The build now checks that both binaries embed the version selected by their locked graph.

Local qualification used Trivy 0.73.0 and vulnerability DB timestamp `2026-11-20T07:09:47.681202359Z`. The four locked Go graphs and both rebuilt AMD64 plugins passed unfiltered HIGH/CRITICAL scans. The targeted Go test packages passed, both plugins reported the expected versions, and Compose parsed the smoke fixture. The signed Ubuntu package probe reproduced the 52 baseline advisories on both architectures and cleared 24 on the new version. Native image, Chromium, runtime and registry qualification still require GitHub runners.

## 3. Resolve the residual header findings

The [successful Ubuntu source run](https://github.com/baobab-platform/baobab-dev/actions/runs/44728549895) targeted 11 CVEs without exhausting its analysis budget. The applicability register still classifies all 298 records as under investigation. Its ancestry and patch correspondence apply to `7.0.0-43.43`.

Both `7.0.0-44.44` payload scans report the same 25 HIGH and three CRITICAL findings without a fixed version. The CRITICAL IDs are CVE-2026-99287, CVE-2026-99306 and CVE-2026-99310. Within each architecture, the set and SHA-256 of every shipped `/usr/include/*.h` path are identical between the two package versions. This supplies payload continuity for further review. The pinned Canonical OSV commit `88c00a77a1247172dd107f5dd3f24a1e1d1f57b2` provides records for all 28 residual IDs. None explicitly lists the newer source or binary version as affected, and none supplies a fixed version for Resolute. Those records predate publication of `7.0.0-44.44`. The newer package therefore carries 28 open release blockers. Ten overlap with the earlier package/source witnesses.

## 4. Verify review and release controls

At the baseline, the three unresolved outdated review threads concerned the retired legacy risk evaluator, unauthenticated release dispositions and Dockerfile healthchecks. The current code rejects invocation of the legacy evaluator, rejects residual release findings without protected authority and uses real shell executables in all four healthchecks. Reviewers still need to confirm these changes on the remediation head.

PR #92 is a separate draft for a historical, development-only inventory. ADR-DEV10-001 restricts scope by exact package version, severity, event and custody. The new package version and residual inventory require their own dispositions. Release-specific dispositions, if needed, require independent approval and a provisioned release trust mechanism.

GitHub reported `main` as unprotected with no effective rules. The active [Release Tag Protection ruleset](https://github.com/baobab-platform/baobab-dev/rules/20470719) returned `refs/tags/refs/tags/v*` in its include list and restricts creation, deletion and non-fast-forward updates. The release verifier requires creation, update and deletion restrictions covering `refs/tags/v*`. The live `dev10-release-promotion` environment passed the repository verifier for both `v1.5.2-rc.1` and `v1.5.2`, with typed numeric reviewers, self-review prevention and the two expected tag patterns. The administrator must restore the effective branch and tag controls before release.

## 5. Qualify the full image family

Run Foundation, Security and Publish on the same PR head after the dependency changes. Compare unfiltered scans and runtime evidence for all four profiles and both native architectures. Keep release eligibility closed while any required scan, native smoke test or review is outstanding.

## 6. Qualify the RC and promote its digests

The release administrator must verify effective main and tag controls and the protected `dev10-release-promotion` environment before any release tag. After qualification, verify the four signed OCI indexes, both child manifests per index, SBOMs, provenance and source commit. Require the GA references to resolve to the exact qualified RC digests. Complete issue #55 by running the required downstream lifecycle and authenticated Codespaces evidence against those digests.

## Reaudit of the f9e11645 qualification run

PR head `f9e11645af3b399a0b4659e06335f6ca5e052843` produced tested merge commit `6afdd6d6c912f63d771336915c1d639f3df57397`. All eight Publish legs passed native runtime qualification, and all four Security source graphs passed. Foundation and all eight Publish scans denied the same 28 `ubuntu` findings for `linux-libc-dev=7.0.0-44.44`. Each scan contains 25 HIGH and three CRITICAL, with no fixed-version signal, reported secret, containerd match or profile-specific addition. The evaluator denied the findings as outside the approved inventory. The [current inventory](dev10-pr74-current-inventory-20261120.tsv) is the deduplicated scan result for this revision. All nine archive hashes matched GitHub's digests. Fresh signature and index checks of Resolute Updates and Security report 7.0.0-44.44 and 7.0.0-43.43 respectively on both architectures. [Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/44747089686) · [Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/44747088528) · [Security](https://github.com/baobab-platform/baobab-dev/actions/runs/44747088721)

| Scan | GitHub artifact ID | ZIP SHA-256 |
| --- | ---: | --- |
| Foundation AMD64 | 14633254009 | `3d07d79035c2e4655dd9c7aaa7411628f30d44178c649b327ca337653a0f154e` |
| final AMD64 | 14634412447 | `5095f5f20bcc18f8a2747a052ba974b7abd8377986dbdd276643bbd66d403885` |
| final ARM64 | 14634681057 | `41078f6b9c38518a51d048417fdbb73d83f25cd08bf961d33030883d478a7589` |
| frontend AMD64 | 14633194405 | `c66478fdcec8c9cb66b28c5a404c9f4d687bb821689cd1cd5328e5590da98fbf` |
| frontend ARM64 | 14633738076 | `6baee6b088b942e069bd7300b96ff144892eb2280039e0b575c8d70c31818968` |
| frontend-e2e AMD64 | 14633284645 | `011c3380c84bf6d7a85f11d708774abe50f5b883454c89c22ffec3ac91e15cbd` |
| frontend-e2e ARM64 | 14634396837 | `a52a8a508b18fdcc7b67466dda127c89edde2cad124d49bc060123ceba84dc20` |
| infra AMD64 | 14633494491 | `68b7cd1328e0db19574fbc24addfb2ab462a2a3affe1964a267f707faa3a8587` |
| infra ARM64 | 14634027683 | `723c62104e3b862e2a61dd26344e67f7575163e0b339446f5619a98157b0b2f0` |

Ubuntu run [44747088486](https://github.com/baobab-platform/baobab-dev/actions/runs/44747088486) verified the `7.0.0-43.43` package on both architectures and its source tag at `f53b359683af7918c5436499948763cb726d5082`. The verified fix-history JSON digest is `3e7fc4d1fce2a6dcbc41869e60af4631531f1f0bca97e2579633697337761d02`. The workflow selected 11 CVEs and reported three exact ancestry matches, six unique stable patch-ID correspondences, 34 incomplete downstream comparisons and three fetch timeouts at candidate level. It deferred 1,412 candidate references outside the selected scope. All 298 CVE dispositions remain under investigation. Ten of the 28 current findings have historical source witnesses, and the other 18 are outside that witness set. The signed package payload comparison supports continuity of the shipped header bytes. Current-image applicability and release disposition still require evidence and independent review for `7.0.0-44.44`. The follow-up retries a timed-out exact candidate fetch once within the remaining analysis budget and preserves an explicit budget-exhausted result.

[PR #92](https://github.com/baobab-platform/baobab-dev/pull/92) at `431be65cb0887f2e84d813a3d50d4d0450f64f8d` changes only the historical decision file. Its base has the eight-finding schema and the old containerd graph. Security reports containerd `v2.4.1` in both graphs. The policy and onboarding checks reject the 12-finding record and its evidence digest field against the older contract. In a detached worktree, the exact proposed file passed Draft 2020-12 validation and the local repository test suite using #74's verifier and schema. The suite ran 594 tests with three skips. Its evidence digest matched #74's lock. The compatible controls need to land first. The draft's historical inventory is inapplicable to the current images, and tagged publication remains independently gated.

The legacy blanket eligibility path is retired, and the active development scan path checks exact scope and authenticated decision custody. All four Dockerfile healthchecks invoke Bash directly, and all eight native runs reached healthy. The release-only verifier rejects residual findings even when supplied a legacy free-text approval record. Independent release approval for residual findings still needs a protected trust mechanism if that route is pursued. Repository governance, final-head review and release qualification remain open.
