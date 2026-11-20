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
