# DEV-10 exact Ubuntu header applicability evidence

**Current package-remediation decision (2026-11-21):** no newer Canonical-supported fixed binary was established for the 30-finding scan inventory. The exact 44.44 amd64/arm64 pins are intentionally unchanged and all 30 findings remain blocking. See [PR #74 kernel package remediation investigation](dev10-pr74-kernel-package-remediation-20261121.md). The 28-record applicability register below is not expanded by inference; CVE-2026-99312 and CVE-2026-99317 remain unassessed.

The [per-CVE binary applicability register](dev10-ubuntu-44.44-binary-applicability.json) contains 28 detailed records on `linux-libc-dev=7.0.0-44.44`; it is not a complete representation of the current scan inventory. The disposition count is 28 unresolved, zero confirmed affected, zero confirmed not affected and zero confirmed fixed or backported for this binary. Each record retains the CNA record digest, upstream fix references, Ubuntu source blob IDs or absences, and the architecture-specific matches. Upstream fix references identify evidence to review. The audit does not decide applicability from scanner severity or path presence alone.

The [development risk assessment](dev10-ubuntu-44.44-development-risk.md) records the proposed treatment, exposure and outstanding controls for each finding. The current PR-head raw scans contain 30 unique findings; CVE-2026-99312 and CVE-2026-99317 are absent from this 28-record register and remain unassessed and blocking. See the [30-finding scan reconciliation](dev10-pr74-30-finding-scan-reconciliation-20261121.md) for immutable artifact references and exact package/version inventory.

## Package and source evidence

| Input | Verified identity |
| --- | --- |
| AMD64 DEB | `b1bd69037483894be260e934503e8c99debebb6d622e3d5010e79fea4108ee43` |
| ARM64 DEB | `4c9e3d5345e22876a4c2b3631dc2011c8e79228e6cd0d8020ad01663e31e306e` |
| Resolute Updates InRelease | `8a6ce0b1c032e5c2f7263c05b354384933c64f5ad26f492c5a35d3e407f17aca` |
| Resolute Updates AMD64 Packages.xz | `514398f0a5ae6114af0772bdee72ab861594387fbddb64df9092bc2b721b5ac3` |
| Resolute Updates ARM64 Packages.xz | `05b44b72001edf68d31e3aa0f9bbf02a7e0f5ab0104a12d49214f47ea2d9fbc3` |
| Resolute Updates source .dsc hash in signed index | `5e117ef9142bb272825dc10f0abab822d1d0cfb744de91d062ddbab725851986` |
| Canonical Git tag commit | `Ubuntu-7.0.0-44.44` at `70d93713221b617bdb0f55289ffb52b99f2038cf` |
| Linux CNA CVE repository revision | `144020080a9c41a4da6d92280c849c9b476a58f1` |

The Ubuntu archive signatures verified against fingerprint `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Both binary indexes and the source index matched their signed metadata. Both DEBs matched the signed package entries and `config/versions.lock`. Package control fields identify source `linux` at the binary version. The Canonical tag resolves to the recorded commit and its packaging changelog identifies the same release. Independent verification of the tag signer's key and a comparison of the source archive against the Git tree remain open.

Resolute Updates offered `7.0.0-44.44` on both architectures. Resolute Security offered `7.0.0-43.43`. The checked pockets and scan inventory offered no newer supported package or fixed version for these findings.

## Applicability observations

The AMD64 archive has 1,039 headers and the ARM64 archive has 1,010. Both also have package documentation. The archives contain no executable files or ELF/static archive objects. Across the 28 CVEs represented in this applicability register, the authoritative affected-path lists yield no direct exported UAPI path or literal include basename match in either archive. This source-path analysis does not cover the two additional scan findings CVE-2026-99312 and CVE-2026-99317. Five CVEs have at least one listed affected file absent from the exact Ubuntu tag. The three CRITICAL findings all have a listed implementation source file present at the tag. Those observations leave Ubuntu backport equivalence, generated headers, indirect ABI/UAPI and downstream compilation exposure open. The 28 findings remain blocking pending exact-source review and a supported remediation or independently reviewed applicability outcome.

## CI evidence before native payload capture

Foundation run [44765028532](https://github.com/baobab-platform/baobab-dev/actions/runs/44765028532) and Publish run [44765026562](https://github.com/baobab-platform/baobab-dev/actions/runs/44765026562) scanned merge checkout `feb30ad2d8a6f2aad444126faa7bd36c6a0ab69c`. All nine verified scan archives contained the same 25 HIGH and three CRITICAL results for the locked version. All eight native archives confirmed the version and architecture in a digest-verified APT inventory and reported a passed runtime. Those native archives lack installed file hashes. The updated qualification step retains per-image file and package metadata manifests in each native artifact and binds their hashes to the checked-out source, lock and image metadata. The audit's optional native input checks all eight installed header sets against the exact architecture DEB.

| Artifact | GitHub artifact ID | Archive SHA-256 |
| --- | ---: | --- |
| dev10-foundation-container-risk | 14644147503 | `8d2a76ba6068841cade2169a570105fbfabe967acf17a3540f7ced41a9d0e904` |
| native-image-final-amd64 | 14645327246 | `65c6e0033af0ee8dbfa9311f716cac1b03b9cade2daed63bcea4a1d714a886d8` |
| native-image-final-arm64 | 14645671964 | `1aa4d2ed28a6ce7f1bfe0fcce9d87c7b820dcb545da383acb40898881b34d69d` |
| native-image-frontend-amd64 | 14643908045 | `8552189ae81868fdeacb29297668579a77a16b9cbdc30082abae73ddbd9b6d8e` |
| native-image-frontend-arm64 | 14645791003 | `3daa46363f4d08be60dada80eaeff54e97174cf32852c4fe7d46bc6d7ae64192` |
| native-image-frontend-e2e-amd64 | 14646105908 | `f591728358d72449b23e8475a6f8c12ba4543366916528356a44da92e666d0b4` |
| native-image-frontend-e2e-arm64 | 14644457850 | `3f62c19c6092e0571ca351982ddbadd49941ed31b1d48b7d8c867eaa1ca50b52` |
| native-image-infra-amd64 | 14646086860 | `dbd06399c82d1d9f89ef41162084aac56a11def32c30c37494262d751b4fcc70` |
| native-image-infra-arm64 | 14646121422 | `0fd7ec69163fc68a0a3f07f38a94fba349f7d341ae9450cbb6003303b2fc3cdc` |
| trivy-final-amd64 | 14646006727 | `775bbb78568dcf75e041a6f647ff723f469f61ec901196b84ee9e35146d7124f` |
| trivy-final-arm64 | 14645776628 | `842b4edff7987ae1611c9b5a865664317ced6e3e1fb79ac30a84f4afba8eb722` |
| trivy-frontend-amd64 | 14645851456 | `0c212b275309f0ef7c7d5a9cf558700b9918b5e79b030993f8f5e2359710f181` |
| trivy-frontend-arm64 | 14645865565 | `a7ad40fbe2c9f7427f082719e7bff0336177507b0adb32bc02cd9a162fa1931f` |
| trivy-frontend-e2e-amd64 | 14645261480 | `eb0a35e2a00594ea41dd534e4393230ae53e0bc3d2c67467747f103f37ad4ad8` |
| trivy-frontend-e2e-arm64 | 14644442877 | `dcb694b9ee09757af2085c366ae72a47a1c55bb1eca23e572e7d7ba64a5bc0ab` |
| trivy-infra-amd64 | 14645802310 | `203f088ad4c16968d0e3ecadb4f3e43fe74eda62ea89756b3d48284b742ac8b5` |
| trivy-infra-arm64 | 14646705858 | `f7d4aee97a5c4e5e99cd1e7543371e9eb12bd420bd3d167104fb1c6517b034d4` |
