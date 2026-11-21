# DEV-10 exact Ubuntu header applicability evidence

The [per-CVE binary applicability register](dev10-ubuntu-44.44-binary-applicability.json)
covers the 30 findings on `linux-libc-dev=7.0.0-44.44` observed at PR head
`6c285e49a37beebb4a9dcade2f1d3ff9351ad957`. Each row records the Linux CNA
record digest, upstream fix references, affected paths at the exact Ubuntu tag,
architecture-specific package observations and Canonical's Resolute `linux`
status. All 30 entries remain under investigation and block qualification.

Use the [development risk assessment](dev10-ubuntu-44.44-development-risk.md)
for the exposure conditions and evidence needed before a decision. The
[30-finding scan reconciliation](dev10-pr74-30-finding-scan-reconciliation-20261121.md)
records the exact finding identities and artifact links.

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
| Linux CNA CVE repository revision | `8867880806ac4a24d2bc865afab0eceadee47a24` |
| Canonical Ubuntu CVE tracker revision | `1d6aaa3351c3619b847340743716898c3fdf11e2` |

The Ubuntu archive signatures verified against fingerprint
`F6ECB3762474EDA9D21B7022871920D1991BC93C`. Both DEBs matched the signed
binary package entries and `config/versions.lock`. Package control fields
identify source `linux` at the binary version. The Canonical tag resolves
to the recorded commit and its packaging changelog identifies the same
release.

The signed Updates source index authenticated the exact 44.44 `.dsc`,
original source archive and Debian diff. The reconstructed source matched
the Ubuntu tag across all 51 unique CNA-named paths, with 49 present and
five absent path occurrences across the 30 records. This verifies the
source used for the per-CVE path checks. Independent verification of the tag
signer's key and whole-tree equivalence remain open. The
`signed_source_archive_comparison` field records the index and member hashes.

The refreshed signed Resolute archive offers `7.0.0-44.44` in Updates and
`7.0.0-43.43` in Security for both architectures. The refreshed index digests
and both exact package entries are in `supported_archive_snapshot` in the
register. Canonical's tracker records `needed` for the generic Resolute
`linux` source on all 30 rows. See the [package acquisition result](dev10-pr74-canonical-fixed-package-acquisition-20261121.md).

## Applicability observations

The AMD64 archive has 1,039 headers and the ARM64 archive has 1,010, plus
package documentation. Both architectures lack executable files and
ELF/static archive objects in the package. Across all 30 records, the CNA
affected paths yield zero direct exported UAPI path or literal include
basename matches in either native payload. Five records have a listed path
absent from the exact Ubuntu tag. Each of the three CRITICAL findings has an
implementation source file present there. Source path matches and absences
leave backport equivalence, generated headers, indirect ABI/UAPI, downstream
compilation and actual host exposure open.

| Additional finding | Ubuntu tag source evidence | Related exported ABI in both DEBs |
| --- | --- | --- |
| [CVE-2026-99312](https://ubuntu.com/security/CVE-2026-99312) | The exact tag contains `arch/x86/kvm/x86.c`. The mainline fix `c7c288d178cb` matches the pre-fix context in a read-only patch check. The reverse check fails. | `/usr/include/linux/kvm.h` |
| [CVE-2026-99317](https://ubuntu.com/security/CVE-2026-99317) | The tag contains `include/sound/hwdep.h` and `sound/core/hwdep.c`. The mainline fix `aee83c204f80` matches the pre-fix context. The reverse check fails. | `/usr/include/sound/asound.h` |

Those checks confirm the upstream patch context in the signed package
source files and the tag. Semantic backport analysis, host reachability and
compensating controls remain open. The register retains the full source
blob IDs and patch SHA-256 values.

## Native payload readback at `6c285e49`

All eight native Publish manifests matched the installed control fields,
complete path sets and file hashes of the corresponding architecture DEB.
The six daemon-scanned legs match the Docker config digest. The two
`final` legs use the Docker archive SHA-256 to bind the scan and subsequent
runtime load. The register records both the Trivy image ID and the Docker
runtime image ID for those legs. The [Publish run](https://github.com/baobab-platform/baobab-dev/actions/runs/44877263421)
retains the per-image artifacts and the register records their verified digests.

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
