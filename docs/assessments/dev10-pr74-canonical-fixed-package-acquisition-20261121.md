# PR #74 — Canonical fixed-package acquisition result (2026-11-21)

## Outcome

**The signed Resolute archive still offers `7.0.0-44.44` as its newest
supported `linux-libc-dev` binary on amd64 and arm64. No supported fixed
package was established for the 30-finding inventory.**

The refreshed audit used the official signed Release, Updates and Security
indexes and compared both 44.44 DEB digests with the signed package entries
and the repository lock. The earlier public catalogue and PPA observations
below remain part of the acquisition history.

## Verified official archive

| Suite | Signed metadata date (UTC) | amd64 | arm64 |
| --- | --- | --- | --- |
| Resolute | 23 April 2026 17:07:15 | `7.0.0-14.14` | `7.0.0-14.14` |
| Resolute Updates | 21 November 2026 06:03:25 | `7.0.0-44.44` | `7.0.0-44.44` |
| Resolute Security | 21 November 2026 03:47:57 | `7.0.0-43.43` | `7.0.0-43.43` |

The archive key fingerprint was `F6ECB3762474EDA9D21B7022871920D1991BC93C`.
For each architecture and suite, the Packages index bytes matched the
SHA-256 in the signed `InRelease`. The [applicability register](dev10-ubuntu-44.44-binary-applicability.json)
records all six checks and the full binary package fields under
`supported_archive_snapshot`.

## Earlier public package catalogue

The earlier public Ubuntu package search returned the following entries.

| Ubuntu suite | Version | amd64 | arm64 |
|---|---:|---:|---:|
| Resolute (26.04) | 7.0.0-42.42 [security] | Yes | Yes |
| Resolute Updates | 7.0.0-43.43 | Yes | Yes |
| Stonking (26.10) | 7.3.0-10.10 [security] | Yes | Yes |
| Stonking Updates | 7.3.0-10.10 | Yes | Yes |

Source: https://packages.ubuntu.com/en/linux-libc-dev

The signed indexes above provide the current archive publication evidence.

## Proposed PPA candidates are not accepted as a remediation

The Canonical Kernel Team proposed PPA directory exposes `linux-libc-dev` binaries including:
- `7.0.0-44.44` for amd64 and arm64 (dated 2026-11-09 in the directory listing).
- `7.3.0-11.12` for amd64 and arm64 (dated 2026-11-10 in the directory listing).

Source: https://ppa.launchpad.net/canonical-kernel-team/proposed/ubuntu/pool/main/l/linux/

These directory entries establish only that files are present in that PPA's pool. They do not by themselves establish:
1. publication in the official Resolute release, updates, or security pocket;
2. a supported Resolute publication target for the 7.3 package;
3. signed repository metadata and package-index inclusion for the intended suite;
4. the source package and build provenance associated with each binary;
5. that the binary contains the fixes for the current CVE inventory.

No PPA binary was copied into the repository lock or treated as a production candidate.

## CVE fix-status gate

At Canonical tracker revision `1d6aaa3351c3619b847340743716898c3fdf11e2`, all
30 CVEs have generic Resolute `linux` status `needed`. The refreshed public
advisory pages render both of the newly assessed CVEs as Vulnerable.

| CVE | Canonical Resolute status | Evidence consequence |
|---|---|---|
| CVE-2026-99312 | Vulnerable | The KVM INIT/MMU-context fix is not established in the Resolute package |
| CVE-2026-99317 | Vulnerable | The ALSA hwdep fix remains needed in the generic Resolute source |
| CVE-2026-99287 | Vulnerable | Critical xen-netback issue remains open |

Sources:
- https://ubuntu.com/security/CVE-2026-99312
- https://ubuntu.com/security/CVE-2026-99317
- https://ubuntu.com/security/CVE-2026-99287

The exact Ubuntu source tag matches the forward patch context for both
upstream fixes. The package applicability record retains the source blobs,
patch digests and checks. The PPA version `7.3.0-11.12` still lacks a supported
Resolute publication and exact-scope fix evidence. [Source checks](dev10-ubuntu-44.44-binary-applicability.md)

## Exact current lock — unchanged

The PR lock remains `linux-libc-dev=7.0.0-44.44`:
- amd64 SHA-256: `b1bd69037483894be260e934503e8c99debebb6d622e3d5010e79fea4108ee43`
- arm64 SHA-256: `4c9e3d5345e22876a4c2b3631dc2011c8e79228e6cd0d8020ad01663e31e306e`

These are the existing locked payload digests, not evidence that this version fixes the CVEs. No package was downloaded, substituted, or represented as remediated in this task.

## Requirements before accepting a candidate

A future candidate must satisfy all of the following before any lock change:
1. Canonical confirms the package is a supported publication for Ubuntu Resolute and identifies the target pocket.
2. The signed InRelease signature and both amd64/arm64 Packages indexes are retained and verified against the correct Canonical archive key.
3. The exact package records identify the same source package/version and architecture-specific filenames, sizes and SHA-256 values.
4. Both DEBs are downloaded and their hashes match the signed indexes; control metadata and package contents are inspected.
5. Canonical's CVE tracker / security notice or authoritative source-package changelog establishes the fixes for the relevant CVEs, with exact source commit/backport correspondence verified.
6. The new package is installed in native amd64 and arm64 builds; all eight profile/architecture scans are rerun and raw reports plus native package/file manifests are retained.
7. The resulting finding set is reconciled exactly. Any residual findings remain blocking pending their own defensible dispositions and the required independent approval.

## Decision

| Criterion | Result |
|---|---|
| Canonical public Resolute package version checked | Pass |
| Higher-version Canonical-team PPA candidates identified | Pass |
| Candidate shown to be a supported fixed Resolute package | **No** |
| Both architecture payloads acquired and verified as a fixed candidate | **No — intentionally not attempted as remediation** |
| Version lock changed | No |
| Current 30-finding block preserved | **Yes** |
| Security approval or release authorization | None |

This result does not clear any Trivy finding, authorize the proposed PPA, grant risk acceptance, or qualify PR #74 for merge/release. It identifies the evidence Canonical must publish or confirm before a fixed package can be safely acquired.
