# DEV-10 shared image composition assessment

The checked package and base alternatives leave unresolved findings. The
current development image remains gated on remediation or a separately
authorized, exact-scope decision. The shared delivery model uses one central
toolchain and the same qualification process across domain engines.
[Accountable owner's delivery direction](https://github.com/baobab-platform/baobab-dev/pull/74#issuecomment-7061063592)

## Verified baseline

PR #74 head `331f98ef2fc3a8bb74b219aa341a829dc766c91a` and its tested merge
`1a58a74370b69dd234451c99bfe02253587b95e8` produced nine matching scan
inventories. All 30 findings are `affected`, with 27 HIGH and three CRITICAL.
The normalized finding hash is `6f95364a4c221519d29e6a95458e04918ee2495b4ae16dc6b1f272e8b84663f3`.
[Verified scan evidence](dev10-pr74-331f98e-scan-evidence.json)

The common `base` stage starts from Ubuntu 26.04 at OCI index
`sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db`.
It verifies and installs `linux-libc-dev=7.0.0-44.44` before the four profiles
diverge. The signed Updates indexes agree with both locked package hashes.
[Dockerfile](../../.devcontainer/docker/Dockerfile) · [Version lock](../../config/versions.lock)

| Architecture | Locked `linux-libc-dev` 44.44 DEB SHA-256 |
| --- | --- |
| `amd64` | `b1bd69037483894be260e934503e8c99debebb6d622e3d5010e79fea4108ee43` |
| `arm64` | `4c9e3d5345e22876a4c2b3631dc2011c8e79228e6cd0d8020ad01663e31e306e` |

The native compiler check builds and runs a C program using glibc and Linux
UAPI headers. The signed `libc6-dev` entries for both architectures require
`linux-libc-dev`. Refreshing the Ubuntu OCI digest alone leaves the explicit
header pin in effect. Removing the headers would break the verified native
build dependency chain. [Native compiler check](../../.devcontainer/docker/Dockerfile)

## Supported package alternatives checked

I verified the Ubuntu release, Updates and Security `main` indexes on both
architectures against the signed archive metadata. Stonking publishes SHA-512
index and header package digests. Canonical tracker commit
`1d6aaa3351c3619b847340743716898c3fdf11e2` was still HEAD at the time of the
check. The counts below describe vendor kernel **source** status.
[Ubuntu archive](https://archive.ubuntu.com/ubuntu/dists/) ·
[Ubuntu Ports](https://ports.ubuntu.com/ubuntu-ports/dists/) ·
[Pinned Canonical tracker](https://git.launchpad.net/ubuntu-cve-tracker/tree/?id=1d6aaa3351c3619b847340743716898c3fdf11e2)

| Base | Published `linux-libc-dev` checked | Finding evidence |
| --- | --- | --- |
| Ubuntu 26.04 LTS Resolute | Updates `7.0.0-44.44`, Security `7.0.0-43.43` on both architectures | 30 fixes still needed, including all three CRITICAL findings. |
| Ubuntu 24.04 LTS Noble | Updates `6.8.0-151.151`, Security `6.8.0-149.149` on both architectures | 26 fixes still needed, including all three CRITICAL findings. Four source entries are `not-affected`. |
| Ubuntu 26.10 Stonking | Updates `7.3.0-11.12`, Security `7.3.0-10.10` on both architectures | 21 fixes still needed, including all three CRITICAL findings. Nine source entries are `not-affected`. |
| Debian 13 Trixie | Security `6.12.117-1`, architecture `all` | The Debian tracker lists the source as fixed for 24 findings, including all three CRITICAL. Six HIGH findings remain vulnerable. |

The six Debian Security tracker holds are CVE-2026-98376, CVE-2026-98420,
CVE-2026-99272, CVE-2026-99275, CVE-2026-99312 and CVE-2026-99317.
Both signed Trixie Security architecture indexes identify `6.12.117-1` as
the newest entry and point to the same architecture-independent DEB.
[Signed Debian Security archive](https://deb.debian.org/debian-security/dists/trixie-security/InRelease) ·
[Debian header package](https://packages.debian.org/trixie/linux-libc-dev) ·
[Debian `libc6-dev` dependencies](https://packages.debian.org/trixie/libc6-dev) ·
[Debian `linux` tracker](https://security-tracker.debian.org/tracker/source-package/linux)

The current lock selects Python 3.14.10, Node 26.13.1, pnpm 12.21.0, a
PostgreSQL 17.12 client built for Resolute, Temurin 21 and a Resolute Docker
CLI package. Another base would need vendor-supported builds with freshly
verified architecture-specific locks. Ubuntu 24.04 lacks Python 3.14 in the
checked `main` indexes. The current SHA-256 APT verifier would also need an
explicit SHA-512 path for the checked Stonking package. PostgreSQL and
Docker use repository suites selected by the runtime OS codename.
[Version lock](../../config/versions.lock) · [Locked APT verifier](../../scripts/locked-apt.sh)

## Qualification disposition

The technical register contains current 44.44 records for all 30 findings.
The two newly observed findings have signed-source and header observations
and still need a defensible risk disposition. The historical 43.43 witness
column is scoped to its older inventory.
[Per-CVE technical records](dev10-ubuntu-44.44-binary-applicability.md) ·
[Inventory](dev10-pr74-current-inventory-20261120.tsv)

The investigated alternatives leave confirmed source-level holds or runtime
qualification work. The existing central pins remain the test baseline.
A replacement must first have defensible package and finding evidence, then
pass Foundation, native builds and unfiltered security scans on all eight
profile and architecture combinations, and locked consumer onboarding.
Any eventual publication uses the existing protected release workflow.
