# Image Python dependency security


The final-image jobs in runs `40360334198` and `40360515417` failed on
CVE-2026-97687 / CVE-2026-97689 in urllib3 2.7.0, on both architectures.
`config/python-build-constraints.txt` now constrains image-tool dependency
resolution to urllib3 2.8.0 in both system pipx and Poetry's isolated environment.
The build checks dependency compatibility and reads back both installed versions;
a resolver conflict fails the build. This constraint is scoped to image creation
and does not override a consuming project's frozen dependency lock.

The original failed runs remain historical evidence. A source test or successful
install does not qualify the image: fresh final-head amd64/arm64 scans, all existing
required checks and developer-environment evidence remain required. No scan
exception or expiry was added or extended by this remediation. Do not release,
publish a new version or promote a consumer digest on the strength of this source
change. Roll back only to a previously qualified digest; an image with the original
finding is not a security rollback target.

## Frozen image verification

Run `config/resolve.sh --locked` for a reviewed source build. Manifest values
marked `latest` resolve from the committed lock; explicit manifest pins still
control their versions. The resolver re-fetches the exact selected version's
upstream asset checksums, regenerates the lock, and CI rejects any byte drift.
Missing versions, duplicate assignments, unresolved values and shell expressions
in the lock are refused before use. The lock is parsed as data, never sourced by
this verification path. This is a verification change, not a toolchain upgrade.

Run `config/resolve.sh` without arguments only to propose updates. The scheduled
update workflow retains that mode and opens reviewable changes. Full image scans
still determine security qualification; selecting an older committed version
never grants an exemption. Existing unsuppressed security and developer execution
obligations remain open until actually qualified.

## npm's embedded HTTP client

The 29 October unsuppressed scan finds CVE-2026-109869 in npm's private
`node_modules/undici` 6.29.0. The upstream v6.29.1 security release fixes it:
https://github.com/nodejs/undici/releases/tag/v6.29.1 . The image now installs
exactly 6.29.1 in the existing isolated security-patch scratch project, copies
that dependency into npm's private tree and reads back its installed version.
Node 24, npm, pnpm and project lock baselines are unchanged. Task/yq and Docker
plugin findings remain independently failing; this correction does not qualify
any image or Codespace.
# Vendored pip dependency remediation

The final-image scan at run 40912583068 still found urllib3 2.7.0 inside
pip 26.2.2, independently of the already-patched system and Poetry distributions.
The `patched-pip` builder verifies the upstream source archive and uses pip's
documented `vendoring sync` process to regenerate code, licensing and SBOM data
with urllib3 2.8.0. Build-tool dependencies are pinned with wheel hashes.
The result is explicitly versioned `26.2.2+baobab.1`; it is not represented as
an unmodified upstream release. Both the system installer and pipx's shared
installer receive the wheel and check the actual vendored import at build time.

An isolated local installation of the rebuilt wheel reports the patched
vendored version and successfully installs, checks and uninstalls a local wheel.
This is component testing only. Final image scans, multi-architecture builds,
Codespaces and the full DEV-10/DEV-14 acceptance remain required. Earlier failed
receipts are retained. All historical `.trivyignore` rules are retired as comments;
newly exposed findings remain blockers, without extensions or suppression.

