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

## 30 October: unrestricted image scan and pnpm's separate client

Heads `0cfb74e2020e430b9252b480a294ff90efb26b3e` (#48) and
`000c037ceff34c7ee96b6f33194085dbfdebfaff` (#50) remove Publish's
whole-path exclusions and unfixed-vulnerability filtering. Foundation also
explicitly disables unfixed filtering. Historical filtered passes do not
qualify these new candidates. The installed pip-audit invocation is corrected
to `--path` without the incompatible requirement-only `--disable-pip` flag.
The workspace test harness now executes the real Node membership checker and
preserves its denial status instead of overwriting it with a successful shell
command. DEV-10 run 41012858820 passes both source and published-image jobs.

The unrestricted #50 frontend scans (run 41012859493, jobs 123922672290 and
123922672323) expose a second undici copy inside the Corepack pnpm cache:
`pnpm/11.24.0/dist/node_modules/undici`, version 6.28.0. Its four HIGH findings
are CVE-2026-109383, CVE-2026-109869, CVE-2026-19534 and CVE-2026-87018.
The Node build stage now replaces that actual library with the same 6.29.1
code already installed for npm, checks the original version/layout before
replacement, imports the patched request API and verifies pnpm's adopted
11.24.0 version. It does not change project package-manager declarations or
project lockfiles. Local component testing exercises a real HTTP request and
frozen offline workspace installation; image qualification remains separate.

Both scans also report 295 HIGH/CRITICAL findings against Ubuntu's
`linux-libc-dev` 7.0.0-42.42, with no fixed version listed. These are source
package/kernel advisory matches; this observation is not proof that an
exploitable kernel runs inside the image. However, no applicability waiver,
VEX exclusion or scanner suppression has been applied. Ubuntu's current
[CVE-2026-89530](https://ubuntu.com/security/CVE-2026-89530) and
[CVE-2026-98863](https://ubuntu.com/security/CVE-2026-98863) records still mark
26.04 vulnerable/work in progress. A qualified distribution fix or separately
reviewed applicability resolution remains required. Removing native compiler
headers merely to reduce scanner output would break the developer contract.
This is an open development-security dependency, not a protected-release hold
and not permission to merge or declare DEV-10/DEV-14 complete.

After the CLI correction, the full ARM64 build (run 41012859493, job
123922672295) reaches the installed distro-Python audit and fails on 39
advisory entries across cryptography, httplib2, jaraco-context, oauthlib and
PyJWT. These are genuine scanner observations, not an accepted applicability
assessment of distro backports. The base image no longer installs
`software-properties-common` unconditionally: it is needed only to configure
the optional deadsnakes fallback, not by any supported runtime command. The
fallback installs it temporarily and removes it with its orphan dependencies
after explicitly installing the selected Python interpreter/dev/venv packages.
Ubuntu's native Python path never installs that helper dependency tree. Both
native compiler support and installed-distribution auditing remain enabled.
Fresh builds must establish whether all five reported packages are eliminated
or whether another dependency still requires remediation; no clean result is
inferred from this source change.

## 30 October: evidence-preserving scan qualification follow-up

The final-head scans in #48 run `41013986362` failed on all eight target/
architecture combinations. Foundation run `41013987217` failed its image scan
and aggregate result; #50 inherited the same image failure. The installed
`linux-libc-dev` release is `7.0.0-42.42` on amd64 and arm64. Trivy reports
295 HIGH/CRITICAL advisory matches (283 HIGH, 12 CRITICAL), all associated
with that package in the inspected scans. No available fix was recorded in
those scan tables. These are **blocking findings**, not an approved exception.

The dependency chain is the common base stage's `build-essential` installation,
which brings in `libc6-dev` and `linux-libc-dev` for C compilation and Linux
user-space API headers. The image now records the actual package/source versions
and `dpkg-query -L` installed paths under
`/usr/local/share/baobab/security/` and runs a real compiler/UAPI smoke check
during *both* architecture builds. This proves compiler/header usability, not
the safety of the host's kernel or the absence of a vulnerable kernel implementation.
An ordinary development container does not ship or boot the host kernel; kernel
advisory matching against its UAPI header package does not alone demonstrate
that affected kernel implementation code can execute inside the image. Nor does
that observation clear the advisory. Exposure through a host kernel or kernel
interfaces requires independent deployment-specific analysis.

The Publish workflow retains the original strict Trivy HIGH/CRITICAL policy,
empty ignore rules, secret scanning and unrestricted OS/library scope. It now
writes a **full vulnerability JSON without secret-match payloads**, including\nadvisory source, installed version,
available fix and package path metadata when provided, followed by a normalized
per-finding JSON report. The original Trivy JSON stays in the ephemeral runner's temporary directory:\nonly secret-redacted vulnerability JSON and the normalized finding inventory are\nuploaded as immutable per-job CI artifacts
even when the scanner exits nonzero. Missing or malformed JSON is itself a
failed gate. Nothing changes Foundation's separate blocking scan.

Vendor status must be verified against Ubuntu's 26.04 security tracker for
**each applicable CVE**, not just representative CVEs. A 26.04 proposed kernel
package must not be treated as a supported security update. Until a supported
fixed version is shipped and the *unrestricted* scans pass, or an independently
approved time-bounded applicability decision is recorded outside this PR, both
PRs remain HELD. No waiver, VEX `not_affected`, scan filtering, package
removal or release activation is introduced here. Existing image consumers must
stay on independently qualified digests; rollback requires a known-good digest
and separate consumer verification.
