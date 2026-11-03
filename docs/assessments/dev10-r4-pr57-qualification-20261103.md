# DEV-10 R4 — PR #57 qualification and v1.5.0 release gate

**Audit:** 2026-11-03. **Governing baseline:** EA v2.3 / EA-DEV DEV-10 and DEV-14; merged baobab-dev #48/#50; security issues #52/#54/#55. **Status:** engineering candidate, NOT release-qualified. This record is deliberately updated on source branch; it is not a retrospective claim that image tests or Codespaces already passed.

## Candidate pins and admission requirements

| Component | Proposed image contract | Admission scope |
| --- | --- | --- |
| Ubuntu | 26.04 | no base distribution change in this gate |
| Python | 3.14.10 (PSF tarball with SHA-256) | full AMD64/ARM64 readback; Pulse/Haystack native consumers |
| Node | 26.13.0 | exact binary readback; Medusa, CP and three estates must qualify |
| pnpm | 12.16.1 native binary | publisher SHA-256 per arch, frozen consumer lock, no Corepack substitution |
| Corepack | 0.36.0 | separate installation; Yarn only; no invisible pnpm download |
| Java | Temurin 21 | iDempiere v13 OSGi and Subscriptions Java 21 with PostgreSQL 17 |
| PostgreSQL | client 17 | server migration/recovery remains DEV-12, not implied |
| Playwright | 1.64.1 | browser binaries and every consumer's test runner must match |
| Maven | 3.10.0 stable GA (candidate manifest/lock) | Apache SHA-512 verified; current-head image readback and independent ERP/Subscriptions JDK21/PG17 consumers still required; Maven 4 RC prohibited as default |

The `config/versions.yaml` file is the policy source, `config/versions.lock` is the reproducible resolution, and actual installed image readback is separate evidence. No changing owner packageManager pins without a native test. See `dev10-r4-all-toolchains-maven4-review-20261102.md`.

## CI evidence and corrections

Initial candidate SHA `ac187a4e40ce895ab53d0036a953730a92874a3b`, workflow run
[41557252699](https://github.com/baobab-platform/baobab-dev/actions/runs/41557252699):

- Passed: DEV-10 locked onboarding, DEV-14 developer doctor, source Security, Foundation, documentation, frozen source lock. Infra AMD64/ARM64 and frontend ARM64, frontend-e2e ARM64 image legs also passed.
- Failed: frontend AMD64 and frontend-e2e AMD64 rejected an invalid handwritten pnpm 12 frozen lockfile fixture. An initial attempt to generate the lock entirely offline was also invalid because pnpm 12 requires cold package-manager bootstrap metadata; the corrected two-stage network-seeding/offline-frozen qualification is documented below and requires fresh CI proof.
- Failed: full AMD64/ARM64 Trivy found **296** HIGH/CRITICAL issues, one additional HIGH beyond the narrowly accepted **295**. Trivy's own independently exported result identified `CVE-2025-47273` (setuptools 70.3.0, fixed >=78.1.1) inside the remaining `/usr/local/lib/python3.14/dist-packages/pip-26.3` installation. The /opt interpreter and pipx installer were separately patched, but the old distro interpreter was not. We now install the audited, checksum-built, source-revendored pip wheel in this third interpreter as well; leave Trivy strict and verify the final image.
- CI remains authoritative for all code corrections. Neither corrected source nor a locally green command is multiarch/consumer acceptance.

## 3 November 2026 — pnpm 12 bootstrap failure and remedial qualification

Final-head candidate `7d7453639ed69ca3a40f30b6eb1835873dfe5f60`,
[Actions run 41575370514](https://github.com/baobab-platform/baobab-dev/actions/runs/41575370514):
all source workflows (Foundation, Security, documentation, DEV-10, DEV-14) passed;
the eight-image matrix built and scanned six legs successfully, but
`frontend/linux-amd64` and `frontend-e2e/linux-amd64` failed specifically at
the noninteractive package-manager fixture. Error:
`ERR_PNPM_BAD_CONFIG_DEP` → `Failed to resolve config dependency pnpm@12.16.1`
from an empty `~/.cache/pnpm/v12/metadata/...` mirror. The fixture required
a newly generated pnpm 12 *boot document* to resolve on a disconnected
network and with no pre-existing registry metadata. This is a test-design
error, not the pnpm 12 native executable or Corepack failing.

Remediation on PR #57:
1. Maintain SHA-256 verified native pnpm 12.16.1 and exact `versions.yaml` /
   `versions.lock` pins; no version bump, skip, risk waiver or scanner change.
2. Set supported pnpm 12 `pnpm_config_pm_on_fail=error` in the image to reject
   mismatched `packageManager` versions, rather than auto-downloading a
   second package-manager executable. Corepack remains limited to Yarn.
3. Replace impossible network-disconnected cold lock generation with
   `scripts/qualify-pnpm-provisioning.sh`: first a bounded normal install
   with registry access, no TTY and real packageManager pin, with pnpm cache
   and store mounted from disposable CI scratch; then a second container
   with `--network none`, `--frozen-lockfile --offline`, equal lock SHA-256;
   negative tests refuse a wrong pnpm version and fabricated lock.
4. Rerun final-head CI and native consumer/Codespaces checks. CI success
   **cannot** imply a cold offline first-ever lock resolution or published
   image. Remaining qualification and protected release boundary unchanged.

pnpm documentation: [pmOnFail setting](https://pnpm.io/settings),
[packageManager boot document](https://pnpm.io/package_json),
[offline install](https://pnpm.io/cli/install).

## Gate matrix

| Gate | Required proof | Current decision |
| --- | --- | --- |
| Syntax / frozen source | manifest lock, workflow parsing, verification scripts and tests | CI rerun required |
| Native image matrix | full, frontend, frontend-e2e, infra on AMD64/ARM64 | rerun required |
| Security | raw Trivy, no new high/critical CVEs, secret scanning | strict gate; remediated source not yet certified |
| Real consumers | Node26/pnpm12/Playwright; Python Pulse; Java ERP and Subscriptions; CP, Payments and estate packages | outstanding |
| Codespaces | signed-in human-owned private package access; post-create; non-root; ports; independent teardown | outstanding |
| Release | immutable digest, SBOM, provenance, Cosign, independent release-specific security determination or vendor remediation | **BLOCKED** |

## Security treatment: hard release boundary

The documented **295** `linux-libc-dev=7.0.0-42.42` CVEs have a narrow, expiring **development-only** acceptance for untagged source PR #57/main until **2026-11-13T00:00:00Z**. It is not a `not_affected` VEX, a vendor fix, an approval for extra CVEs, or an exception for a release tag.

The requested owner sequence is **candidate review → v1.5.0-rc.1 → v1.5.0 → GHCR publish**.
A policy correction in PR #57 retains `v*.*.*` and `v*.*.*-*`
pushes as CI events but derives `is_release=true` **only from stable
tags without a prerelease suffix**. Therefore `v1.5.0-rc.1` runs
strict build/security validation without exporting a digest, signing it,
or creating a GHCR/GitHub Release. `v1.5.0` retains the actual publish
and attestation path only once the independent security gate is satisfied.
Neither RC nor GA may bypass strict release scanning. A separate attributable, per-CVE/digest release decision or vendor remediation is required, followed by a clean tag-time scan and supply-chain provenance checks. Release tagging remains with the owner.

## Rollback and follow-up

- Retain the existing published 1.4.4 image/digest and consumer pins as rollback authority until v1.5.0 is qualified.
- Prefer remediation over expanding security waivers. Do not label failed/unknown external integrations as PASS.
- Preserve PR #57 open unless final-head checks and the required upgrade acceptance evidence are satisfactory.
- Update this register with exact workflow run IDs, asset digests, current-head SHAs, failures/repairs, independent attestations and responsible reviewer before declaring DEV-10 R4 closed.

## 3 November 2026 — CI run 41588044957, fixture ownership correction

At source head `27aef158bc6590dad67ab2364719f051cb02051a`,
[workflow 41588044957](https://github.com/baobab-platform/baobab-dev/actions/runs/41588044957)
reported a new `frontend/linux-amd64` failure in the pnpm provisioning step.
The image's `baobab-verify` was HEALTHY and the pnpm 12.16.1 cold install
completed, but the host runner then could not read `pnpm-lock.yaml`:
`sha256sum: .../project/pnpm-lock.yaml: Permission denied`. The image
executes as UID 1000, different from the runner, and pnpm creates private
cache/store and lock files *after* the script's initial chmod. The EXIT
cleanup also emitted permission errors. This is a host/container test-fixture
ownership defect, not evidence of a pnpm failure or a security exception.

The candidate branch now restores host access to disposable scratch contents
through a short, network-disabled root helper **inside the same throwaway
container image** after each test invocation and before cleanup. It does not
change the production image user, installed packages, pnpm pins, Trivy output,
or the exact 295-CVE development-only decision. The helper and the remaining
negative cases require a **fresh final-head CI run**. Other image matrix legs
that were still running at inspection are not counted as PASS. No hosted
Codespaces, consumer adoption, release approval or image publication is claimed.

## 3 November 2026 — run 41591284867, Maven bundled Guava guard

At head `01ba49f8f8f73ca7cdeb672b84e7e1ea761a0a1b`, [publish workflow 41591284867](https://github.com/baobab-platform/baobab-dev/actions/runs/41591284867) completed **FAILURE**: `final/linux-amd64` and `final/linux-arm64` exited during the Maven installation layer. The pinned Maven archive SHA512 verified, but the Dockerfile still required Maven 3.9.16's `guava-33.6.0-jre.jar` filename after the manifest advanced to Maven 3.10.0. The guard was therefore stale. Six other image/architecture legs passed, as did the frozen-lockfile job; no complete eight-leg success is claimed. Foundation, Security, documentation, DEV-10 source/published-image, and DEV-14 doctor succeeded at that previous head.

Repair commit `539f01c4c2bc54962237008cf3e91d77333641a1` preserves the exactly-one-bundled-Guava fail-closed guard, replaces the upstream Guava jar irrespective of its old filename with checksum-pinned 33.7.2-jre, and checks the single resulting jar. It does **not** change `config/versions.yaml`, `versions.lock`, the raw Trivy scanner, or the 295-CVE DEV-only exception. The corrected final-head eight-leg build, scanner results and release safety remain **UNVERIFIED** until new CI completes. Human Codespaces and native consumers remain **NOT RUN/NOT VERIFIED**. PR remains HELD; no tags or GHCR publishing authorized.

## 3 November 2026 — eight-leg successful candidate verification and follow-up hardening

At candidate head `ce196a0219f27ef352e87587fc933673446d22cb`,
[Publish run 41601842744](https://github.com/baobab-platform/baobab-dev/actions/runs/41601842744)
completed successfully: `final`, `frontend`, `frontend-e2e` and
`infra` all passed on **both** `linux/amd64` and `linux/arm64`.
Foundation, Security, DEV-10 source/published-image, DEV-14 doctor, and
documentation checks on that head were also green. The full-image logs
show Python **3.14.10** and Maven **3.10.0** actual installed readbacks;
the frontend AMD64 log proves native pnpm **12.16.1** metadata bootstrap,
network-isolated frozen-lock replay and negative tests passed.

**Security caveat:** every affected build's scanner still records the **295**
known `linux-libc-dev 7.0.0-42.42` findings. The temporary approved DEV
treatment is **not a fix**, is not transferable to PR #58, and expires at
**2026-11-13T00:00:00Z**. No release digest, production readiness or
human Codespaces/native cross-repository consumer acceptance follows
from the eight build jobs.

Subsequent R4 source enhancements correct `tmux` doctor readback to
`tmux -V` (the previous command yielded an inaccurate optional-tool
warning on otherwise healthy images) and replace a brittle fixed-count
checkout test with *per-checkout* SHA-pinning and credential-custody checks.
This also preserves the test when R5 adds separately privileged jobs.
These follow-up commits require their **own final-head CI**; the earlier
41601842744 results must not be presented as tests of changed files.

**Owner gate remains held:** conduct signed-in, human-created/disposed
Codespaces with private packages and actual runtime consumers in owning
repos; document pinned lock compatibility, native JDK21/iDempiere,
Subscriptions/Maven3.10.0, Playwright browser revision and all negatives.
No merge/release authorisation from this audit entry.
