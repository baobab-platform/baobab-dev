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
| Maven | 3.9.16 (current lock) | 3.10.0 GA is next isolated candidate; Maven 4 RC must not be made default |

The `config/versions.yaml` file is the policy source, `config/versions.lock` is the reproducible resolution, and actual installed image readback is separate evidence. No changing owner packageManager pins without a native test. See `dev10-r4-all-toolchains-maven4-review-20261102.md`.

## CI evidence and corrections

Initial candidate SHA `ac187a4e40ce895ab53d0036a953730a92874a3b`, workflow run
[41557252699](https://github.com/baobab-platform/baobab-dev/actions/runs/41557252699):

- Passed: DEV-10 locked onboarding, DEV-14 developer doctor, source Security, Foundation, documentation, frozen source lock. Infra AMD64/ARM64 and frontend ARM64, frontend-e2e ARM64 image legs also passed.
- Failed: frontend AMD64 and frontend-e2e AMD64 rejected an invalid handwritten pnpm 12 frozen lockfile fixture; corrected to generate a valid fixture using the exact image binary entirely offline, then execute the frozen install.
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
