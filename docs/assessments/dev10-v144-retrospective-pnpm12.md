# DEV-10: immutable v1.4.4 release retrospective and pnpm 12 readiness

Assessment date: 2026-10-30
Repository: baobab-platform/baobab-dev
Scope: PR #48 only
Status: independently captured diagnostic evidence; security-release gate HELD

## Evidence custody

An isolated comparison run was executed on GitHub Actions:
https://github.com/baobab-platform/baobab-dev/actions/runs/41022963883

- Ten diagnostic jobs completed successfully: eight read-only vulnerability inventory jobs
  and two pnpm 12.16.1 preview jobs.
- Eight artifacts named v144-TARGET-ARCH retain each exact reference,
  secret-redacted Trivy vulnerability JSON, and normalized per-finding evidence.
- The evidence-only scans used Trivy 0.73.0, --scanners vuln,secret,
  --ignorefile /dev/null, --pkg-types os,library, --severity CRITICAL,HIGH,
  platform selection and immutable GHCR digests. They used --exit-code 0
  deliberately to record historical findings without treating an old release
  as the current release gate. Errors and missing inventory evidence failed.
- A CodeQL high-severity check appeared while the temporary workflow was
  under qualification. It continued to fail after that workflow was removed.
  Its cause is NOT established by this assessment and must be investigated
  separately, without attributing it to the temporary workflow. The temporary
  workflow was removed because the diagnostic evidence had been captured and
  ongoing CI execution was no longer needed; the Foundation and Publish
  release gates are unchanged.

## Historical immutable profiles and present-day findings

Source of digests: immutable v1.4.4 GitHub release published 2026-09-24,
https://github.com/baobab-platform/baobab-dev/releases/tag/v1.4.4

| Profile | Published manifest digest (sha256) | AMD64 | ARM64 | linux-libc-dev |
| --- | --- | ---: | ---: | --- |
| final | 9603f0e7402aa85771e904db1c20f2ecc02f705131b266cb4ec3d1c24ea58ae4 | 501 (16 critical) | 501 (16 critical) | 398 |
| infra | 0f73f3e6093ab5c955cbbb341e5731681ee4283cae75f13c56f3e38373467ecc | 463 (14 critical) | 463 (14 critical) | 398 |
| frontend | 1b3165067912eacbca96b576efb67e0428850b1ff1a953aa9013127a01635371 | 441 (14 critical) | 441 (14 critical) | 398 |
| frontend-e2e | eb9c401cea16c4f333c28b250dd455e505752dfc6d11e9779a182a02bc207213 | 442 (14 critical) | 442 (14 critical) | 398 |

All eight historical images contain linux-libc-dev 7.0.0-34.34. Its 398
matched advisories are a subset of the total; the old profiles also contain
matches for Go stdlib/modules, curl/OpenSSL, undici 6.28.0, and, in final,
Python vendored libraries and Guava. A complete inventory is in the run
artifacts, not this abbreviated report.

The later PR #48 image security scans at head 80ed4684 each recorded
295 HIGH/CRITICAL findings (12 critical, 283 high), all for linux-libc-dev
7.0.0-42.42. These are observed advisory-match counts, not vulnerability
exploitability conclusions. The builds are not byte-identical and the
historical image is remote, while current PR scanning uses local build
products. Avoid interpreting this comparison as a formal security
certification. Nonetheless, this establishes that today's unfiltered scan
would flag the previously released v1.4.4 images, so their earlier green
status was not proof of unrestricted image-vulnerability clearance.

## Historical CI policy change

- v1.4.4 Foundation pin: Shared 53ed9cdba8fc33e2f184d1ba29b990f71b74f85f,
  container_ignore_unfixed: true.
- PR #48 Shared Foundation pin: 31de2bc3dcd56128c019c640dc7e12c10ae9ca69,
  container_ignore_unfixed: false.
- Both Shared pins have an identical reusable-foundation-container.yml Git
  blob (54c80c047c654397a434f5379ec690a9562bb9fb).
- v1.4.4 Publish enabled --ignore-unfixed and broad --skip-files paths;
  PR #48 deliberately removed both, and uses --ignorefile /dev/null.
- The former green Foundation and Publish runs passed under the earlier,
  narrower policy. The present container failure is driven by the stricter
  security criteria, not a demonstrated compiler or DEV-10 onboarding defect.

## pnpm 12.16.1 compatibility qualification

Stable upstream pnpm v12.16.1 was released 2026-10-27:
https://github.com/pnpm/pnpm/releases/tag/v12.16.1

Official native Linux binary asset SHA256:
- x64 pnpm-linux-x64.tar.gz:
  565ff81174a14f6f7bd5d84c1b17e51031a80230d370a1fe24be5d16bd02a825
- arm64 pnpm-linux-arm64.tar.gz:
  f5847699e5d528f8f8e9bcfb385e58cb9fba7482af1b1aa7b70737be42277f81

Both AMD64 and ARM64 tests verified these exact SHA256 values, ran the
native pnpm 12.16.1 executable inside the published v1.4.4 frontend image
with a temporary pnpm 12 packageManager pin, and successfully executed an
offline frozen install of the committed pnpm 11-format DEV-10 workspace
fixture. The lockfile SHA256 remained identical. This is an intentionally
small compatibility smoke test; real consumers and Corepack 12 activation
were not qualified by it.

Read-only consumer assessment shows exact pnpm 11.24.0 pins and/or bootstrap
version checks in nabhold, zuribeans, thamani and baobab-cp. The existing
baobab-dev image has an intentionally network-disabled, prepopulated
Corepack cache. An image-only change to pnpm 12 would break the exact
consumer startup contract.

Migration gate before default upgrade: verify Corepack provisioning with
pnpm 12 in an isolated disposable image; coordinate exact packageManager
and bootstrap changes across the four consuming repos; validate real
private GitHub Packages authentication, frozen lockfiles, install scripts,
build/test/typecheck, AMD64/ARM64 Codespaces bootstrap and rollback;
independently review security and acceptance. No consuming repository,
default pnpm 11.24.0 pin, or release image was changed by this assessment.

## Decision

Retain the effective pnpm 11.24.0 default pending coordinated migration.
Keep the existing unrestricted HIGH/CRITICAL Trivy exit-code 1 gates
mandatory. PR #48 must remain HELD until unresolved vendor advisories and
applicable release/consumer acceptance requirements are qualified.
