# DEV-10 Foundation / Publish policy proposal — independent review brief

**Decision state: PENDING INDEPENDENT REVIEW. This proposal is not an active exception and grants no CI, merge, tag, publication, or promotion authority.**

Machine-readable proposal: [`security/decisions/development/foundation.proposal.json`](../../security/decisions/development/foundation.proposal.json)

## Current PR #74 evidence — complete eight-image matrix

Publish run [43829121908](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908), attempt 3, is a `pull_request` run for PR #74 at head `c161821441c0d7c054514abd78a40dc25e774479`. All eight build jobs completed their image build and Trivy scan. Every job reported the same eight HIGH findings against Ubuntu `linux-libc-dev=7.0.0-43.43`; all reported no Trivy fixed version. The review-only inventory preparation succeeded in every job, which also rejects secret findings and fixed-version signals.

| Profile | Platform | Evidence artifact | Raw Trivy SHA-256 | Normalized findings SHA-256 |
|---|---|---:|---|---|
| final | linux/amd64 | [14211489933](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14211489933) | `66757d603f61f4cf60368a5d0c8d3657ad86233339e40ba128e8577add6333cc` | `f17c1ad2708f8f2b4bd3067d814f97eb7341fdb4ad62408bc65f5309448c0b0f` |
| final | linux/arm64 | [14211698892](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14211698892) | `c2736382d0aed323c91358a2fc2ad343aec800058d55b59992acec3322e4731f` | `9366f2271f07ad4d4ec99f46e90ea77f4412fcf1d80cb90b5b46c4ee039d7f39` |
| frontend | linux/amd64 | [14211368408](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14211368408) | `45b7ed6b387b23d5eae532d160007635f0c2764c2a708043ed4578aee3bf2423` | `196d902ab390e44d36c55038eb719fc0f66d5079ca61ca8a5b29f3f966c8ad72` |
| frontend | linux/arm64 | [14212082425](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14212082425) | `c27b2cf36acdb1fc3d56c46de71851211b2c15d8d4ddcd9cd013076322b0cacb` | `13d2a60978e238846a870db257bbf6ca43472d9386bbdc85b0bb797c9f36f486` |
| frontend-e2e | linux/amd64 | [14211789145](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14211789145) | `5f46f70539c6eb5fb956c31433076467b8c17ae701bf8d0abc48a48acc919d94` | `2ab56ac211cb14e7c21193e59b47c36f604370f74798b95415044b2788527f4e` |
| frontend-e2e | linux/arm64 | [14212885283](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14212885283) | `fb5318a1f5ec6cef89229fc3a8314122b6d8f306a83e69028697273455b309ab` | `96066687790656fb5bf7dd5acca0432a20473e183f4bbd2bbb7b2f4b05535e41` |
| infra | linux/amd64 | [14212093246](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14212093246) | `e69dd4590c9018a4c02164ebbb86cc105ac6ae160e714d1a3cce88993e72d4c1` | `de71b4dee1e908613c65e43154673c28d96f88a1a3af6f0afedf1c64a650c980` |
| infra | linux/arm64 | [14211443322](https://github.com/baobab-platform/baobab-dev/actions/runs/43829121908/artifacts/14211443322) | `67542a282d6b6d37f6f2aa251eeb6307c20108958151e04808d7df6d81d08c9c` | `4e4bf05629b5aeb515bb16feaa158a027fceb92864d839ef70c008415efd07bc` |

Each artifact includes the sanitized Trivy vulnerability report, normalized findings, review-only inventory and Trivy database freshness metadata. Trivy was `0.73.0`; vulnerability DB metadata was version 2 and Java DB metadata version 1. Both databases were downloaded during the individual jobs and their recorded update/expiry metadata passed the workflow freshness gate.

Foundation run [43829123295](https://github.com/baobab-platform/baobab-dev/actions/runs/43829123295) independently reproduced the same eight findings in its locally built `final/linux/amd64` image. Its review-only artifact is [14210637706](https://github.com/baobab-platform/baobab-dev/actions/runs/43829123295/artifacts/14210637706).

## Exact finding inventory

| CVE | Package | Installed version | Severity | Trivy fixed version |
|---|---|---|---|---|
| CVE-2022-50240 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2025-40190 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2026-68103 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2026-72198 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2026-74578 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2026-89805 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2026-98376 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |
| CVE-2026-98420 | linux-libc-dev | 7.0.0-43.43 | HIGH | None reported |

The eight normalized inventories contain the same unique finding identities. The package version is published in the Ubuntu 26.04 `resolute-updates` archive; see [Ubuntu package search](https://packages.ubuntu.com/search?arch=any&keywords=libc-dev). Ubuntu's own CVE records continue to mark the kernel source package vulnerable for examples including [CVE-2026-98376](https://ubuntu.com/security/CVE-2026-98376), [CVE-2026-74578](https://ubuntu.com/security/CVE-2026-74578), and [CVE-2026-68103](https://ubuntu.com/security/CVE-2026-68103). These records concern the kernel source package; they do not by themselves decide applicability to the headers-only binary package or its downstream users.

## Why all eight jobs failed — and what did not fail

The image builds, Trivy installation, database freshness checks, scans, normalized evidence generation and artifact uploads completed. Each job then failed closed because the active decision file `security/decisions/development/foundation.json` is absent and the protected `DEV10_PROTECTED_DECISION_SHA256` trust anchor is unset. The configured `DEV10_SECURITY_APPROVER_LOGINS` allowlist is not itself an approval.

BuildKit also logged cache-export errors stating that the configured cache budget had been reached and the cache became read-only. These did not fail the image-build step: the builds proceeded to Trivy scans and retained evidence. This is a separate cache-performance issue, not the security-gate failure.

The Publish gate must not be weakened, and the required compiler/UAPI headers must not be removed merely to silence this package finding. A package-level kernel advisory match is not proof of exploitability in the container, but neither is headers-only packaging proof of non-applicability. The independent per-CVE Ubuntu patch, shipped-header, downstream UAPI/ABI and host-kernel review remains necessary.

## Approval-scope reconciliation

The available governance record does **not** authorize PR #74 to accept these findings:

1. Issue #54's 12 November owner amendment names PR #62 for the `7.0.0-43.43` eight-CVE treatment; it does not name PR #74.
2. The risk register's PR #62 scope is distinct from the legacy executable gate's PR #71 constant. The issue/PR record does not resolve that #62/#71 custody discrepancy.
3. Issue #54's 14 November entry explicitly places PR #74 in v1.5.2 release-preparation **review scope only**, with no CVE exception, tag permission or scanner bypass.
4. PR #74's subsequent issue comment reiterates that it is an assessment request only.

The new machine-readable file therefore remains `pending_independent_review`. Its proposed scope lists the four profiles and two architectures solely so the independent reviewer can assess the complete matrix. Approval fields and timestamps remain null. It does not create an active `foundation.json`, authorize PR #74, or make any CI job pass.

## Required decision and activation sequence

1. The accountable owner and independent security reviewer must reconcile the #62/#71 discrepancy and decide whether any PR #74 development-only residual-risk acceptance is justified. A decision to accept residual risk must not be represented as remediation or VEX `not_affected`.
2. Complete the per-CVE applicability review, including Canonical's Ubuntu patch/backport state, shipped UAPI headers, downstream compilation/ABI impact and the separate host-kernel boundary. Prefer a supported vendor fix when available.
3. If and only if a bounded development-only decision is explicitly approved, finalize the decision record with exact findings, profiles, architectures, preparer, independent approver, approval PR, approval timestamp and expiry.
4. Merge the decision through the protected approval process. Verify the PR is merged into `main`, the preparer authored it, the current independent trusted reviewer approved the merged head, and numeric reviewer/contributor custody is independent.
5. Only after those exact bytes are final and merged, calculate SHA-256 over the approved file and have the designated custodian provision that exact value as `DEV10_PROTECTED_DECISION_SHA256`. Any byte change requires renewed review and a new hash.
6. Re-run Foundation and all eight Publish jobs on the resulting PR head. Residual-risk acceptance, if approved, remains development-only and does not authorize a release tag, GHCR publication, signing, promotion, staging or production. Those controls require their own exact-digest and protected approvals.

Until this sequence is completed, Foundation and Publish are expected to remain **SECURITY DENIED** for these findings. That is the correct fail-closed outcome, not a CI defect to suppress.



## 16 November 2026 — reusable development policy proposal and execution boundary

The 12 November issue #54 amendment explicitly names **PR #62** for the eight HIGH findings against Ubuntu 26.04 `linux-libc-dev=7.0.0-43.43`, with expiry **2026-11-26 00:00 UTC**. No approval naming PR #71 was found in the issue #54 decision comments or PR #71's described scope. The older assessment text that called PR #71 the executable approval scope is superseded: the current legacy gate denies all PR/main residual-risk acceptance and does not grant PR-number-based authority.

The PR #74 scans provide new inventory evidence, not an approval. The proposal seeks a **reusable, PR-number-independent development policy** for the exact eight observed findings, all four profiles and both Linux architectures. It is limited to same-repository pull requests whose base is `main` and push CI on `refs/heads/main`; it is not available to tags, releases, workflow dispatch, schedules, deployments, fork PRs, other PR base branches, staging or production. It expires at `2026-11-26T00:00:00Z`. Any new/changed finding, package/version/severity, fixed-version signal, secret, missing scan inventory or scanner error remains blocking.

The policy remains `pending_independent_review`. The PR #74 evidence runs were produced at source head `c161821441c0d7c054514abd78a40dc25e774479`; they are not claimed to be scans of the later documentation-only head. The exact bytes of an approved `foundation.json` must be reviewed and merged through the protected decision path before the trust anchor is provisioned. No SHA is to be derived from this proposal.
