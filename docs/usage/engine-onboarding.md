# Engine developer onboarding (DEV-14)

**Scope:** developer diagnostics and handoff. This document does not certify
Pulse, Payments or any new provider, and does not change the active image lock.

DEV-14 introduces a *fourth* contract: Shared's
`contracts/development/v1/engine-integration-profile.schema.json`, merged via
[Shared #402](https://github.com/baobab-platform/shared/pull/402) and
subsequently amended by [Shared #403](https://github.com/baobab-platform/shared/pull/403).
The current exact qualified checkout is Shared #403's merge SHA
`32b71f3335e566daeb58246f17fcbbf162cf7f53`; the older #402
pin `9fa1bbd6ad9b5c9d4ec406c721bd75227803dcea` must be rejected
because it lacks the Payments invocation re-registration fix.

It selects IAM, CP, one subject engine and its owner-native dependencies. It
references, but never replaces, each engine's:
- `.baobab/environment.yaml` (toolchain);
- `.baobab/capability-provider.yaml` (source implementation claim);
- Shared synthetic enterprise profiles (disposable tenant scenario).

## Read-only local doctor

```sh
python3 scripts/dev14-doctor.py --profile pulse-intelligence
python3 scripts/dev14-doctor.py --profile payments-sandbox
# Add a checked out exact Shared source to check the contract pin:
python3 scripts/dev14-doctor.py --profile pulse-intelligence --shared-root ../shared
```

The tool checks relevant installed binaries/versions, Docker daemon and
Compose reachability, and (when supplied) the **exact clean Shared commit**.
For Pulse the current qualified interpreter line is Python 3.14.x (not 3.15); Payments needs Rust >=1.88 plus
Cargo. An absent Rust toolchain is a BLOCKED prerequisite, not a simulated
native build or permission to silently change the global image. Use a
reviewed and owner-qualified Rust Dev Container feature/layer if necessary.

`--fail-on-blocked` returns nonzero for a blocked local toolchain; without
this option the command emits machine-readable diagnostics for the UI/CI.
It never prints credentials, pulls images, contacts IAM/CP, creates tenants
or proves EngineInstances. `LOCAL_TOOLCHAIN_OBSERVED` means local tools
only. It does *not* mean a native engine/API, IAM/CP or ENG-ONB case passed.

## Execution remains owned by Infrastructure

The reusable profile-aware Infrastructure controller must independently
validate the Shared schema/owner declaration, pin source/image digests,
create a private bounded project, use genuine IAM and CP authority, run
native adapters, record explicit case outcomes and recover all resources.
Infrastructure [#64](https://github.com/baobab-platform/infrastructure/pull/64)
is merged and introduces the connected IAM/CP/native engine executor and
independent evidence/cleanup checks. The existence of that executor and
its source CI does **not** establish that every ENG-ONB case passed on the
current owner images or that any protected release is authorised. Consume
the current Shared #403 bundle and independently inspect executed cases,
current identity/authority evidence, teardown and immutable receipts.

Keep DEV-15 actual Pulse/Payments database/API tests separate. CMS is not
required by either headless profile. No developer profile activates a
certified provider, grants a legal actor mandate or authorises production
money movement.

## Rollback and operator guidance

Remove the developer diagnostic or restore its previous source commit to
roll back. It changes neither `config/versions.lock` nor the published image
contents. Treat `UNAVAILABLE`, `VERSION_UNSUPPORTED`, and `MISMATCH`
as actionable blockers, and never turn them into green status by hiding the
check. Keep SDK and language versions pinned by their owner contract.


## DEV-10 security dependency and merge sequencing

This DEV-14 doctor changes source diagnostics, not image trust. The branch
also carries the same checksum-pinned Terraform 1.17.1, Maven Guava 33.7.2
replacement, pip-vendored msgpack 1.2.3, setuptools-derived pkg_resources
78.1.1 and urllib3 2.8.0 security remediations proposed in
[baobab-dev #48](https://github.com/baobab-platform/baobab-dev/pull/48).
Both PRs must preserve these fixes when #48 is merged first. A stale
DEV-14 branch must never revert to Terraform 1.16.7 or the unpatched
vendored libraries. The vendoring rebuild also requires an upstream-
compatible pkg_resources patch and must pass full amd64/arm64 image CI
before merge. No .trivyignore suppression or expiry extension is authorised
by the doctor; report remaining unsuppressed findings explicitly.

`LOCAL_TOOLCHAIN_OBSERVED` does not supersede independent Infrastructure
native execution, evidence custody or protected environment approvals.

## Stacked DEV-10 integration and security qualification (30 October 2026)

PR #50 integrates the qualified #48 source head
`47f76836854d42b7f08b2ee1796d2c902706dacc` and retains the four
DEV-14-specific developer-doctor additions. GitHub currently treats the pair
as a **stack**: the immediate merge and auto-merge endpoints rejected #48
while the dependent PR exists, and changing #50's base directly is blocked.
This source integration is **not** a claim that #48 was merged to `main`.

The temporary, user-attested DEV-10 *development residual-risk acceptance*
now explicitly includes **PR #50**, as well as PR #48 and untagged development
`main`, so the dependent checks exercise the same exact known package
`linux-libc-dev 7.0.0-42.42` and 295-CVE inventory. The expiry remains
**13 November 2026 at 00:00 UTC**. It is not a `not_affected` VEX approval,
a release exemption, a staging/production certification, or a newly fixed
vendor CVE. All other CVEs, package versions, PR identities and tag pushes
remain denied. See `scripts/dev10_kernel_risk_gate.py`,
`tests/test_dev10_kernel_risk_gate.py` and
`docs/assessments/dev10-linux-libc-dev-risk-decision.md`.

**Merge sequence remains:** merge qualified #48 via GitHub's stack-supported
merge workflow; retarget #50 to the resulting `main`; requalify the final
#50 head and perform its required review before considering its merge.


## Future toolchain upgrades

Do not repeat the DEV-10 integration difficulties when bringing new engines
onto Codespaces. See the
[Toolchain Upgrade Playbook](toolchain-upgrade-playbook.md) for exact version
coupling, native/embedded dependency qualification, mandatory denial tests,
multi-architecture scanning and consumer rollout. The
[DEV-10/DEV-14 retrospective](../incidents/2026-10-30-dev10-dev14-toolchain-retrospective.md)
records observed failures and distinguishes passing source checks from
actual engine/runtime and protected release evidence.
