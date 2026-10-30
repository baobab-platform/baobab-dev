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
The current Infrastructure DEV-14 source planner is deliberately fail closed
until a real execution adapter exists.

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
