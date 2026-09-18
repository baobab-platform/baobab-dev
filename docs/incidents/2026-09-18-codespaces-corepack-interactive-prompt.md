# Incident: Codespaces hang on an interactive Corepack pnpm download prompt

**Date detected:** 2026-09-18
**Repository:** `nabhold/baobab-dev`
**Affected published contract:** `ghcr.io/nabhold/baobab-dev:1.4.0-frontend`
**Affected downstream consumer observed:** `nabhold/zuribeans` GitHub Codespaces (and, on inspection, every other repo sharing its `.devcontainer/devcontainer.json` convention, e.g. `nabhold/nabhold`)

## Summary

A clean Codespace/Dev Container build for ZuriBeans stalled during `updateContentCommand`:

```text
corepack enable && pnpm install --frozen-lockfile

! Corepack is about to download
https://registry.npmjs.org/pnpm/-/pnpm-11.24.0.tgz

? Do you want to continue? [Y/n]
```

The container itself started successfully — this was not an image-pull or container-startup failure (contrast `docs/incidents/2026-09-13-ghcr-v1.3.0-frontend-manifest-loss.md`, a genuinely different failure mode with superficially similar symptoms). Package-manager provisioning was interactive, and a Codespaces/Dev Container lifecycle command has no TTY to answer that prompt, so the build hung indefinitely.

## Root cause

`config/versions.yaml`'s `package_managers.pnpm.version` was `"latest"`. `config/resolve.sh` resolves that to whatever pnpm release is newest on the npm registry **at this image's own build time**, and the Dockerfile's `with-node` stage bakes that resolved version in via `corepack prepare "pnpm@${PNPM_VERSION}" --activate`.

Every frontend consumer repo independently pins an *exact* pnpm version in its own `package.json`, via the `packageManager` field — e.g. `nabhold/zuribeans`:

```json
{
  "packageManager": "pnpm@11.24.0"
}
```

That declaration is resolved completely independently of this image's own release cadence. Corepack's default behavior (`COREPACK_ENABLE_PROJECT_SPEC`, on unless explicitly disabled) checks a project's `packageManager` field against what's already activated; on a mismatch it attempts to download the project-declared version over the network on first invocation, and — because Corepack could not confirm it was running fully non-interactively — showed a confirmation prompt first. With `versions.yaml` floating pnpm to `"latest"`, this mismatch was not an edge case: it was the expected steady state, since pnpm ships new releases far more often than this image is rebuilt and published.

## Why `check_required "pnpm" pnpm` in `baobab-verify` didn't catch this

The pre-fix `baobab-verify` (`scripts/verify.sh`) only checked that `pnpm --version` succeeded — i.e., that *some* pnpm binary was on `PATH`. It never compared that version against anything, so an image whose baked-in pnpm no longer matched any real consumer's `packageManager` pin still passed every existing check, both at image-build time (`RUN baobab-verify`) and inside a consumer's own `postCreateCommand`.

## Fix

1. **`config/versions.yaml`**: `package_managers.pnpm.version` changed from `"latest"` to the exact version consuming repos currently declare (`11.24.0`), so the image now bakes in precisely the version those repos already expect. For the common case, this eliminates the mismatch outright — no network fetch is ever attempted.
2. **Dockerfile (`with-node` stage)**: added `ENV COREPACK_ENABLE_NETWORK=0`, inherited by every profile that descends from it (`frontend`, `frontend-e2e`, `final`). Defense-in-depth, not the primary fix — it ensures that if a consumer repo's `packageManager` pin drifts ahead of this image's own pin again in the future, Corepack fails immediately with an explicit "network disabled" error rather than downloading silently or prompting and hanging.
3. **`scripts/verify.sh`**: added `check_exact_version()` (pnpm, against `PNPM_VERSION` from `versions.lock`) and `check_major_version()` (Node, against `NODE_MAJOR`), replacing the presence-only `check_required` calls for those two. A future version-pinning regression now fails `baobab-verify` loudly, both at image-build time and at container runtime.
4. **`.github/workflows/publish.yml`**: added a non-interactive package-manager provisioning test (frontend/frontend-e2e targets) that runs `pnpm install --frozen-lockfile` inside the built candidate image against a fixture project pinning this image's own exact `PNPM_VERSION`, with stdin closed and `CI=true` set, bounded by a 90-second timeout — proving the fix holds under the same non-interactive shape a real Codespace lifecycle command runs under, and turning any regression of this exact hang into a clean, bounded CI failure.
5. **Consumers** (`nabhold/zuribeans`): `updateContentCommand` simplified from `"corepack enable && pnpm install --frozen-lockfile"` to `"pnpm install --frozen-lockfile"` — `corepack enable` writes shim scripts into the image filesystem and is already done once at Docker build time; re-running it on every container create added no correctness benefit while keeping the interactive code path reachable.

## Control gap and follow-up

There was no coordination mechanism between this repo's own pnpm version resolution and any consumer's `packageManager` pin — see `docs/architecture/version-management.md § Consumer Version Coupling` for the documented ownership boundary and upgrade procedure this incident motivated. The `.nabhold/environment.yaml` development-environment contract (schema in `nabhold/shared`) governs a repo's required baobab-dev **image** version (`minimum_version`), but has no field for the pnpm version baked into that image — a consumer's own `packageManager` field is the only place that version is declared. Bumping `versions.yaml`'s pnpm pin therefore still requires a human to notice a consumer has moved (there is no automated cross-repo check yet); this is a known gap, not resolved by this fix, tracked for a future ADR/schema addition rather than papered over here.
