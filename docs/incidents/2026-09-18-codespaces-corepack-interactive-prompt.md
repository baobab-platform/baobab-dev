# Incident: Codespaces hang on an interactive Corepack pnpm download prompt

**Date detected:** 2026-09-18
**Repository:** `baobab-platform/baobab-dev`
**Affected published contract:** `ghcr.io/baobab-platform/baobab-dev:1.4.0-frontend`
**Affected downstream consumer observed:** `baobab-platform/zuribeans` GitHub Codespaces (and, on inspection, every other repo sharing its `.devcontainer/devcontainer.json` convention, e.g. `baobab-platform/nabhold`)

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

Every frontend consumer repo independently pins an *exact* pnpm version in its own `package.json`, via the `packageManager` field — e.g. `baobab-platform/zuribeans`:

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
5. **Consumers** (`baobab-platform/zuribeans`): `updateContentCommand` simplified from `"corepack enable && pnpm install --frozen-lockfile"` to `"pnpm install --frozen-lockfile"` — `corepack enable` writes shim scripts into the image filesystem and is already done once at Docker build time; re-running it on every container create added no correctness benefit while keeping the interactive code path reachable.

## Correction (same day, during PR CI validation)

The first version of this fix shipped `ENV COREPACK_ENABLE_NETWORK=0` alone. PR CI (`baobab-platform/baobab-dev#32`) caught that this broke the `frontend`/`frontend-e2e`/`final` image builds outright: the Dockerfile's own `RUN baobab-verify` step failed with `pnpm — 'pnpm --version' failed (exit 1): Network access disabled by the environment; can't reach npm repository https://registry.npmjs.org`.

Root cause of the regression: `COREPACK_ENABLE_NETWORK=0` is not the only Corepack setting that governs network access. A bare `pnpm --version` invocation with no project `packageManager` field in scope (exactly what `baobab-verify` does, run from `/workspaces` with no `package.json` present) is, by default, resolved through Corepack's "Known Good Release" mechanism — which checks the npm registry for a newer release on *every* invocation, independent of whether a matching version is already `prepare --activate`d locally. That check is governed separately by `COREPACK_DEFAULT_TO_LATEST` (on by default), not by `COREPACK_ENABLE_NETWORK`. With network disabled and that check still enabled, the check itself failed hard.

Fix: also set `ENV COREPACK_DEFAULT_TO_LATEST=0`. With both set, Corepack trusts the already-activated version instead of phoning home first (so ordinary invocations — including `baobab-verify`, and any consumer whose `packageManager` pin matches this image's `PNPM_VERSION`) work fully offline, while a genuine version *mismatch* still fails immediately and clearly per `COREPACK_ENABLE_NETWORK=0` — the actual defense-in-depth behavior this section was meant to add.

## Control gap and follow-up

There was no coordination mechanism between this repo's own pnpm version resolution and any consumer's `packageManager` pin — see `docs/architecture/version-management.md § Consumer Version Coupling` for the documented ownership boundary and upgrade procedure this incident motivated. The `.baobab/environment.yaml` development-environment contract (schema in `baobab-platform/shared`) governs a repo's required baobab-dev **image** version (`minimum_version`), but has no field for the pnpm version baked into that image — a consumer's own `packageManager` field is the only place that version is declared. Bumping `versions.yaml`'s pnpm pin therefore still requires a human to notice a consumer has moved (there is no automated cross-repo check yet); this is a known gap, not resolved by this fix, tracked for a future ADR/schema addition rather than papered over here.

## Recurrence (v1.4.2, same rollout): the identical class of bug, for Playwright

While rolling v1.4.1 out to consumer repos, `baobab-platform/zuribeans#60`'s CI failed on `Error: browserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1234/...`. Confirmed as a genuine regression (not a flake) by checking that the identical CI job passed on `zuribeans`' `main` branch against the older `1.2.6-frontend-e2e` image.

Root cause: `frontend_tooling.playwright.version` in `versions.yaml` was *also* left floating at `"latest"` — the exact same coordination gap this pnpm incident describes, just for a different tool. The globally-installed `playwright` CLI in this image (which downloads browser binaries at build time) and a consumer's own `@playwright/test` dependency (which looks up browser binaries by the exact revision its own version expects) must resolve to the same release, or the browser binaries this image downloaded are invisible to the consumer's test runner. `zuribeans` pins `"@playwright/test": "1.62.1"`; by the time v1.4.1 was built, "latest" had drifted past that.

Fix (v1.4.2): pin `frontend_tooling.playwright.version` to `1.62.1`, matching consumers, exactly the same remediation pnpm already got. This confirms the gap above is real and not hypothetical: `sharp`/`lighthouse`/`turbo` remain floating deliberately (see `docs/architecture/version-management.md`) — they are ordinary CLI tools with no consumer-side version coupling, unlike pnpm and Playwright.
