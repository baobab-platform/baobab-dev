#!/usr/bin/env bash
# Shared, fail-closed project-pinned pnpm selection for onboarding, summary,
# and read-only verification. The image-wide native pnpm remains independent.

set -euo pipefail

project_corepack_home() {
    : "${HOME:?HOME must be set for the user-owned Corepack cache}"
    printf '%s\n' "${BAOBAB_COREPACK_PROJECT_HOME:-${HOME}/.cache/baobab-corepack}"
}

project_pnpm_pin() {
    [ -f package.json ] || {
        printf '%s\n' "package.json is required for a project pnpm pin." >&2
        return 1
    }
    command -v node >/dev/null 2>&1 || {
        printf '%s\n' "Node.js is required to read packageManager." >&2
        return 1
    }
    node -e '
const fs = require("node:fs");
const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
const manager = typeof pkg.packageManager === "string" ? pkg.packageManager : "";
const match = /^pnpm@([0-9]+\.[0-9]+\.[0-9]+)(?:\+sha(?:224|512)\.[0-9a-f]+)?$/.exec(manager);
if (!match) {
  console.error("package.json must declare an exact pnpm packageManager.");
  process.exit(2);
}
process.stdout.write(match[1] + "\n");
'
}

prepare_project_pnpm() {
    local home
    home="$(project_corepack_home)"
    project_pnpm_pin >/dev/null
    command -v corepack >/dev/null 2>&1 || {
        printf '%s\n' "Corepack is required for project-pinned pnpm." >&2
        return 1
    }
    mkdir -p "${home}" || {
        printf '%s\n' "Project Corepack cache is not writable: ${home}" >&2
        return 1
    }
    [ -d "${home}" ] && [ -w "${home}" ] || {
        printf '%s\n' "Project Corepack cache is not writable: ${home}" >&2
        return 1
    }
    env -u COREPACK_INTEGRITY_KEYS \
        COREPACK_HOME="${home}" \
        COREPACK_ENABLE_NETWORK=1 \
        COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
        COREPACK_DEFAULT_TO_LATEST=0 \
        COREPACK_ON_UNVERIFIED_DOWNLOAD=error \
            corepack install
    env -u COREPACK_INTEGRITY_KEYS \
        COREPACK_HOME="${home}" \
        COREPACK_ENABLE_NETWORK=1 \
        COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
        COREPACK_DEFAULT_TO_LATEST=0 \
        COREPACK_ON_UNVERIFIED_DOWNLOAD=error \
            corepack pnpm --version >/dev/null
}

run_project_pnpm() {
    local home
    home="$(project_corepack_home)"
    project_pnpm_pin >/dev/null
    command -v corepack >/dev/null 2>&1 || {
        printf '%s\n' "Corepack is required for project-pinned pnpm." >&2
        return 1
    }
    env -u COREPACK_INTEGRITY_KEYS \
        COREPACK_HOME="${home}" \
        COREPACK_ENABLE_NETWORK=0 \
        COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
        COREPACK_DEFAULT_TO_LATEST=0 \
        COREPACK_ON_UNVERIFIED_DOWNLOAD=error \
            corepack pnpm "$@"
}

case "${1:-}" in
    prepare)
        shift
        [ "$#" -eq 0 ] || { printf '%s\n' "Usage: baobab-project-pnpm prepare" >&2; exit 2; }
        prepare_project_pnpm
        ;;
    pin)
        shift
        [ "$#" -eq 0 ] || { printf '%s\n' "Usage: baobab-project-pnpm pin" >&2; exit 2; }
        project_pnpm_pin
        ;;
    --version|-v)
        [ "$#" -eq 1 ] || { printf '%s\n' "Usage: baobab-project-pnpm --version" >&2; exit 2; }
        run_project_pnpm --version
        ;;
    *)
        run_project_pnpm "$@"
        ;;
esac
