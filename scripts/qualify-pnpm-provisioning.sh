#!/usr/bin/env bash
# DEV-10 R4: a new pnpm 12 lockfile requires metadata for its packageManager
# bootstrap dependency. Qualify a network-assisted cold lock resolution, then
# a physically disconnected frozen install against the identical cache/lock.
set -euo pipefail
image="${1:?usage: qualify-pnpm-provisioning.sh IMAGE PNPM_VERSION}"
pin="${2:?pnpm version required}"
[[ "$pin" =~ ^12\.[0-9]+\.[0-9]+$ ]] ||
    { echo "::error::Expected an exact pinned pnpm 12 release"; exit 1; }
scratch="$(mktemp -d "${RUNNER_TEMP:-/tmp}/baobab-pnpm-12.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
fixture="$scratch/project"
cache="$scratch/cache"
store="$scratch/store"
mkdir -p "$fixture" "$cache" "$store"
cat > "$fixture/package.json" <<EOF
{
  "name": "baobab-dev-pnpm-provisioning-fixture",
  "private": true,
  "packageManager": "pnpm@${pin}"
}
EOF
# Ephemeral CI scratch only; no secrets, credentials or consumer packages.
# Image USER vscode (1000) differs from the runner's host UID.
chmod -R a+rwX "$scratch"
common=(
    --rm
    -e CI=true
    -e pnpm_config_pm_on_fail=error
    -v "$fixture:/workspaces/fixture"
    -v "$cache:/home/vscode/.cache/pnpm"
    -v "$store:/home/vscode/.local/share/pnpm/store"
    -w /workspaces/fixture
)
echo "::notice::pnpm ${pin}: resolve cold package-manager metadata online, without TTY."
# pnpm 12 treats a packageManager pin as a configuration dependency.
# Do not mislabel unavailable OFFLINE bootstrap metadata as a broken binary.
timeout 120 docker run "${common[@]}" "$image" \
    sh -eu -c 'test "$(pnpm --version)" = "$1"; pnpm install --lockfile-only --no-frozen-lockfile < /dev/null; test -s pnpm-lock.yaml' \
    sh "$pin" < /dev/null
before="$(sha256sum "$fixture/pnpm-lock.yaml" | cut -d ' ' -f 1)"
echo "::notice::pnpm ${pin}: validate committed-style frozen lock with network disabled."
timeout 90 docker run "${common[@]}" --network none "$image" \
    sh -eu -c 'pnpm install --frozen-lockfile --offline < /dev/null && test -s pnpm-lock.yaml' \
    < /dev/null
after="$(sha256sum "$fixture/pnpm-lock.yaml" | cut -d ' ' -f 1)"
[[ "$before" == "$after" ]] ||
    { echo "::error::Frozen pnpm install modified the lockfile"; exit 1; }

# A wrong version must not cause a silent Corepack/pnpm download.
cp "$fixture/package.json" "$scratch/original-package.json"
sed -i "s/pnpm@${pin}/pnpm@0.0.0/" "$fixture/package.json"
if timeout 45 docker run "${common[@]}" --network none "$image" \
        sh -eu -c 'pnpm install --frozen-lockfile --offline < /dev/null' \
        < /dev/null > "$scratch/mismatched-pin.log" 2>&1; then
    echo "::error::pnpm accepted an incorrect packageManager pin"
    exit 1
fi
mv "$scratch/original-package.json" "$fixture/package.json"

# The old handcrafted one-line v9 lockfile is intentionally invalid.
cp "$fixture/pnpm-lock.yaml" "$scratch/original-pnpm-lock.yaml"
printf "lockfileVersion: '9.0'\n" > "$fixture/pnpm-lock.yaml"
if timeout 45 docker run "${common[@]}" --network none "$image" \
        sh -eu -c 'pnpm install --frozen-lockfile --offline < /dev/null' \
        < /dev/null > "$scratch/invalid-lock.log" 2>&1; then
    echo "::error::pnpm accepted an invalid frozen lockfile"
    exit 1
fi
mv "$scratch/original-pnpm-lock.yaml" "$fixture/pnpm-lock.yaml"

echo "::notice::pnpm ${pin}: cold bootstrap, offline frozen lock, mismatch and invalid-lock negatives passed."
