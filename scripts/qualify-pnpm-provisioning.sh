#!/usr/bin/env bash
# DEV-10 R4: a new pnpm 12 lockfile requires metadata for its packageManager
# bootstrap dependency. Qualify a network-assisted cold install, then
# a physically disconnected frozen install against the identical cache/lock.
set -euo pipefail
image="${1:?usage: qualify-pnpm-provisioning.sh IMAGE PNPM_VERSION}"
pin="${2:?pnpm version required}"
[[ "$pin" =~ ^12\.[0-9]+\.[0-9]+$ ]] ||
    { echo "::error::Expected an exact pinned pnpm 12 release"; exit 1; }
scratch="$(mktemp -d "${RUNNER_TEMP:-/tmp}/baobab-pnpm-12.XXXXXX")"
# The container's vscode UID (1000) may not match the host runner UID.
# A recursive chmod on the EMPTY scratch directory is insufficient: pnpm
# creates fresh 0600 files and 0700 directories during its install.
# Regrant host access through an isolated root helper in the same image.
# No privileged host Docker operation or global permission change is needed.
restore_host_access() {
    docker run --rm --user 0 --network none \
        -v "$scratch:/tmp/dev10-fixture" --entrypoint sh "$image" \
        -c 'chmod -R a+rwX /tmp/dev10-fixture'
}
cleanup() {
    restore_host_access || true
    rm -rf "$scratch"
}
trap cleanup EXIT
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
# A normal install (not --lockfile-only) also warms any required package
# archive, not just its registry metadata, before the disconnected replay.
# Do not mislabel unavailable OFFLINE bootstrap metadata as a broken binary.
timeout 120 docker run "${common[@]}" "$image" \
    sh -eu -c 'test "$(pnpm --version)" = "$1"; pnpm install --no-frozen-lockfile < /dev/null; test -s pnpm-lock.yaml' \
    sh "$pin" < /dev/null
restore_host_access
before="$(sha256sum "$fixture/pnpm-lock.yaml" | cut -d ' ' -f 1)"
echo "::notice::pnpm ${pin}: validate committed-style frozen lock with network disabled."
timeout 90 docker run "${common[@]}" --network none "$image" \
    sh -eu -c 'pnpm install --frozen-lockfile --offline < /dev/null && test -s pnpm-lock.yaml' \
    < /dev/null
restore_host_access
after="$(sha256sum "$fixture/pnpm-lock.yaml" | cut -d ' ' -f 1)"
[[ "$before" == "$after" ]] ||
    { echo "::error::Frozen pnpm install modified the lockfile"; exit 1; }

# A wrong version must not cause a silent Corepack/pnpm download.
cp "$fixture/package.json" "$scratch/original-package.json"
sed -i "s/pnpm@${pin}/pnpm@0.0.0/" "$fixture/package.json"
mismatch_rc=0
timeout 45 docker run "${common[@]}" --network none "$image" \
    sh -eu -c 'pnpm install --no-frozen-lockfile --offline < /dev/null' \
    < /dev/null > "$scratch/mismatched-pin.log" 2>&1 || mismatch_rc=$?
restore_host_access
# A timeout, Docker runtime failure or wrong lockfile is NOT evidence of an
# exact-version mismatch. Require a prompt pnpm-level failure in this test.
if (( mismatch_rc != 1 )) || ! grep -Eiq 'pnpm|package.?manager|version' "$scratch/mismatched-pin.log"; then
    echo "::error::pnpm version mismatch negative failed (status=${mismatch_rc})"
    sed -n '1,20p' "$scratch/mismatched-pin.log"
    exit 1
fi
mv "$scratch/original-package.json" "$fixture/package.json"

# The old handcrafted one-line v9 lockfile is intentionally invalid.
cp "$fixture/pnpm-lock.yaml" "$scratch/original-pnpm-lock.yaml"
printf "lockfileVersion: '9.0'\n" > "$fixture/pnpm-lock.yaml"
badlock_rc=0
timeout 45 docker run "${common[@]}" --network none "$image" \
    sh -eu -c 'pnpm install --frozen-lockfile --offline < /dev/null' \
    < /dev/null > "$scratch/invalid-lock.log" 2>&1 || badlock_rc=$?
restore_host_access
if (( badlock_rc != 1 )) || ! grep -Eiq 'lockfile|frozen|outdated' "$scratch/invalid-lock.log"; then
    echo "::error::Invalid pnpm lock negative failed (status=${badlock_rc})"
    sed -n '1,20p' "$scratch/invalid-lock.log"
    exit 1
fi
mv "$scratch/original-pnpm-lock.yaml" "$fixture/pnpm-lock.yaml"

echo "::notice::pnpm ${pin}: cold bootstrap, offline frozen lock, mismatch and invalid-lock negatives passed."
