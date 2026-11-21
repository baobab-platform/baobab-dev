#!/usr/bin/env bash
# Launch the actual reference configuration on a disposable Linux Docker host.
set -euo pipefail

config="$PWD/.devcontainer/devcontainer.json"
collector=scripts/ci/collect-development-host-evidence.py
mode="${1:?use --pull-reference or supply an output JSON path}"
scratch=$(mktemp -d)
workspace_id=
child_id=
local_ref=
cleanup() {
    if [[ "$child_id" =~ ^[a-f0-9]{64}$ ]]; then
        docker rm -f "$child_id" >/dev/null 2>&1 || true
    fi
    if [[ "$workspace_id" =~ ^[a-f0-9]{64}$ ]]; then
        docker rm -f "$workspace_id" >/dev/null 2>&1 || true
    fi
    if [[ -n "$local_ref" ]]; then
        docker image rm "$local_ref" >/dev/null 2>&1 || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT

unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS_VERIFY DOCKER_CERT_PATH
# The pinned image is the published reference declared by the source config.
base_image=$(sed -nE 's#^[[:space:]]*"image": "(ghcr\.io/baobab-platform/baobab-dev:[0-9.]+@sha256:[a-f0-9]{64})",?[[:space:]]*$#\1#p' "$config")
[[ "$base_image" =~ ^ghcr\.io/baobab-platform/baobab-dev:[0-9.]+@sha256:[a-f0-9]{64}$ ]]
if [[ "$mode" == --pull-reference ]]; then
    mkdir -m 700 "$scratch/registry"
    printf '%s' "${GHCR_READ_TOKEN:?read-only GHCR token required}" | docker --config "$scratch/registry" \
        login ghcr.io --username "$GITHUB_ACTOR" --password-stdin >/dev/null
    docker --config "$scratch/registry" pull "$base_image"
    exit 0
fi

# Use the verified local image for provisioning. The pull step's credential
# directory and environment are gone before any workspace process starts.
base_id=$(docker image inspect --format '{{.Id}}' "$base_image")
[[ "$base_id" =~ ^sha256:[a-f0-9]{64}$ ]]
local_ref="baobab-dev10-host-reference:${scratch##*/}"
docker tag "$base_id" "$local_ref"
python3 - "$config" "$scratch/config.json" "$base_image" "$local_ref" <<'PY'
from pathlib import Path
import sys

source, destination, reference, local_reference = sys.argv[1:]
config = Path(source).read_text(encoding="utf-8")
assert config.count(f'"{reference}"') == 1
Path(destination).write_text(config.replace(f'"{reference}"', f'"{local_reference}"'), encoding="utf-8")
PY

registry=https://registry.npmjs.org/@devcontainers/cli/-/cli-0.91.0.tgz
checksum=2abaefab0a4e0ef11a9098685f079a024a0c1b7f8d66295ba13e1ee124137fa7715572de8b22c32aea6712d50c6957b51495c73b86267bb4d38eac6c9123ae72
curl -fsSL --retry 3 --max-time 50 "$registry" -o "$scratch/cli.tgz"
printf '%s  %s\n' "$checksum" "$scratch/cli.tgz" | sha512sum --check --strict
tar -xzf "$scratch/cli.tgz" -C "$scratch"
cli=(node "$scratch/package/devcontainer.js")
[[ "$("${cli[@]}" --version)" == 0.91.0 ]]

options=(--workspace-folder "$PWD" --config "$config" --log-level info
         --id-label "baobab.dev10.host-evidence=${scratch##*/}")
"${cli[@]}" up "${options[@]}" --override-config "$scratch/config.json" --skip-post-create > "$scratch/up.json"
workspace_id=$(jq -er '.containerId | select(test("^[a-f0-9]{64}$"))' "$scratch/up.json")
"${cli[@]}" exec "${options[@]}" python3 "$collector" namespace --workspace . > "$scratch/workspace.json"

child_args=()
if child_id=$("${cli[@]}" exec "${options[@]}" docker --host unix:///var/run/docker.sock run \
        --detach --pull=never --network none --read-only --no-healthcheck \
        --entrypoint /bin/sleep "$base_id" 240); then
    [[ "$child_id" =~ ^[a-f0-9]{64}$ ]]
    docker exec -i "$child_id" python3 - namespace < "$collector" > "$scratch/child.json"
    child_args=(--child-id "$child_id" --child-snapshot "$scratch/child.json")
else
    echo 'The workspace could not start the ordinary Docker child. The receipt records host and workspace observations.'
fi

python3 "$collector" host --workspace "$PWD" --workspace-id "$workspace_id" \
    --workspace-snapshot "$scratch/workspace.json" --base-image "$base_image" \
    --base-image-id "$base_id" --config "$config" --source "$(git rev-parse HEAD)" "${child_args[@]}" > "$mode"
