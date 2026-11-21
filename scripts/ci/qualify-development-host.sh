#!/usr/bin/env bash
# Launch the actual reference configuration on a disposable Linux Docker host.
set -euo pipefail

config="$PWD/.devcontainer/devcontainer.json"
collector=scripts/ci/collect-development-host-evidence.py
output="${1:?output JSON required}"
scratch=$(mktemp -d)
workspace_id=
child_id=
cleanup() {
    if [[ "$child_id" =~ ^[a-f0-9]{64}$ ]]; then
        docker rm -f "$child_id" >/dev/null 2>&1 || true
    fi
    if [[ "$workspace_id" =~ ^[a-f0-9]{64}$ ]]; then
        docker rm -f "$workspace_id" >/dev/null 2>&1 || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT

unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS_VERIFY DOCKER_CERT_PATH
registry=https://registry.npmjs.org/@devcontainers/cli/-/cli-0.91.0.tgz
checksum=2abaefab0a4e0ef11a9098685f079a024a0c1b7f8d66295ba13e1ee124137fa7715572de8b22c32aea6712d50c6957b51495c73b86267bb4d38eac6c9123ae72
curl -fsSL --retry 3 --max-time 50 "$registry" -o "$scratch/cli.tgz"
printf '%s  %s\n' "$checksum" "$scratch/cli.tgz" | sha512sum --check --strict
tar -xzf "$scratch/cli.tgz" -C "$scratch"
cli=(node "$scratch/package/devcontainer.js")
[[ "$("${cli[@]}" --version)" == 0.91.0 ]]

# The pinned image is the published reference declared by the source config.
base_image=$(sed -nE 's#^[[:space:]]*"image": "(ghcr\.io/baobab-platform/baobab-dev:[0-9.]+@sha256:[a-f0-9]{64})",?[[:space:]]*$#\1#p' "$config")
[[ "$base_image" =~ ^ghcr\.io/baobab-platform/baobab-dev:[0-9.]+@sha256:[a-f0-9]{64}$ ]]
docker pull "$base_image"
base_id=$(docker image inspect --format '{{.Id}}' "$base_image")
[[ "$base_id" =~ ^sha256:[a-f0-9]{64}$ ]]

options=(--workspace-folder "$PWD" --config "$config" --log-level info
         --id-label "baobab.dev10.host-evidence=${scratch##*/}")
"${cli[@]}" up "${options[@]}" --skip-post-create > "$scratch/up.json"
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
    --config "$config" --source "$(git rev-parse HEAD)" "${child_args[@]}" > "$output"
