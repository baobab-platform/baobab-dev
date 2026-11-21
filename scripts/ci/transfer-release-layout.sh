#!/usr/bin/env bash
# Publish one already-qualified OCI index, preserving its exact bytes.
set -euo pipefail
target="${1:?release profile required}"
architecture="${2:?architecture required}"
layout="${RUNNER_TEMP:?runner temporary directory required}/release-layout"
image="${REGISTRY:?registry required}/${IMAGE_NAME:?image repository required}"
digest=$(python3 scripts/attested_release_layout.py readback --layout "$layout" \
    --target "$target" --architecture "$architecture" --source "${GITHUB_SHA:?source SHA required}" \
    --lock "$(sha256sum config/versions.lock | cut -d ' ' -f1)")
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "$(crane push "$layout" "$image@$digest")" == "$image@$digest" ]]
[[ "$(crane digest "$image@$digest")" == "$digest" ]]
mkdir -p "$RUNNER_TEMP/digests"
touch "$RUNNER_TEMP/digests/${digest#sha256:}"
rm -rf -- "$layout"
