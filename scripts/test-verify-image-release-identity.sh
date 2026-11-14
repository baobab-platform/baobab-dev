#!/usr/bin/env bash
# DEV-10 PR #71/#74 regression: release identity and prerelease-family boundaries.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/cosign" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >> "$COSIGN_CALL_LOG"
MOCK
chmod +x "$tmp/cosign"
export PATH="$tmp:$PATH" COSIGN_CALL_LOG="$tmp/calls"
check_pass() {
  local image="$1" tag="$2" expected="$3"
  : > "$COSIGN_CALL_LOG"
  if [[ -z "$tag" ]]; then
    "$ROOT/scripts/verify-image.sh" "$image" > "$tmp/out" 2>&1
  else
    "$ROOT/scripts/verify-image.sh" "$image" "$tag" > "$tmp/out" 2>&1
  fi
  [[ "$(wc -l < "$COSIGN_CALL_LOG")" -eq 3 ]] || { cat "$tmp/out"; return 1; }
  [[ "$(grep -Fc -- "--certificate-identity https://github.com/baobab-platform/baobab-dev/.github/workflows/publish.yml@refs/tags/$expected" "$COSIGN_CALL_LOG")" -eq 3 ]] || { cat "$COSIGN_CALL_LOG"; return 1; }
  grep -q -- '--type slsaprovenance1' "$COSIGN_CALL_LOG"
  grep -q -- '--type spdxjson' "$COSIGN_CALL_LOG"
}
check_fail() {
  : > "$COSIGN_CALL_LOG"
  if "$ROOT/scripts/verify-image.sh" "$@" > "$tmp/out" 2>&1; then
    echo "unexpectedly accepted: $*" >&2; return 1
  fi
  [[ ! -s "$COSIGN_CALL_LOG" ]] || { echo "invalid release reached cosign: $*" >&2; return 1; }
}
check_pass 'ghcr.io/baobab-platform/baobab-dev:v1.5.2-rc.1' '' 'v1.5.2-rc.1'
check_pass 'ghcr.io/baobab-platform/baobab-dev:v1.5.1-rc.2' '' 'v1.5.1-rc.2'
check_pass 'ghcr.io/baobab-platform/baobab-dev:v1.5.0-rc.9' '' 'v1.5.0-rc.9'
check_pass 'ghcr.io/baobab-platform/baobab-dev@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'v1.5.2-rc.3' 'v1.5.2-rc.3'
check_pass 'ghcr.io/baobab-platform/baobab-dev:v1.5.2' '' 'v1.5.2'
check_fail 'ghcr.io/baobab-platform/baobab-dev:v1.5.3-rc.1'
check_fail 'ghcr.io/baobab-platform/baobab-dev:v1.5.2-rc.0'
check_fail 'ghcr.io/baobab-platform/baobab-dev:v1.5.2-rc.01'
check_fail 'ghcr.io/baobab-platform/baobab-dev:v1.5.2-beta.1'
check_fail 'ghcr.io/baobab-platform/baobab-dev@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
echo 'DEV-10 release identity regressions passed'
