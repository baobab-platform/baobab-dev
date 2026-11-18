#!/usr/bin/env bash
# Execute locked onboarding against the exact immutable image supplied by CI.
# The checkout remains read-only; only consumer workspaces are writable.
set -euo pipefail

SRC_DIR=/source
PROJECT_DIR=/tmp/dev10-project
CONSUMER_DIR=/tmp/dev10-consumer
TOOLS_DIR=/tmp/dev10-tools

require_source() {
  [[ -f "$SRC_DIR/scripts/post-create.sh" && -x "$SRC_DIR/scripts/project-pnpm.sh" ]] || {
    echo "Reviewed source checkout is incomplete" >&2
    ls -la "$SRC_DIR/scripts" >&2 || true
    exit 2
  }
}

require_source
mkdir -p "$PROJECT_DIR" "$TOOLS_DIR"
cp -a "$SRC_DIR/." "$PROJECT_DIR/"
test -f "$PROJECT_DIR/scripts/post-create.sh"

# Compatibility wrappers let the newer reviewed checkout exercise the
# published 1.5.1 image without changing the image itself.
printf '%s\n' '#!/usr/bin/env bash' 'exec bash /source/scripts/summary.sh "$@"' > "$TOOLS_DIR/baobab-summary"
printf '%s\n' '#!/usr/bin/env bash' 'exec bash /source/scripts/verify.sh "$@"' > "$TOOLS_DIR/baobab-verify"
chmod +x "$TOOLS_DIR/baobab-summary" "$TOOLS_DIR/baobab-verify"

# Install the repository-pinned uv with an architecture-specific checksum.
mkdir -p /tmp/dev10-uv
case "$(uname -m)" in
  x86_64)
    uv_asset=uv-x86_64-unknown-linux-gnu.tar.gz
    uv_sha=a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5
    ;;
  aarch64)
    uv_asset=uv-aarch64-unknown-linux-gnu.tar.gz
    uv_sha=0797542018e541a9288855df555c8077eed06f7a47d206362030480e8ecc9f3d
    ;;
  *)
    echo "Unsupported onboarding architecture: $(uname -m)" >&2
    exit 2
    ;;
esac
curl -fsSL --retry 5 --retry-all-errors \
  "https://github.com/astral-sh/uv/releases/download/0.13.9/$uv_asset" \
  -o /tmp/dev10-uv/uv.tar.gz
echo "$uv_sha  /tmp/dev10-uv/uv.tar.gz" | sha256sum --check --strict
tar -xzf /tmp/dev10-uv/uv.tar.gz -C /tmp/dev10-uv
mapfile -t uv_bins < <(find /tmp/dev10-uv -type f -name uv -perm -u+x -print)
(( ${#uv_bins[@]} == 1 )) || {
  echo "Expected exactly one executable uv in verified archive" >&2
  exit 2
}
install "${uv_bins[0]}" "$TOOLS_DIR/uv"
uv_version="$("$TOOLS_DIR/uv" --version)"
[[ "$uv_version" == "uv 0.13.9"* ]] || {
  echo "Expected uv 0.13.9, got: $uv_version" >&2
  exit 2
}
export PATH="$TOOLS_DIR:$PATH"

# post-create.sh and its helper execute from the read-only reviewed checkout;
# WORKSPACE_DIR points only to the writable copy of the consumer project.
(
  cd "$PROJECT_DIR"
  WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/post-create.sh" --stage=post-create
)
python3 -B -m unittest discover -s "$PROJECT_DIR/tests" -v

# Exercise the published native pnpm and two exact project-pinned versions.
[[ "$(cd / && pnpm --version)" == "12.16.1" ]]
for pnpm_version in 12.16.1 11.24.0; do
  rm -rf "$CONSUMER_DIR"
  mkdir -p "$CONSUMER_DIR"
  cp -R "$SRC_DIR/tests/fixtures/pnpm-workspace/." "$CONSUMER_DIR/"
  mv "$CONSUMER_DIR/package.json.fixture" "$CONSUMER_DIR/package.json"
  mv "$CONSUMER_DIR/frontend/package.json.fixture" "$CONSUMER_DIR/frontend/package.json"
  cp -R "$SRC_DIR/config" "$CONSUMER_DIR/config"
  sed -i "s/pnpm@12[.]16[.]1/pnpm@${pnpm_version}/" "$CONSUMER_DIR/package.json"
  echo "Testing consumer packageManager pnpm@${pnpm_version}"
  (
    cd "$CONSUMER_DIR"
    WORKSPACE_DIR="$CONSUMER_DIR" bash "$SRC_DIR/scripts/post-create.sh" --stage=post-create
  )
  test ! -f "$CONSUMER_DIR/frontend/package-lock.json"
done

# Browser/runtime contract: the reviewed verifier must execute under the
# published non-root image user, including its browser/Playwright checks.
WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/verify.sh" --quiet
