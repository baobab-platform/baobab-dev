#!/usr/bin/env bash
# Rebuild upstream gh/cosign from exact reviewed Git commit trees, with the
# fixed x/net module. No vulnerable release binary is copied into the image.
set -euo pipefail
export PATH="/build/go/bin:$PATH" GOTOOLCHAIN=local CGO_ENABLED=0
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
go version | grep -F 'go1.27.3'
mkdir -p /out
for tool in gh cosign; do
  case "$tool" in
    gh)
      repo=https://github.com/cli/cli.git
      commit=89d7dcec017194af1d6f8853176b2dae9c1da762
      package=./cmd/gh ;;
    cosign)
      repo=https://github.com/sigstore/cosign.git
      commit=0e48502cf5ef34e2e60bbd3617aa19945712f705
      package=./cmd/cosign ;;
  esac
  dest="/build/upstream-$tool"
  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$repo"
  git -C "$dest" fetch --depth 1 origin "$commit"
  git -C "$dest" checkout --detach -q FETCH_HEAD
  [[ "$(git -C "$dest" rev-parse HEAD)" == "$commit" ]] || {
    echo "::error::Upstream $tool source commit mismatch" >&2; exit 1;
  }
  cd "$dest"
  # Upstream released binaries embed x/net 0.60.0/0.61.0 respectively.
  # Resolve and verify the fixed graph against the Go checksum database.
  go get golang.org/x/net@v0.62.0
  go mod tidy
  go mod verify
  selected="$(go list -m -f '{{.Version}}' golang.org/x/net)"
  [[ "$selected" == "v0.62.0" ]] || {
    echo "::error::$tool selected x/net $selected, not v0.62.0" >&2; exit 1;
  }
  go build -trimpath -buildvcs=false -ldflags="-s -w" -o "/out/$tool" "$package"
  go version -m "/out/$tool" | tee "/out/$tool.buildinfo"
  grep -E 'golang.org/x/net[[:space:]]+v0.62.0[[:space:]]' "/out/$tool.buildinfo"
  "/out/$tool" version > "/out/$tool.version" 2>&1 || {
    # Some upstream CLIs use --version rather than the version subcommand.
    "/out/$tool" --version > "/out/$tool.version"
  }
done
