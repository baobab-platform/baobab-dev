#!/usr/bin/env bash
# DEV-10: resilience for transient Go module proxy HTTP/2 stream resets.
#
# Only wraps the network download. The caller retains its exact go.mod.lock,
# go.sum, GOFLAGS=-mod=readonly, go mod verify, tests and binary buildinfo
# checks. No GOPROXY=direct fallback, disabled checksum DB or floating update.
# Failure after four bounded attempts remains a fatal Docker build failure.
set -Eeuo pipefail
[[ $# -eq 0 ]] || { echo "usage: go-mod-download-retry.sh (no arguments)" >&2; exit 2; }
command -v go >/dev/null || { echo "Go toolchain missing" >&2; exit 2; }

for attempt in 1 2 3 4; do
  # Go documents this escape hatch for broken intermediary HTTP/2 streams.
  # It changes only the transport for this module fetch: HTTP/1.1 over TLS;
  # module versions and ordinary sumdb/hash verification stay unchanged.
  if GODEBUG=http2client=0 go mod download; then
    [[ $attempt -eq 1 ]] || echo "::notice::Go module download recovered on attempt ${attempt}/4"
    exit 0
  fi
  if (( attempt == 4 )); then
    echo "::error::Go module download failed after four attempts; refusing incomplete/unverified security CLI builds." >&2
    exit 1
  fi
  pause=$((attempt * 5))
  echo "::warning::Go module proxy download failed (attempt ${attempt}/4); retrying in ${pause}s with the same locked inputs." >&2
  sleep "$pause"
done
