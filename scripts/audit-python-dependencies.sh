#!/usr/bin/env bash
# Independent Python advisory audit. Inputs are committed locks or installed
# distribution metadata, never Trivy's vulnerability findings.
set -euo pipefail
export UV_NO_PROGRESS=1 CI=true
PIP_AUDIT_VERSION=2.10.1

audit() {
  # Pin the auditor release; uvx resolves its isolated tool environment.
  # Advisory database responses are live and must never be silently ignored.
  uvx --from "pip-audit==${PIP_AUDIT_VERSION}" pip-audit --progress-spinner off "$@"
}

case "${1:-}" in
  --source)
    command -v uv >/dev/null || { echo "Missing pinned uv" >&2; exit 1; }
    command -v uvx >/dev/null || { echo "Missing pinned uvx" >&2; exit 1; }
    test -f uv.lock && test -f pyproject.toml
    test -f config/security/pip-vendoring-requirements.txt
    test -f config/python-build-constraints.txt
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    echo "Auditing committed uv.lock (all declared dependency groups)"
    uv export --locked --all-groups --no-emit-project \
      --format requirements-txt --output-file "$tmp/uv-requirements.txt"
    grep -q '^.*==.*--hash=sha256:' "$tmp/uv-requirements.txt" || {
      echo "Locked uv export lacks hashed pinned dependencies" >&2; exit 1;
    }
    audit --require-hashes --no-deps -r "$tmp/uv-requirements.txt"
    echo "Auditing the hash-pinned Python vendoring builder requirements"
    audit --require-hashes --no-deps -r config/security/pip-vendoring-requirements.txt
    echo "Auditing explicit Python image-tool constraints"
    audit --no-deps -r config/python-build-constraints.txt
    ;;
  --installed)
    command -v uvx >/dev/null || { echo "Missing pinned uvx" >&2; exit 1; }
    # Final image: system interpreter and both pipx environments. A package
    # path is included only if it contains installed distribution metadata.
    # The expected environments MUST be present or this check fails closed.
    shopt -s nullglob
    roots=(/usr/local/lib/python*/dist-packages
           /usr/local/lib/python*/site-packages
           /usr/lib/python3/dist-packages
           /opt/pipx/shared/lib/python*/site-packages
           /opt/pipx/venvs/*/lib/python*/site-packages)
    audited=0
    found_system=0
    found_shared=0
    found_poetry=0
    for root in "${roots[@]}"; do
      test -d "$root" || continue
      metadata=("$root"/*.dist-info "$root"/*.egg-info)
      test "${#metadata[@]}" -gt 0 || continue
      case "$root" in
        /usr/local/lib/*) found_system=1 ;;
        /opt/pipx/shared/*) found_shared=1 ;;
        /opt/pipx/venvs/poetry/*) found_poetry=1 ;;
      esac
      echo "Auditing installed Python distributions in $root"
      audit --disable-pip --path "$root"
      audited=$((audited + 1))
    done
    test "$audited" -gt 0 && test "$found_system" -eq 1 &&
      test "$found_shared" -eq 1 && test "$found_poetry" -eq 1 || {
      echo "Required image Python environments not fully enumerated" >&2
      exit 1
    }
    ;;
  *)
    echo "Usage: $0 --source|--installed" >&2
    exit 2
    ;;
esac
