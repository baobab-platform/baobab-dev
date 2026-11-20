#!/usr/bin/env bash
# Shared checks for exact package installations in the Dockerfile.

verify_locked_apt_index() {
    local spec="${1:?exact APT package spec required}" expected_sha="${2-}"
    local metadata index_sha
    metadata=$(apt-cache show "$spec") || {
        echo "Locked APT package is unavailable: $spec" >&2
        return 1
    }
    index_sha=$(awk '/^SHA256: / {print $2}' <<< "$metadata" | sort -u)
    if [[ ! "$index_sha" =~ ^[0-9a-f]{64}$ || ( -n "$expected_sha" && "$index_sha" != "$expected_sha" ) ]]; then
        echo "Authenticated APT index identity differs from the locked package: $spec" >&2
        return 1
    fi
    printf 'Verified authenticated APT index entry %s %s\n' "$spec" "$index_sha"
}

verify_installed_apt_version() {
    local spec="${1:?exact APT package spec required}" actual
    actual=$(dpkg-query -W -f='${Version}' "${spec%%=*}") || return 1
    if [[ "$actual" != "${spec#*=}" ]]; then
        echo "Installed APT package differs from $spec: $actual" >&2
        return 1
    fi
}
