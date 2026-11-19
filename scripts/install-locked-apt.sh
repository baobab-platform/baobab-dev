#!/usr/bin/env bash
# Install the exact package from the authenticated APT index.
set -euo pipefail
package="${1:?package name required}"
version="${2:?APT version required}"
expected_sha="${3-}"
shift 3

spec="${package}=${version}"
metadata=$(apt-cache show "$spec") || {
    echo "Locked APT package is unavailable: $spec" >&2
    exit 1
}
index_sha=$(awk '/^SHA256: / {print $2}' <<< "$metadata" | sort -u)
if [[ ! "$index_sha" =~ ^[0-9a-f]{64}$ || ( -n "$expected_sha" && "$index_sha" != "$expected_sha" ) ]]; then
    echo "Authenticated APT index identity differs from the locked package: $spec" >&2
    exit 1
fi

apt-get install -y --no-install-recommends "$spec" "$@"
actual=$(dpkg-query -W -f='${Version}' "$package")
[[ "$actual" == "$version" ]] || {
    echo "Installed APT package differs from $spec: $actual" >&2
    exit 1
}
printf 'APT package %s %s %s\n' "$package" "$actual" "$index_sha"
