#!/usr/bin/env bash
# Build security-only variants of adopted releases, without floating resolution.
set -euo pipefail
arch=${1:?target architecture required}
case "$arch" in
  amd64) compiler_sha=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
  arm64) compiler_sha=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
  *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac
. /build/versions.lock
[[ "$TASK_VERSION" == 3.54.0 && "$YQ_VERSION" == 4.54.1 ]] || {
  echo 'Re-evaluate security rebuild when adopted releases change' >&2; exit 1;
}
fetch() {
  curl -fsSL --retry 5 --retry-all-errors "$1" -o "$2"
  printf '%s  %s\n' "$3" "$2" | sha256sum --check --strict
}
fetch "https://go.dev/dl/go1.27.3.linux-${arch}.tar.gz" /build/go.tar.gz "$compiler_sha"
tar -xzf /build/go.tar.gz -C /build
export PATH="/build/go/bin:$PATH" GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=readonly
mkdir -p /out
for tool in task yq buildx compose; do
  ldflags="-s -w"
  binary=$tool
  case "$tool" in
    task)
      repo=go-task/task; version=$TASK_VERSION
      sha=a423e352dc97095a2bf8cd29e24588cf156a45eb122a6add089af762ef0928e7
      package=./cmd/task ;;
    yq)
      repo=mikefarah/yq; version=$YQ_VERSION
      sha=ddbc126be37271341e795dddd3cad96ea16935050be5081c999faf16d3ffca6c
      package=. ;;
    buildx)
      repo=docker/buildx; version=0.38.1; binary=docker-buildx
      sha=381a978d0608c94b0ff6eda31aee7142186e286c6f0c52537f304035af87b95f
      package=./cmd/buildx
      ldflags="$ldflags -X github.com/docker/buildx/version.Version=v$version" ;;
    compose)
      repo=docker/compose; version=5.6.1; binary=docker-compose
      sha=14c1095f739c782d471680ef994d4119bd40239fbcc75dfe01b1ebee363771a3
      package=./cmd
      ldflags="$ldflags -X github.com/docker/compose/v5/internal.Version=v$version" ;;
  esac
  fetch "https://api.github.com/repos/${repo}/tarball/v${version}" "/build/${tool}.tar.gz" "$sha"
  mkdir -p "/build/$tool"
  tar -xzf "/build/${tool}.tar.gz" -C "/build/$tool" --strip-components=1
  cp "/build/security/$tool/go.mod.lock" "/build/$tool/go.mod"
  cp "/build/security/$tool/go.sum" "/build/$tool/go.sum"
  cd "/build/$tool"
  go mod download
  go mod verify
  case "$tool" in
    task|yq) go test ./... ;;
    buildx) go test ./version ./util/buildflags ;;
    compose) go test ./pkg/api ./pkg/utils ;;
  esac
  go build -trimpath -buildvcs=false -ldflags="$ldflags" -o "/out/$binary" "$package"
  go version -m "/out/$binary" | tee "/out/${tool}.buildinfo"
  grep -F 'go1.27.3' "/out/${tool}.buildinfo"
  grep -E 'golang.org/x/net[[:space:]]+v0.60.0[[:space:]]' "/out/${tool}.buildinfo"
  cmp go.mod "/build/security/$tool/go.mod.lock"
  cmp go.sum "/build/security/$tool/go.sum"
done
/out/task --version | grep -F '3.54.0'
/out/yq --version | grep -F '4.54.1'
[[ "$(printf 'a: 2\n' | /out/yq '.a + 3')" == 5 ]]
mkdir -p /build/smoke
printf 'version: "3"\ntasks:\n  default:\n    cmds:\n      - echo security-rebuild-ok\n' > /build/smoke/Taskfile.yml
/out/task --dir /build/smoke --silent | grep -Fx security-rebuild-ok

/out/docker-buildx version | grep -F 'v0.38.1'
/out/docker-compose version | grep -F 'v5.6.1'
printf 'services:
  smoke:
    image: busybox:1.37.0
' > /build/smoke/compose.yaml
/out/docker-compose -f /build/smoke/compose.yaml config --services | grep -Fx smoke
