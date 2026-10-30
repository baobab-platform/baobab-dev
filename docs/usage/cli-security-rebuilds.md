# Security rebuilds of adopted CLI releases

The image rebuilds Task 3.54.0, yq 4.54.1, Buildx 0.38.1 and Compose 5.6.1 from their checksum-pinned upstream
source archives. Task/yq application versions remain those in `config/versions.lock`; Docker plugin
versions are guarded against the installed apt packages. The build fails if those versions change without
re-evaluating this override. Upstream binary checksums remain in that lock for
historical provenance; these image executables now come from the separate
`patched-go-clis` stage.

This isolated builder uses Go 1.27.3 and the committed module graphs under
`config/security/{task,yq,buildx,compose}` with `golang.org/x/net v0.60.0`
and patched JOSE v4.1.6 wherever that module is present. It addresses the
Go standard-library and HTTP/2 findings in image run 40866955151. It does not
change any consuming project's adopted Go version. Both compiler architectures
and source archives have explicit SHA-256 checks. Dependency resolution uses
the Go checksum database, committed sums, readonly build mode and graph drift
checks. Build information is retained beside the builder's binaries.

On 2026-10-29, both complete upstream `go test ./...` suites passed locally
with the x/net-patched graphs and Go 1.27.3 on Linux amd64. The subsequent JOSE
patch is requalified by the build tests. Buildx/Compose compile locally and pass
version/config smoke checks; selected package tests run during the build. The image build also checks
embedded compiler/dependency versions and executes real Taskfile and YAML
transform smoke cases. This is candidate component evidence, not Codespaces,
multi-architecture image or programme acceptance.

Full image security qualification remains held until every finding is resolved.
The same recorded scan also found urllib3 2.7.0
vendored by pip 26.2.2; the system/Poetry urllib3 constraints do not patch pip's
vendored source. No suppression is added or extended by this override.

Remove each source override when an adopted upstream binary passes the same
security checks. Reverting the override restores known-vulnerable binaries and
must not be treated as a qualified developer-image rollback.

The `go.mod.lock`/`go.sum` files are inputs for downloaded source trees,
not standalone Go projects. The Security workflow materialises them in a
throwaway audit directory and scans every dependency without ignore rules.
The image builder copies them into their upstream source trees, runs real
source tests and refuses lock drift. This keeps dependency coverage explicit
without pretending a directory containing only locks has runnable Go packages.

Buildx imports the legacy Docker Engine module only for its frozen name generator.
The security builder verifies and copies that exact source file from the pinned
upstream archive into an internal package, changes the one import, and preserves
its Apache licence in the resulting image. The legacy engine dependency is removed
from the committed graph. An added test exercises generation, validation, native
store writes and readback through a real store transaction; existing store tests
also run. This is source dependency removal, not a vulnerability suppression.

The upstream Task `TestParams` golden output is line-sorted even though its
three dependencies write concurrently. Run 40912583068 demonstrated two messages
interleaving within a line. The explicit `params-test.patch` serialises only that
parameter-substitution test. Its assertions and expected output remain unchanged;
all other concurrency tests still run. No production Task code is patched.
