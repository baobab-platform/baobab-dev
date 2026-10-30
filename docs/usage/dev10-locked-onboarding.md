# DEV-10 locked onboarding

The repository lifecycle uses its committed lockfile. A uv project runs
`uv sync --locked --no-managed-python`; a Poetry project checks its committed
lock before installation. Ambiguous or missing Python locks fail. Requirements
files require hashes and use `uv pip sync`. Missing required tools fail instead
of reporting successful onboarding.

Root and `frontend/` JavaScript projects use the same selection. Exactly one
lockfile is required, pnpm/Yarn must match an exact `packageManager`, and installs
are frozen/immutable. npm uses `npm ci`, with no unlocked fallback after a failed
install. An exact `.node-version`, when supplied, is checked against the actual
Node executable. Corepack download prompts are disabled for every stage.

Per-repository Node and package-manager pins remain repository-owned. The image
provides a Node major baseline and a resolved pnpm version; it does not silently
rewrite project pins. Shared's existing Codespaces private-package bootstrap
owns its user credential probe and authenticated frozen install. A successful
Actions GHCR login is not evidence that a new user's Codespace can read packages.
Never put tokens into source, image build arguments, `.env` or shell tracing.

The DEV-10 workflow executes this checkout's actual post-create script and locked
uv dependencies inside the published 1.4.4 image as its native vscode user, on an owned copy
of a read-only source mount. A raw host UID without passwd/cache remapping is
not treated as a valid Dev Container. It records
the resolved image digest in the job log. Mock-CLI regressions separately prove
that failures cannot fall back to an unlocked install. This is container/CLI
evidence; it is not an observed fresh hosted Codespace or fleet-wide adoption.

No image version or toolchain pin changes in this increment. Existing published
images retain their baked scripts until a reviewed release. Consumers that call
the image's `baobab-post-create` need that release/adoption; the repository's own
Dev Container calls the checked-out script directly.

For an upgrade, test the candidate image by immutable digest across every affected
consumer's actual supported language/test commands before changing their pins.
Java 21 consumers need their declared additional JDK; the image's Java 17 does not
satisfy them. Go and Rust consumers need their pinned repository toolchain/features.
The PostgreSQL 17 client is not a server migration or permission to mount an old
physical database volume. Qualify server migration/restore independently.

Rollback restores the prior reviewed image digest, repository toolchain files and
lockfiles together, rebuilds the disposable workspace and reruns frozen installation.
Do not delete a consumer's database or reuse a PostgreSQL physical volume across
major versions to make a tooling test pass. Revoke only run-owned credentials and
remove run-owned resources; keep prior receipts and native database restore plans.

The container shell enables errexit before both onboarding and tests. A separate
fault-injection run forces the final verifier to exit 42 and requires that exact
container exit status; passing tests cannot mask a failed lifecycle. The fresh
pnpm workspace fixture proves a frontend member uses its actual root frozen lock.

### 29 October image dependency remediation

The final-image jobs in runs `40360334198` and `40360515417` failed on
CVE-2026-97687 / CVE-2026-97689 in urllib3 2.7.0, on both architectures.
`config/python-build-constraints.txt` now constrains image-tool dependency
resolution to urllib3 2.8.0 in both system pipx and Poetry's isolated environment.
The build checks dependency compatibility and reads back both installed versions;
a resolver conflict fails the build. This constraint is scoped to image creation
and does not override a consuming project's frozen dependency lock.

The original failed runs remain historical evidence. A source test or successful
install does not qualify the image: fresh final-head amd64/arm64 scans, all existing
required checks and developer-environment evidence remain required. No scan
exception or expiry was added or extended by this remediation. Do not release,
publish a new version or promote a consumer digest on the strength of this source
change. Roll back only to a previously qualified digest; an image with the original
finding is not a security rollback target.

### 30 October final-head security remediation (PR #48)

Latest pre-fix head `e68c5691` passed DEV-10 source/published-image onboarding
and the Security workflow, but blocked Foundation and Publish Trivy image gates.
Both infra architectures identified Terraform 1.16.7 embedding
`github.com/go-jose/go-jose/v4@v4.1.4` (CVE-2026-116587); both full
architectures identified Maven's Guava 33.6.0-jre (CVE-2026-102554) and pip's
internally vendored msgpack 1.1.2 (CVE-2026-114613 /
GHSA-6v7p-g79w-8964) and setuptools 70.3.0 (CVE-2025-47273).
This is observed scan evidence, not an inference from upstream release notes.

The fixes deliberately preserve the Python 3.14 / Node 24 / PostgreSQL 17
project baselines and frozen onboarding behavior:

- Terraform upgrades to vendor release 1.17.1 on the infra profile, with
  its amd64/arm64 SHA-256 digests pinned from HashiCorp's official
  `hashicorp/homebrew-tap` formula. Its upstream source now requires
  go-jose v4.1.6; replacing an older binary in-place without validating the
  embedded module would *not* be a security fix. Infra consumers must still
  verify compatibility with 1.17 before adopting a new image digest.
- Maven remains on reviewed 3.9.16 for ERP compatibility. The full profile
  replaces only its original Guava JAR with Maven Central 33.7.2-jre
  (SHA-256 `b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c`).
  The old JAR must exist exactly once; the replacement is digest-checked,
  the old copy removed and `mvn --version` exercised. If the upstream
  Maven layout changes, the build fails instead of guessing a path.
- The pinned pip source's vendoring manifest is updated through its
  **actual vendoring tool** to msgpack 1.2.3 and setuptools 78.1.1,
  alongside the existing urllib3 2.8.0 remediation. The isolated wheel
  build asserts all three actual vendored imports before installing into
  the final system and pipx-shared environments.

No CVE exceptions were introduced or extended; previously retired rules
remain retired. These source changes are candidate remediations, **not**
clearance: merge and image promotion remain HELD until the *new* final-head
Foundation scan, all eight Publish platform/profile combinations, DEV-10
real image onboarding, required security/CI gates and independent
Codespaces/consumer qualification pass. PR #50's DEV-14 doctor is a separate
non-mutating assurance surface and cannot confer that evidence.
