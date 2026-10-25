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
