# DEV-10 — Exact signer identity for digest-reused GA releases

**Status:** Implemented on PR #74; final hosted CI and live registry re-verification remain required.

## Why GA and signer tags differ

DEV-10 GA promotion reuses the four image digests from one successfully qualified release candidate. It does not rebuild or re-sign those image bytes. Consequently, the Cosign certificate identity on each digest remains the exact GitHub Actions workflow identity that signed the RC:

`https://github.com/baobab-platform/baobab-dev/.github/workflows/publish.yml@refs/tags/vMAJOR.MINOR.PATCH-rc.N`

The later GA tag is a new Git reference to the same source commit and image digests; it is not the signer identity. Verifying a reused RC digest against the GA tag's certificate identity is incorrect and produces a genuine certificate SAN mismatch.

## Controls

- `prepare_ga_reuse.py` retains the exact qualified RC tag and workflow run ID in every GA image record.
- `verify_release_artifact_contract.py` requires all four GA records to contain one identical, same-version RC signer tag and positive run ID. RC records retain their smaller three-field schema.
- The generated GitHub Release body prints the signer source tag and qualified RC run, and its Cosign examples use that exact identity.
- The read-only registry observer independently resolves the stable release tag to a commit, lists same-version RC tags, dereferences lightweight or annotated tag objects, and requires exactly one RC tag to resolve to the same commit. Server-enforced protection against tag update/deletion remains a separate GitHub ruleset requirement and was not independently verified here. Zero or multiple matches fail closed. It then reads the actual GitHub Actions workflow-run API record and requires a completed successful `push` run for that exact tag, source SHA and `.github/workflows/publish.yml`; GA release metadata run IDs are checked against the API response.
- `verify-image.sh` and `verify_registry_arch_attestations.py` then verify the exact RC certificate identity and GitHub Actions OIDC issuer. The latter also checks both native image revision labels against the GA source SHA and compares the signed SLSA/SPDX predicates with the embedded BuildKit predicates.
- The signer is never selected by a broad certificate-identity regexp. Cross-version RCs, malformed tags, ambiguous RC tags, mismatched source SHAs, wrong OIDC issuers and mismatched signed subjects remain denied.

## Evidence boundary

Unit tests cover RC self-signing, same-version GA-to-RC signer resolution, annotated/lightweight tag resolution policy, ambiguity and mismatch negatives, and dual-architecture signed-content verification. These tests do not prove that the live GHCR digests or GitHub tag refs are currently available. The updated `Verify Released GHCR Contracts` workflow must pass against the actual v1.5.1 GA release and subsequent release candidates before this change is accepted.

This correction does not authorise a new release tag, image publication, CVE exception, promotion, or consumer upgrade. Those remain subject to their independent security and protected-environment gates.
