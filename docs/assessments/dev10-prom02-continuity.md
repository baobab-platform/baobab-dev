# DEV-10 PROM-02 — protected release continuity

## GA enforcement

The protected `promote` job checks `DEV10_QUALIFIED_RC_RUN_ID` before any
GHCR tag mutation. It independently fetches the selected GitHub Actions run,
requires a successful completed tag-push execution of `publish.yml` at the
same commit, downloads its four immutable published-info artifacts, and
compares every OCI digest with the GA run's four candidate records.

A missing run, expired artifact, changed digest, incomplete profile, changed
source, unsupported tag family, or failed RC run refuses promotion. The
resulting evidence is uploaded in the existing promotion journal artifact.

**Critical:** The current GA workflow still builds its own images. Rebuilding
the same source does not guarantee byte-identical OCI digests. This gate
therefore correctly refuses GA when rebuilt images differ. The next release
architecture improvement is to promote the exact qualified RC digests as
GA versioned tags rather than rebuild, retaining the existing signature,
attestation and provenance verification. Until implemented, no claim of
seamless RC-to-GA adoption is justified.

RC published-info artifacts now retain for 30 days (previously one day).
Only a completed, successful RC run should be configured in the repository
variable; setting the variable does not bypass the protected environment.
This gate is additive to existing signatures, security scans, and independent
review. It does not extend time-limited v1.5.0 CVE risk acceptance.

## Platform adoption

Reuse the contract across repositories by parameterising: image registry,
profile inventory, release channel, protected environment, source provenance,
qualification evidence and allowed mutable aliases. Staging/production
deployment should use *separate* independently reviewed environments and
deployment attestations; image publication approval is not production
deployment approval. Never let dev-only risk exceptions cross environments.
