# GII-09 / GII-10 — live evidence and API cost

## GII-09 — Qualification protocol
The successful identity-resolution test must exercise a real authenticated read-only GraphQL/REST lookup against an immutable exact SHA, including a linked numeric committer. The historic GraphQL null-link case is **not** a permanent acceptance condition: when GitHub repairs that projection, the test must still prove numeric identity and fail-closed malformed/unauthorized responses. Pin the fixture SHA, expected raw metadata, REST linked account numeric ID, and source URL in a separately reviewed manifest; do not derive expected identity from the same response being tested.

Evidence required: GitHub API request IDs (sanitized), run ID, attempt, tested commit SHA, final PR head, exact reviewer review commit IDs, contributor count, complete pagination, and independent readback. A mocked response is unit evidence only. Live read-only queries are allowed; no protected provisioning or secret capture. A missing credential or 403 is **unverified**, not a pass.

## GII-10 — call budget and caching
Let C be commits and U be unlinked GraphQL committers. The baseline enumerator uses up to ceil(C/100) paginated GraphQL PR-history calls; each unlinked committer can incur one REST exact-SHA call. The local-range path also batches commit objects in groups of 20. No measured live U/C ratio or rate-limit counters are available, so no numerical savings are claimed.

**Approved design recommendation (not an implemented cache):** per-run in-memory cache keyed strictly by exact SHA plus verified raw committer metadata and immutable linked numeric User ID. A cache hit must recheck the current expected SHA and raw metadata. Never cache by email/name/login, never persist credentials, never allow a cached result to override a changed PR head, and never reuse across independent decision runs without fresh corroboration. Record actual request counts before enabling caching.

## Gate
GII-09 remains unqualified pending authenticated read-only live evidence. GII-10 performance optimization remains proposed; no change to custody enforcement or identity attribution.
