# DEV-10 foundation policy proposal — independent review brief

**Decision state: PENDING. This record is not an active exception and grants no CI, merge, tag, publication, or promotion authority.**

Machine-readable proposal: [`security/decisions/foundation.json`](../../security/decisions/foundation.json)

## Evidence-backed finding inventory

The retained Actions artifact `13962922393` (run `43257311010`) contains a Trivy 0.73.0 report with eight HIGH findings for Ubuntu `linux-libc-dev=7.0.0-43.43`:

| CVE | Installed version | Severity | Trivy fixed version |
|---|---|---|---|
| CVE-2022-50240 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2025-40190 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2026-68103 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2026-72198 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2026-74578 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2026-89805 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2026-98376 | 7.0.0-43.43 | HIGH | Not reported |
| CVE-2026-98420 | 7.0.0-43.43 | HIGH | Not reported |

The report also contains two HIGH `golang.org/x/net` findings in the separately downloaded `gh` and `cosign` binaries. Their installed versions are `v0.60.0` and `v0.61.0`, respectively, and Trivy reports fixed version `0.62.0` for both. They are intentionally excluded from this proposal. The current evaluator rejects a finding with a fixed-version signal; remediate these binaries and rescan rather than include them in a residual-risk exception.

## Evidence limitations

- The retained scan is from PR #62, source commit `6e531c042fd413d0075906398afe8900df6fe049`, not PR #74.
- It covers only profile `final` on `linux/amd64`.
- Its Trivy JSON has no `Metadata.RepoDigests` entry. The `ArtifactID` is not a substitute for the exact GHCR child-manifest digest required by the evaluator.
- Consequently, this artifact supports the eight-finding inventory only. It does not qualify a PR #74 artifact or establish the proposed four-profile/two-architecture scope.
- Report SHA-256: `7755fb395c57ae16894a838e58a8125f13f2727a6312353350d939e56dfad199`.
- Normalized finding evidence SHA-256: `235b13a805d8cb5b749d1d557c88052977e8458897d361338bbad167e2916d35`.

## Approval-scope reconciliation

The available record does not establish an approval for PR #74:

1. The 12 November issue #54 owner comment records a development-only approval for PR #62 and a 14-day renewal. It does not name PR #74.
2. The risk register records the eight-finding `7.0.0-43.43` amendment as PR #62-only.
3. The executable legacy gate later names PR #71 for the additional package/CVE set, but PR #71's own description concerns v1.5.1 RC exact-digest signature verification and does not document that risk acceptance.
4. The 14 November issue #54 comments explicitly describe PR #74 as release-preparation review scope only, with no CVE exception or tag permission.

The #62/#71 custody discrepancy must be reconciled by the accountable owner and independent security reviewer. No approval is inferred from code, a PR description, or a chat identity.

## Scope and expiry submitted for decision

The JSON records a **proposal only** for PR #74's `pull_request` event and `refs/pull/74/merge`, development environment, four image profiles and two Linux architectures. It expressly excludes main, tags, release publication, protected promotion, staging and production.

The proposed expiry `2026-11-26T00:00:00Z` is a review deadline suggestion, not an inherited extension of PR #62's decision. Reviewers must affirm or replace both the scope and expiry. Root-level approved `profiles` and `architectures` remain empty until that decision is made.

## Validation and activation boundary

The eight finding objects pass the evaluator's finding-identity requirements: valid CVE identifier, package, installed version, HIGH severity, and Trivy result type `ubuntu`; identities are unique.

The proposal intentionally remains `pending_independent_review`, with approval and activation fields null and no approved profiles or architectures. It is therefore **not expected to pass the active evaluator**. The active evaluator requires `status=approved`, authenticated approval custody, valid approval/expiry timestamps, non-empty approved scope, and exact policy bytes matching a separately provisioned SHA-256 trust anchor. The retained scan also fails the evaluator's exact GHCR digest binding requirement.

After the owner and independent reviewer decide, engineering must obtain fresh exact-digest scan evidence, finalize the approved JSON, merge it through the protected decision process, calculate SHA-256 over those final bytes, and have the designated custodian provision that exact hash. Any subsequent byte change requires a new review and hash. Release authorization remains separate.
