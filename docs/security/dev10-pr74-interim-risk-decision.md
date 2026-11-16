# DEV-10 interim development-risk decision — PR #74 / v1.5.3 RC

**Status: DRAFT — NOT APPROVED; NOT ACTIVE IN CI**  
**Repository:** `baobab-platform/baobab-dev`  
**Candidate under consideration:** PR #74; proposed tag `v1.5.3-rc.1`  
**Decision class:** narrowly scoped internal-development residual-risk acceptance  
**Governing implementation:** `scripts/evaluate_protected_risk_decision.py` (schema version 2)

> This document records the evidence and unresolved authorization questions. It is not a risk acceptance, VEX statement, scanner suppression, merge approval, tag authorization, or release-promotion authorization. Do not use it as the protected policy JSON or provision its hash as a trust anchor.

## Superseding governance update — 16 November 2026

This earlier PR-specific draft is superseded as the preferred governance route. The platform owner has directed preparation of a reusable, PR-number-independent development policy with expiry **2026-11-26T00:00:00Z**, covering eligible pull requests targeting `main` and development-main push CI only. The policy is limited to the exact eight HIGH findings for `linux-libc-dev=7.0.0-43.43`, four profiles and two Linux architectures. It does not authorize tags, releases, manual dispatch, schedules, deployments, other PR base branches, staging or production.

The 12 November issue #54 decision names PR #62; no PR #71 approval was located. PR #74's scans remain inventory evidence, not approval. The proposal is pending independent review; no active `foundation.json`, trust-anchor value, PR #74 risk acceptance, v1.5.3 tag permission or release qualification is created by this document.

## 1. Decision requested

The decision owner is considering whether to permit the known `linux-libc-dev=7.0.0-43.43` findings to remain present in internal development images while PR #74 is merged and a v1.5.3 release candidate is qualified.

That would be a **new scope decision**. Existing records do not authorize PR #74 or v1.5.3:

- The 12 November record describes the 7.0.0-43.43 eight-CVE acceptance as applying to PR #62 and the v1.5.0 development-image release family.
- The executable legacy gate instead names PR #71 for the additional package-version scope.
- The 14 November PR #74 record explicitly limits PR #74 to assessment/review scope and does not grant a new CVE exception or release-tag permission.
- The policy document says the protected evaluator is not activated and the legacy Foundation/Publish gate remains authoritative.

The #62/#71 custody discrepancy must be reconciled before relying on the earlier decision. Neither PR #62 nor PR #71 is evidence of authorization for PR #74 or v1.5.3.

## 2. Evidence-backed finding inventory

The assessment register records eight HIGH Trivy findings for Ubuntu package `linux-libc-dev=7.0.0-43.43`, with no fixed version reported in the retained scan:

| CVE | Severity | Package | Installed version | Fixed version in recorded scan |
|---|---|---|---|---|
| CVE-2022-50240 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2025-40190 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2026-68103 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2026-72198 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2026-74578 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2026-89805 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2026-98376 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |
| CVE-2026-98420 | HIGH | linux-libc-dev | 7.0.0-43.43 | none reported |

**Evidence references:** assessment `docs/assessments/dev10-linux-libc-dev-risk-decision.md`, 12 November amendment; Foundation run [43271916377](https://github.com/baobab-platform/baobab-dev/actions/runs/43271916377); retained image scan artifact ID `13962922393`.

**Evidence still required before a policy decision can be instantiated:**

1. Retrieve the original retained Trivy JSON artifact and verify the eight observations, package type, installed version, severity, fixed-version fields and absence of secret findings.
2. Record the exact raw report SHA-256 and scanner version for the source scan. The protected evaluator requires Trivy `0.73.0` and evaluates each actual candidate's exact remote child-manifest digest, profile and architecture independently.
3. Re-scan the exact candidate GHCR child digests for each in-scope profile and architecture. A historical Foundation scan does not qualify a later RC digest.
4. Record sanitized evidence references. Do not commit raw secret-bearing scanner output.

The upstream 295-CVE path classification is supporting triage only. It is not Ubuntu patch-diff review, a VEX determination, or authorization to suppress findings.

## 3. Authorization scope — unresolved

The following must be decided explicitly by the owner and independently approved. The earlier v1.5.0 decision must not be silently extended.

| Dimension | Proposed value / status |
|---|---|
| Repository | `baobab-platform/baobab-dev` |
| Image repository | `ghcr.io/baobab-platform/baobab-dev` |
| Environment | `development` only |
| Package and version | `linux-libc-dev=7.0.0-43.43` only |
| Finding set | Exactly the eight CVEs in §2 |
| PR scope | **Unresolved.** Explicitly decide whether PR #74 is included; current record excludes it. |
| Tag scope | **Unresolved.** Explicitly decide whether `v1.5.3-rc.1` and subsequent RCs are included; current record only names v1.5.0 refs. |
| Profiles | Candidate scope may include `final`, `frontend`, `frontend-e2e`, `infra`; approve each explicitly. |
| Architectures | Candidate scope may include `linux/amd64`, `linux/arm64`; approve each explicitly. |
| Expiry | Must be a newly agreed UTC timestamp. The earlier 2026-11-26 expiry cannot be assumed to cover a new PR/tag scope. |
| Production / application deployment | Prohibited |
| GA promotion | Not authorized by this record |

A candidate policy may enumerate only profiles and architectures explicitly approved by the decision. The evaluator recognizes the four profile identifiers and two architecture identifiers above; it rejects empty or unknown scope.

## 4. Mandatory decision boundaries

If the owner and independent security approver authorize the scope, the decision may permit only the exact listed HIGH findings for the exact package version in the approved development context.

It must reject:

- Any additional or changed CVE, package, installed version, severity or ecosystem type.
- Any finding with a fixed-version signal.
- Any secret finding.
- Any scan with missing or malformed inventory, wrong Trivy version, wrong repository, wrong digest, profile or architecture.
- Any expired, revoked, unauthenticated or incorrectly scoped policy.
- Production use, application deployment, GA promotion, or an unapproved tag/PR.

No Trivy ignore, VEX `not_affected` assertion, legacy allow-list edit or release-control bypass is authorized by this draft.

## 5. Approval custody required by the implementation

The actual evaluator requires a schema-version-2 JSON decision with these fields:

- `schema_version: 2`
- `status: "approved"` and `revoked_at: null`
- `repository`, `image_repository`, `environment`
- non-empty, supported `profiles` and `architectures`
- non-empty `approval_id`
- distinct non-empty `prepared_by` and `approved_by`
- `approval_evidence` linking to the merged protected decision PR
- timezone-aware `approved_at` and `expires_at`, with approval currently valid
- non-empty `findings`, each containing `cve`, `package`, `version`, `severity`, and `type`

The finding identity is the tuple (CVE, package, installed version, severity, Trivy result type). Severity is restricted to HIGH or CRITICAL. Duplicate finding identities are rejected. The evaluator also verifies the exact policy bytes against the separately provisioned lowercase SHA-256 trust anchor.

The custody verifier additionally requires the decision PR to be merged into `main`, authored by the preparer, changed the selected decision file, and contain a current independent approval on its merged head by an independently provisioned trusted reviewer.

**Do not populate approval fields with placeholders or fabricated identities.** Until the owner scope and independent approval exist, this file remains a proposal and must not be converted to `status: "approved"`.

## 6. Decision attestations — pending

**Decision owner / preparer**
- GitHub login: [to be supplied]
- Explicit decision on PR #74 and v1.5.3 RC scope: [pending]
- Attestation timestamp (UTC): [pending]

**Independent security approver**
- GitHub login: [trusted, authorized reviewer]
- Approval reference: [merged protected decision PR]
- Approval timestamp (UTC): [pending]

**Custody**
- Approved JSON path: [to be selected under `security/decisions/`]
- Exact JSON SHA-256: [computed after approval content is final]
- Protected environment trust-anchor provisioning evidence: [pending]
- Ruleset / CODEOWNERS / reviewer permission verification: [pending]

## 7. Effectiveness

This draft has no authorization effect. The legacy Foundation and Publish gates remain authoritative. It becomes eligible for enforcement only after the exact inventory and scope are verified, an independent approval is merged through the protected review path, the exact policy hash is provisioned by the authorized custodian, and the live custody verifier and artifact evaluator pass.

Even then, it only permits the bounded development-risk evaluation. PR merge, RC publication, artifact qualification and promotion remain separate decisions.
