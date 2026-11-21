# DEV-10 PR #74: scoped evidence handoff (engineering only)

## Authorization boundary

@sknabusiu's 2026-11-16 limited-scope review authorizes **engineering evidence
preparation only**. It is neither risk acceptance nor permission to merge,
tag, publish, promote, or extend the previous #71 acceptance. The only
candidate residual scope is eight HIGH findings for
`linux-libc-dev=7.0.0-43.43` in PR #74's development qualification.
If a fixed package exists, install it and rescan instead of seeking an
exception.

## Evidence collection and candidate preparation

1. Verify upstream Ubuntu package availability for the exact distro and
   architecture, record the source and time, and prefer remediation.
2. Build the intended final-head images. For each of the four profiles
   (`final`, `frontend`, `frontend-e2e`, `infra`) on both
   `linux/amd64` and `linux/arm64`, resolve the **child manifest digest**
   from GHCR. A local Docker tag, index digest, or unpushed image is not
   interchangeable with that child digest.
3. Run pinned Trivy 0.73.0 against each immutable
   `ghcr.io/baobab-platform/baobab-dev@sha256:...` child reference.
   Preserve the raw JSON in restricted evidence custody, and record the
   scanner/database provenance, DB timestamps, capture timestamp and
   image digest. Never upload raw secret-match material to public artifacts.
4. Prepare a local JSON manifest with `scans`, containing exactly eight
   objects, each with `profile`, `architecture`, `digest`, `report`
   (local raw JSON path), `database_evidence` (traceable immutable DB
   provenance) and `captured_at` (UTC ISO timestamp). Execute:

   ```sh
   python3 scripts/assemble_dev10_review_scope.py \
     --manifest restricted/evidence-manifest.json \
     --output restricted/foundation.review-candidate.json
   python3 -m unittest discover -s tests -p 'test_assemble_dev10_review_scope.py'
   ```

5. If any profile/architecture is missing, the digest cannot be verified,
   there is a secret, a fixed-version signal, an additional CVE, a changed
   package/version, or any evidence cannot be resolved, the assembler
   refuses. Do not weaken its checks to force an eight-CVE result.
6. The generated candidate is **not** the protected policy. It deliberately
   has no approver, approval time, expiry or approval evidence. Reviewer
   decides expiry and exact acceptable scope, then submits a distinct
   protected decision PR. Verify that the policy schema supports any
   required PR-only and exact-digest constraints before activation; a
   review-candidate metadata field alone is not an enforcement control.
7. After that decision PR is independently approved **on its final head**
   and merged, an authorized custodian computes
   `sha256sum security/decisions/development/foundation.json` from
   the merged bytes, independently checks reviewer/contributor custody,
   and provisions `DEV10_PROTECTED_DECISION_SHA256` in the protected
   GitHub environment. A preapproval hash may be shared as a review
   fingerprint but **must not** be installed as the trust anchor.

## Current gates

- Existing Foundation and Publish failure is not an approved exception.
- The protected evaluator, custody verification, trusted reviewer IDs,
  CODEOWNERS/rulesets, environment controls and negative tests must be
  verified independently. The decision PR must be distinct from the
  engineering PR.
- Development authorization is not tagged-image release authorization.
  RC-to-GA promotion requires separate release evidence and approval.
- Do not fabricate missing raw Trivy, digest, database or independent
  approval evidence to complete the policy.
