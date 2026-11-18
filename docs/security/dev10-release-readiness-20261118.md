# DEV-10 release-readiness evidence — 2026-11-18

## Decision boundary

This record documents an independent, read-only verification of the four existing
GHCR v1.5.1 profile images. It is historical supply-chain evidence only. It does
not qualify a v1.5.2 release candidate, authorize publication, move a tag, or
approve promotion.

The development-only DEV-10 residual-risk policy is not a release authority.
The Publish workflow confines that policy to same-repository pull requests
targeting `main` and pushes to `main`. Release-tag scans independently inspect
exact registry digests and fail closed on residual HIGH/CRITICAL findings unless
a separate exact-digest release decision is authenticated. The release-digest,
publish and promotion jobs do not consume
`DEV10_PROTECTED_DECISION_SHA256`,
`DEV10_SECURITY_APPROVER_LOGINS`, or the development-policy verifier. The
promotion job has its own protected environment and separate digest decision
checks.

## Independent GHCR verification

**Workflow:** [DEV-10 locked onboarding, run 44330235494](https://github.com/baobab-platform/baobab-dev/actions/runs/44330235494)

**Source identity:** `13493b24d6af1a9e7bddf7df9be555d1c06a635d`

**Release tag:** `v1.5.1`

**Signer workflow tag:** `v1.5.1-rc.2`

**Cosign identity:** `https://github.com/baobab-platform/baobab-dev/.github/workflows/publish.yml@refs/tags/v1.5.1-rc.2`

Each profile was independently resolved from GHCR using the immutable OCI index
digest. The verifier compared the raw OCI index SHA-256 with `crane digest`,
validated the two native Linux platform descriptors and their distinct
BuildKit attestation siblings, fetched the child manifests and configs, checked
the immutable source revision label on both children, fetched the embedded
BuildKit SLSA and SPDX blobs, verified the index Cosign signature, and verified
the signed SLSA and SPDX statements against the embedded native predicates.

All four profile artifacts report
`STRICT_SIGNED_NATIVE_CONTENT_VERIFIED`. Each artifact reports five verified
image signatures and two signed statements for each predicate type (one per
architecture).

| Profile | Immutable index digest | amd64 child | arm64 child | Evidence artifact |
|---|---|---|---|---|
| `final` | `sha256:faf9022ef06288767651a0ec1071d5199bc2b645f2cf7ada50477774dd297eed` | `sha256:51c380e8128431dc546fdd59736ad91a02d3f6bcac2d6b9d16389f312f697c0c` | `sha256:1f1a90dc05e3248a8f90e1848d63aa9f5e82a078976a9a1a0d6be3c496360804` | [14439297155](https://github.com/baobab-platform/baobab-dev/actions/runs/44330235494/artifacts/14439297155) |
| `frontend` | `sha256:388d604293fc6a2046d1abb9c7b80b32e78c6003636b091d1e9c7c827e34766d` | `sha256:387eefb51bb748194c10ac35e18c50faed467a8ff2ebc07697cc0dc7063c72f5` | `sha256:a1943251cbd035df107149e94bcd9a28d7feff8094ef911781ef8c71497e9182` | [14439391830](https://github.com/baobab-platform/baobab-dev/actions/runs/44330235494/artifacts/14439391830) |
| `frontend-e2e` | `sha256:5b4a9ce1ac819a2b125f078fef4b14837b5b65b46527087a2bb8898b4811bb0b` | `sha256:96d34348b0b7be9a85c024179d60481597619e15980897896c0653265c78d37e` | `sha256:549336dcc9405f0b657fcc4877749274a9c96d937c7c49ba2fa3fc3c0862f3b5` | [14438972949](https://github.com/baobab-platform/baobab-dev/actions/runs/44330235494/artifacts/14438972949) |
| `infra` | `sha256:5b39e71dd068da12e009421012d7c3620339746c2a39839182ea1f4fe788ffda` | `sha256:1ca79f79867eb0fc3a4a1b0c31ccf0aa47d252915f2e01ff32d6e51d2cfb0fa7` | `sha256:290140edf7fc9c252befe9454119b059549c3a5ddd44cf668392d442f81657d7` | [14438583734](https://github.com/baobab-platform/baobab-dev/actions/runs/44330235494/artifacts/14438583734) |

The artifacts also record the per-architecture attestation-sibling digest,
BuildKit SLSA blob digest, BuildKit SPDX blob digest, and verified signed
predicate digests. The artifacts are the machine-readable evidence; the
profile index and child digests above are copied from those exact outputs.

## Qualification limits and remaining release gates

- This is an independent readback of the existing v1.5.1 images. It is not a
  new build and is not v1.5.2 release qualification.
- The historical v1.5.1 source commit and same-version RC signer are verified;
  no claim is made that this evidence qualifies any other source revision,
  tag, profile or digest.
- The 298-CVE audit remains conservative: all 298 records are
  `under_investigation`; nine upstream-path discrepancies remain unresolved.
  Source-path presence, source-package status and the development risk decision
  do not establish binary non-applicability or remediation.
- The 2026-11-18 onboarding run's registry-provenance artifacts are strict
  successes, but the overall onboarding matrix was not green: runtime checks
  exposed historical-image compatibility gaps. Those are being corrected and
  must pass on the final PR head for the requested consumer qualification.
- v1.5.2 remains gated on final-head CI, a fresh 4-profile × 2-architecture
  build/scan, immutable per-platform and index digests, exact-digest Trivy
  evidence, signed native SLSA/SPDX equivalence, independent release review,
  RC-to-GA digest continuity, and the separate protected promotion process.

No release image was published, no GHCR tag or alias was moved, and no
promotion was performed by this verification.
