# DEV-10 kernel CVE source qualification and independent VEX authority

Status: **ENGINEERING IN PROGRESS / SECURITY HELD** (30 October 2026).
Governing: accepted EA v2.3, EA-DEV, security ADRs, maker/checker separation.
Primary PR: #48; independent review request: #54. This is not security approval.

## Existing evidence is retained

Do not overwrite the Trivy 295-case inventory, Canonical status TSV, upstream
path-capture script, package manifest, historical artifacts, or original
Foundation/Publish failures. Known package: Ubuntu 26.04
`linux-libc-dev=7.0.0-42.42`, 1,039 headers, two docs, no executable binary.
Canonical's 287 pending / eight needed statuses refer to Ubuntu's `linux`
**source package**, not a statement about this binary's exploitability.
Original source paths: 248 implementation-only and 47 with private headers.
Zero direct shipped UAPI path matches does not prove absence of transitive
macros, ABI changes or vendor downstream patches.

The read-only `dev10-kernel-paths` workflow now joins these sources into
`dev10-cve-applicability-register.json` with **295 distinct CVE records**.
It refuses incomplete/mismatched source lists. Every item remains
`under_investigation` until Ubuntu 26.04 patch provenance, backports,
release-pocket status, compiler-visible headers, downstream userspace
compilation effects, and independent human review have been established.
The initial register's empty Ubuntu patch fields are deliberate unknowns.
The upstream JSON and manifest are bound to their recorded SHA256 hashes.
The 295-entry permanent preliminary TSV is
`docs/assessments/dev10-cve-applicability-review-register-20261030.tsv`.
Read-only `.github/workflows/dev10-ubuntu-source.yml` checks actual source
paths at a Canonical Ubuntu 26.04 kernel release tag. That check is **not** a
verified per-CVE Ubuntu fix/backport history, nor a byte-for-byte vendor header
diff across fixed revisions.
The Ubuntu patch input is optional for engineering collection and must not
be mislabeled as independent approval.

## Authority model: no bootstrap-by-author

The existing Baobab IAM Principal and Control Plane administrative-grant,
changeset/approval, evidence and audit contracts are the architectural
authorities. Reuse them rather than inventing a competing issuer. In the
meantime the minimal verifier reads a **protected, externally issued**
authorised-reviewer trust bundle; it does not create appointments or grant
permissions. The trust bundle **must not** come from this PR checkout,
an author-modifiable `main` path or an unprotected workflow input.
Bind it to a reviewed protected environment or independently managed
governance/evidence store. The production authority source and key lifecycle
remain **NOT PROVISIONED**.

Independent appointing authority must verify a real human/governed Principal
and establish the `security:vex:approve` grant scoped to
`baobab-platform/baobab-dev`. Evidence preparer, code author and approving
Principal must differ. Platform-level approval powers alone are not evidence
of an appointed independent security reviewer. **Issue #54 requests
appointment or properly delegated authorisation; it is not an approval.**
Rejection and request-for-evidence are signed, recorded decisions that leave
the security gate closed.

Decision signature: the verifier checks an external Ed25519 public key via
OpenSSL over deterministic JSON bytes of the complete `decision` object,
including exact OCI digest, platform, OCI product PURL, source revision,
full unfiltered Trivy inventory hash, evidence hash, reviewer identity,
decision timestamps, and explicit CVE decisions. The public key is obtained
only through the protected governance trust bundle. The signed payload
must include per-CVE Canonical status, technical review reason, separately
reviewed Ubuntu patch/source and UAPI/ABI evidence references, and the
individual evidence SHA256. An expiring reviewer appointment and an
unrevoked key/decision are mandatory. Expired, revoked, altered,
unauthorised, self-approved, digest/architecture-mismatched and missing
evidence assertions fail closed.

**No real trusted key or reviewer appointment is shipped in this PR.**
Unit tests use ephemeral TEST-ONLY Ed25519 keys; their positive results
are neither a security decision nor usable VEX. In production, CP must
provide a time-bounded snapshot with independent custody and verification.

## OpenVEX and Trivy boundaries

OpenVEX v0.2.0 recognises `not_affected` and
`vulnerable_code_not_present`. Trivy 0.73.0 supports local `--vex` but
its VEX feature is experimental; Trivy's OCI VEX discovery does **not**
automatically verify the attestation's signature. Trivy's PURL matching
can also match a package across images or architectures if scoped only to
a package PURL. Thus feeding arbitrary OpenVEX to Trivy is **not** an
authorisation control. Sources:
https://trivy.dev/docs/v0.73/guide/supply-chain/vex/
https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
https://trivy.dev/docs/dev/guide/supply-chain/vex/oci/

`scripts/verify_dev10_vex.py` is the separately testable authorisation
filter. It consumes full, unfiltered Trivy JSON, the conservative 295-record
register, a real signed independent decision and a protected trust bundle.
It enforces exact digest, platform, package identity/version, full scanner
evidence integrity, per-CVE approval references, expiry, revocation and
maker/checker separation. It emits an OpenVEX projection only AFTER verified
authorisation; each product statement binds the OCI digest with a package PURL
subcomponent. A signed approval for one CVE does not permit another. The
per-CVE register must independently mark actual Ubuntu source diffs,
shipped-header comparisons, header inline/macro impact, UAPI/ABI/compiled
userspace impacts as reviewed before a signed decision can be applied.
Missing fields or unresolved impacts keep the CVE blocked.
It never changes the Canonical source status. Tests cover positive and
negative policy cases with ephemeral cryptographic keys.

The current Foundation/Publish scanners continue to run unfiltered with
HIGH/CRITICAL blocking, secret scanning, no `--ignore-unfixed`, no
`--skip-files`, and no CVE-wide `.trivyignore` entries. **No
`--vex` flag is added to either blocking scanner by this PR.** Before
production use, a separate protected workflow must verify the exact
build/image manifest digest and a governed trust bundle, run the raw strict
scan, retain it, apply approved VEX/policy as an additional gate, and test
Trivy's actual filtering and image-PURL behaviour on both architectures.
That CI change requires independent review, not an automatic feature toggle.
Release tags and registry writes remain separately protected.

## Reviewer package template (request, not approval)

- Request/Change ID, author Principal, evidence preparer Principal.
- Requested independent reviewer and **existing authoritative grant**
  (or an appointment request to the established appointing authority).
- Exact target profile, `linux/amd64` or `linux/arm64`, OCI digest,
  image PURL, package PURL and installed binary version.
- Each CVE's original vendor severity/status, Ubuntu source commit/diff,
  upstream fix commit, Debian/Ubuntu backport and repository-pocket proof.
- Actual changed files vs `dpkg-query -L`; indirect inline/macros,
  compiler-generated code, UAPI/ABI, downstream binaries, host isolation.
- Remediation status in supported `resolute-security` or
  `resolute-updates`; evidence of no available supported fix if applicable.
- Independent disposition `affected`, `not_affected`,
  `under_investigation`, `rejected` or `needs_evidence`,
  with signed rationale, accountable risk owner, expiry/review trigger.
- Signed decision, immutable evidence digest, revision, timestamp,
  revocation location and durable tamper-evident evidence custody.

**Re-review triggers:** new vendor record, patch/USN or security pocket,
new source/binary or OCI digest, scanner/version/database changes, compiler
or UAPI changes, changed privilege or host kernel assurance, expiry,
revocation, changes to maker/checker authority and release promotion.
The GitHub repository currently enforces **15 days maximum artifact retention**
(even for workflows requesting 30 days). That is not sufficient for immutable
approval/evidence custody. Independent longer-term signed storage is required.

## Development vs authorization vs release

Development checks and source qualification may progress while authority
is pending. No permitted engineering work needs a fabricated approval.
A development verifier passing **synthetic** tests is not a VEX authorisation.
No production image digest, independent Principal, signed reviewer decision,
immutable approval evidence, live host kernel certification or EA-REL
release certificate is currently asserted. **PR #48 stays SECURITY HELD.**
