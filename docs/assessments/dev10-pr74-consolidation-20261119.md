# DEV-10 consolidation into PR #74

The integration keeps the DEV-10 development-risk decision, read-only engineering evidence, and release authorization under their existing authorities. Applicable controls are EA v2.3, EA-DEV DEV-10 and DEV-14, ADR-DEV10-001 and the DEV-10 release contracts.

## Source references at the start of the audit

| Ref | Commit | Base and review |
| --- | --- | --- |
| `main` | `bc6ca0a9f7d28c8baa41a903642ff808c99e84f2` | Default branch |
| [#74](https://github.com/baobab-platform/baobab-dev/pull/74) | `157103b5bc0ea78ab1b4482d9b9eb4155345d49b` | `main`. GitHub reported no merge conflict. Earlier reviews include changes requested and approval, with fresh review required for consolidation. |
| [#82](https://github.com/baobab-platform/baobab-dev/pull/82) | `39071c6a1a5cf89ef4ebd24e8555afea127e11ae` | `main`. Four changed files. GitHub reported no merge conflict and recorded approval and changes requested. Its merge base with #74 is `e46d5e11d24480d369c173ed017fd8f7021ac122`. |
| [#91](https://github.com/baobab-platform/baobab-dev/pull/91) | `fcdb0c344037cda08ef0b777f5c8330a8ed27617` | The #74 branch at `157103b5` is an ancestor. GitHub reported no merge conflict and recorded changes requested. The merge-base diff contains 69 files. |
| [#92](https://github.com/baobab-platform/baobab-dev/pull/92) | Draft independent decision | Reference only. The active decision file in #74 is byte-identical to its pre-consolidation version. |

## Integration matrix

| Source | Disposition on #74 | Verification |
| --- | --- | --- |
| #82 verifier, workflow, tests and operations note | The verifier and protected capture semantics were already present. Kept #74's RC selection, artifact custody and v2 structure. Corroborated the original actor type through the immutable numeric ID. | Ran 20 source tests and 35 integrated approval and release-boundary tests. The capture-step test exercises both actor lookups, the actual verifier CLI and exclusion of review comments. |
| #91 pinned inputs | Integrated the evidence lock, the reviewed 298-CVE and Canonical inventories, and a pinned sparse Linux CNA checkout. The historical 295-CVE files are byte-for-byte unchanged. | Verified lock digests, exact unique CVE sets and source revision. Tests show that changing a working-tree record leaves reads from the pinned Git object unchanged. |
| #91 kernel and binary evidence | Integrated exact Ubuntu tag and Linux CNA pins, per-path results, the Canonical OSV comparison and the separate 41-CVE reconciliation. An exact dpkg root directory marker is excluded from the payload comparison. | Replayed SHA-256-verified #91 inputs against the new verifier. The downloaded archives and installed payloads matched across 1,101 amd64 and 1,072 arm64 entries. Unsupported applicability and VEX conclusions remain refused. |
| #91 policy and verifiers | The inactive proposal and schema support the bounded 12-finding form. Both provisioning and runtime evaluation require its evidence-lock SHA-256. The legacy kernel exception script is now disclosure-only and rejects authorization calls. | Negative tests deny missing or mismatched evidence locks, unauthorized bases, altered findings, secrets, expiry and self-approval. Release Trivy validation binds the exact child digest, architecture and scanner version. |
| #91 GitHub Actions and lifecycle | The 298-CVE combined workflow carries the former upstream-only check. Locked onboarding shares one supplemental source audit across its two joins. The exact Ubuntu APT capture is shared by the native jobs. Publish restores caches on PRs and exports only final layers on main. | Workflow parsing, shell validation and native GitHub jobs exercise the four image targets on both architectures. A diagnostic historical image result remains distinguishable from strict qualification. |

## CI root causes and repair location

| Evidence | Classification | Disposition |
| --- | --- | --- |
| [#82 Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/44121286504) and [Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/44121284415) | C, inherited authorization refusal | The prior exception scope refused #82. Its four-file change passed the targeted tests. Source #82 needed no repair. |
| [#74 upstream](https://github.com/baobab-platform/baobab-dev/actions/runs/44268952813), [Ubuntu](https://github.com/baobab-platform/baobab-dev/actions/runs/44268952792) and [onboarding](https://github.com/baobab-platform/baobab-dev/actions/runs/44268952747) | A, evidence fixture defect | The mock lacked `classification`. The integrated test now follows the actual output and pinned-checkout contract. |
| [#91 Foundation](https://github.com/baobab-platform/baobab-dev/actions/runs/44437608924) and [onboarding](https://github.com/baobab-platform/baobab-dev/actions/runs/44437607584) | A/B, source and integration defects | Removed duplicated broken YAML and shell fragments. Fixed escaped newlines, stale lock and field references, test import coupling, source checkout handling and the dpkg root-marker comparison. Reproduced and repaired on #74 with the source branch preserved. |
| [#74 Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/44268952724) and [#91 Publish](https://github.com/baobab-platform/baobab-dev/actions/runs/44437607632) | D, cache budget | Cache reservation failed during export. Native build and Trivy continued. Consolidation limits writes to scoped main builds and retains all targets and architectures. |
| [#91 frontend amd64 scanner artifact](https://github.com/baobab-platform/baobab-dev/actions/runs/44437607632/artifacts/14490405899) | A and C, a fix available plus expanded findings | Verified artifact SHA-256 `1739ec85abfb417181e4d696c9a34db3d47f7b157e4f006bfd0d7f13a9b0e749`. It contained 52 kernel findings and one Go standard-library finding in each of `gh`, `task` and `yq`. Rebuilt the pinned CLI sources using checksum-verified Go 1.27.4 for amd64 and arm64. The protected evaluator still refuses findings outside the approved inventory. [Go security advisory](https://pkg.go.dev/vuln/GO-2026-6859) |

The 12-finding proposal represents an earlier scanner observation. Current scan outputs determine whether any separately approved inventory applies. The active decision, approval custody, `main` execution scope, expiry and release environment retain their existing authority. The historical GHCR results relate to v1.5.1 and its locked signer and index. A future release requires its own digest, scan, signing, provenance, SBOM, approval and promotion evidence.

The first integrated run passed the native APT captures and corroborated all 41 supplemental source records, with zero Linux CNA mirror discrepancies. It surfaced the dpkg root marker in the published-image manifest format as well. The follow-up validates and excludes only that directory marker and captures package evidence before exercising the lifecycle. The strict historical onboarding check still records a failure because the immutable v1.5.1 image reports GitHub CLI as `DEV`, while the locked contract requires `2.102.1`. [First integrated onboarding run](https://github.com/baobab-platform/baobab-dev/actions/runs/44441823774)

The readback from the second integrated run supplied all eight historical image manifests. The 41-CVE comparison matched the immutable index for each profile and compared 53 source paths against the pinned Ubuntu tree. It found 51 paths present. Both native APT payload joins reproduced the same path count. The join now runs after a historical lifecycle refusal and requires all eight manifest digests before it can report a result. [Second integrated onboarding run](https://github.com/baobab-platform/baobab-dev/actions/runs/44442669022)

The next Foundation scan surfaced the same Go finding in Terraform 1.17.1. Both official 1.17.2 archives matched HashiCorp's SHA-256 manifest and still reported Go 1.26.10 in their build information. The infra target rebuilds the existing Terraform pin from its exact release commit using the verified Go 1.27.4 compiler. The builder checks the module sums, refuses module file drift, and verifies the resulting CLI version. [Foundation scan artifact](https://github.com/baobab-platform/baobab-dev/actions/runs/44443796173/artifacts/14493230882)

PR #82 is a supersession candidate once its final-head checks are reviewed. PR #91 remains open until consolidated source and consumer qualification is witnessed. PR #92 remains independent. The integration stays open while security and release prerequisites are outstanding.


## 19 November reconciliation update — PR #91 remains open

### Reconciliation decision

PR #91 is **not yet eligible to close as superseded**. Its implementation is substantially represented on the PR #74 integration branch, but the repository's stated closure condition remains unmet: consolidated source and consumer qualification must be witnessed on the current #74 head. PR #91 must not be closed merely because its paths or inventory files exist on #74.

The PR #74 branch contains the 298-CVE inventory and evidence lock with identical Git blob IDs to #91:
- `docs/assessments/dev10-kernel-cves-298.tsv`: `8074dfb1e14a047b53a6bf48070b5abb2a75f23d`
- `security/evidence/dev10-kernel-evidence.lock.json`: `bfa43900b3433c57c4cb5d8ffaf89a9bfd180288`
- `scripts/audit_ubuntu_kernel_git_paths.py`: `7b2a5e486e546054179d5f1d46817da5d7e81b2b`
- `scripts/build_dev10_applicability_register.py`: `3465348158f809bcf36a56c3a25e0e6f90acf3ce`

One important implementation divergence is intentional and must be retained: #74's `scripts/audit_kernel_cve_paths.py` is not byte-identical to #91's version. The #74 version reads each CNA record with `git show <pinned-sha>:<path>`, validates the immutable Git checkout before reading, and only records commit-shaped stable/linus references as candidate fix references. The #91 version reads from the working tree and returns all HTTPS references; its commit URL regular expression is over-escaped. The #74 implementation is the stricter replacement and must not be regressed to #91's version.

The ADR `docs/adr/ADR-DEV10-001-reusable-development-risk-policy.md` is byte-identical on both heads (blob `ac4f20ef470452aa64759e55a0ed27eec55a152b`). Its authority boundaries remain binding: the 12-finding development proposal is inactive until the separate #92 decision and custody/provisioning requirements pass; development risk acceptance is not release authorization; all new or changed findings remain blocking.

### Evidence observed before the latest #74 commits

The following runs exercised the then-current #74 merge head (not the later cleanup commits):
- [Ubuntu exact-tag source corroboration, run 44445936263](https://github.com/baobab-platform/baobab-dev/actions/runs/44445936263): passed. It checked the 298-record inventory against the pinned `Ubuntu-7.0.0-43.43` source tag at `f53b359683af7918c5436499948763cb726d5082`, validated Canonical OSV records and retained artifact `14493222621` (SHA-256 `caee45dc5aac6f498634a46cf1f46d6c4141d9fcb627ea730e4d3625185e52a9`). The joined register retained all 298 records as `under_investigation`; this is source-path corroboration, not fix/backport proof.
- [Locked onboarding, run 44445936290](https://github.com/baobab-platform/baobab-dev/actions/runs/44445936290): source audit, both native APT captures, all eight published-image manifests, and both 41-CVE source-to-binary joins passed. The eight published-image lifecycle jobs did not qualify: the immutable historical v1.5.1 image reports GitHub CLI `DEV` instead of the required `2.102.1`, and its Cosign version output also fails the verifier's expected format. The jobs correctly retained historical-baseline-unqualified status; this is not a reason to weaken the pinned toolchain contract.
- [Foundation Repository Gates, run 44445937621](https://github.com/baobab-platform/baobab-dev/actions/runs/44445937621): the unfiltered Foundation scan found 52 `linux-libc-dev=7.0.0-43.43` advisories (3 Critical, 49 High). The exact 12-finding development proposal does not cover this set. The protected evaluator correctly denied the findings as outside the approved inventory. Do not expand the proposal, suppress findings, or alter the fail-closed gate to make CI green.
- [Publish, run 44445936275](https://github.com/baobab-platform/baobab-dev/actions/runs/44445936275): all eight profile/architecture scans failed at the same protected evaluator boundary because the observed inventory exceeded the exact approved set. Builds and non-final smoke tests ran; release/GA reuse, digest scan, publish/sign and promotion stages remained skipped.

### Scoped implementation completed in the integration branch

Three non-functional review findings in #91's transplanted files were corrected on #74:
- Removed the unused `EvidenceLock` import from `tests/test_canonical_osv_evidence.py`.
- Removed the unused `copy` import from `tests/test_dev10_evidence_lock.py`.
- Removed the unused `basename` local from `scripts/audit_ubuntu_kernel_git_paths.py`.

These edits were committed sequentially on `dev10/v1.5.2-rc-verifier`; final commit: `be314583eca6b1c140f5cadbff9ed0b4e8b92bce`. The three changes are cleanup only and do not alter evidence semantics.

### Strict rollout plan and exit criteria

1. **Reconcile source and evidence inputs.** Keep the 295-row historical TSVs immutable; validate the separate 298-row inventory, Canonical snapshot, evidence lock and pinned source revisions. Retain all missing-path discrepancies and same-basename candidates as non-dispositive leads.
2. **Prove source-to-binary evidence.** Require the exact Ubuntu tag and binary/source provenance; retain the 298-row register with every disposition under investigation. Separately require the 41-CVE amd64/arm64 package-archive and eight published-image payload joins. No missing path or path match may produce a not-affected, fix, backport or VEX conclusion.
3. **Complete candidate fix adjudication.** For every upstream candidate fix relevant to a finding, compare the candidate against the exact Ubuntu Resolute source history and binary payload. Check ancestry and patch equivalence (including cherry-pick/backport equivalence); a matching path, basename or commit reference alone is insufficient. Record unresolved cases without disposition. Issue #93 remains the history/ancestry follow-up.
4. **Resolve scanner findings without policy expansion.** Reconcile the 52-finding Foundation result and each profile/architecture Publish result against exact source, package and build provenance. Remediate actual vulnerable components or obtain a separate exact-scope, independently reviewed decision through #92 and its required custody/provisioning path. Do not transfer historical acceptance or widen the 12-finding proposal.
5. **Repair historical consumer qualification.** Resolve the immutable v1.5.1 image's GitHub CLI and Cosign verifier mismatches through a documented compatibility decision or a correctly pinned image baseline. Do not silently accept `DEV`, relax exact versions or call the historical image qualified.
6. **Re-run final-head CI.** All required jobs must complete on the same latest #74 head. Require both architectures, all four profiles, source evidence, binary evidence, Foundation, Publish, security and consumer contracts. No skipped, neutralized or bypassed required job counts as a pass.
7. **Close #91 only after witnessed integration.** Compare the final #91 scope against the final #74 head, verify no unique behavior or evidence remains, obtain required fresh reviews, and record the exact #74 head and evidence run IDs in this reconciliation note. Then close #91 as superseded with a link to #74. Until all criteria pass, #91 remains open and #74 remains the integration vehicle.

### Current-head qualification status

The three cleanup commits moved #74 to `be314583eca6b1c140f5cadbff9ed0b4e8b92bce`. New final-head workflows have been triggered for that exact commit (including Foundation, Publish, Security, locked onboarding and Ubuntu source corroboration). Their queued/in-progress results are not yet qualification evidence. This note must be updated from those completed runs before any supersession or merge decision.
