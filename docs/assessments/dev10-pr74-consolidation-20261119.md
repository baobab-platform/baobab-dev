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

PR #82 is a supersession candidate once its final-head checks are reviewed. PR #91 remains open until consolidated source and consumer qualification is witnessed. PR #92 remains independent. The integration stays open while security and release prerequisites are outstanding.
