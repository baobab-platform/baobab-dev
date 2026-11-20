# Run 533 Ubuntu source and installed-package review

[Source job](https://github.com/baobab-platform/baobab-dev/actions/runs/44699737484/job/136164923205) · [Fix-history archive](https://github.com/baobab-platform/baobab-dev/actions/runs/44699737484/artifacts/14617541152) · [Binary and source archive](https://github.com/baobab-platform/baobab-dev/actions/runs/44699737484/artifacts/14616747677)

The downloaded fix-history ZIP SHA-256 is `40d11fafdbc4889267f3e2720bd454510a885afbed7d8376df3bb113785e34ac`. The report SHA-256 is `4a64540cef8aba32c35cb56e0cea312e9791b5cd4453a89b48885be86175e9a5`. The two original Debian packages from the source archive independently match the architecture lock and every installed-manifest entry when freshly extracted. These comparisons use the original packages to avoid relying on the case-colliding loose headers in the old ZIP.

## Installed version 7.0.0-43.43

Canonical lists the exact linux source version for all eleven. Its binary lists identify the exact linux-libc-dev version for six. The table uses the per-package lists in the pinned OSV records. All eleven have zero direct UAPI path candidates in both verified installed manifests. Indirect exposure and binary remediation remain under investigation.

| CVE | Exact binary explicitly listed | Missing CNA path at the Ubuntu tag |
| --- | --- | --- |
| CVE-2022-50240 | No | drivers/android/binder_alloc_selftest.c |
| CVE-2025-40190 | No | None |
| CVE-2026-68103 | No | None |
| CVE-2026-72198 | No | fs/ntfs/attrib.c |
| CVE-2026-74578 | No | None |
| CVE-2026-89805 | Yes | None |
| CVE-2026-98376 | Yes | tools/testing/selftests/bpf/prog_tests/percpu_array_inner_map.c |
| CVE-2026-98420 | Yes | None |
| CVE-2026-98869 | Yes | kernel/bpf/fixups.c |
| CVE-2026-98890 | Yes | None |
| CVE-2026-99083 | Yes | None |

## Ancestry and correspondence

- CVE-2022-50240. The ancestor a43cfc87ca changes Binder allocation and its self-test. The release tag contains both allocator files. The self-test path is absent. This separates the missing test from the two implementation paths.
- CVE-2025-40190. The ancestor 57295e8354 adds an EA inode reference-count guard in fs/ext4/xattr.c. The implementation path exists at the release tag. Six stable variants had a common patch-ID witness in incomplete searches.
- CVE-2026-72198. The ancestor 7ffa8f3d30 removes the classic NTFS implementation, including fs/ntfs/attrib.c, its build entries and configuration. This explains a concrete historical deletion. Replacement implementations and other candidate refs require separate review.
- CVE-2026-98890. Seven stable variants concern the short monitor-transmit-frame check in the Libertas driver and match Ubuntu commit 08c60b09c8. CVE-2026-68451, outside the image eleven, accounts for the other three unique correspondences. They concern the CCA ECC request length check in the s390 zcrypt driver and match Ubuntu commit 1cacb65c00. CVE-2026-74578 yielded three matches in incomplete searches, a separate category.

The workflow revisits all thirteen historical leads, validates each upstream reference against the pinned CNA data, checks downstream reachability, compares ordered changed lines and records each downstream post-image against the release-tag tree. Equal edit fingerprints and identical post-images strengthen source correspondence. Changed post-images require semantic review of subsequent changes. A missing path retains its explicit null tree entry.

## Reproduction and scope

PR runs select the eleven findings from the evidence lock before fetching candidates. Every other inventory reference receives an explicit deferred status. Select inventory in a manual workflow run for the broader search. Review selected count, candidate-level assessments and incomplete searches alongside workflow status. The budget applies to candidate analysis. Tag-history materialization and supplemental witness verification are separately timed steps.

The architecture artifact retains two tar files with the original packages, extracted payloads, manifests and hashes. CI downloads the uploaded artifact by ID, compares both tar files byte for byte and compares their members against the runner trees. The combined source artifact keeps manifests and packages and excludes loose extracted headers.

The resulting evidence supports issue #93 and the applicability review in #54. All dispositions remain under investigation.
