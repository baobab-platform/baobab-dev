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

## Follow-up on the completed eleven-finding run

[Hosted run 44714959258](https://github.com/baobab-platform/baobab-dev/actions/runs/44714959258) · [Fix-history ZIP](https://github.com/baobab-platform/baobab-dev/actions/runs/44714959258/artifacts/14622723038) · [Source and witness ZIP](https://github.com/baobab-platform/baobab-dev/actions/runs/44714959258/artifacts/14623786151)

The targeted search covered 46 candidate commits without exhausting its time budget. It recorded 3 exact ancestors, 7 unique stable patch matches, 35 incomplete downstream patch searches and 1 truncated search. It explicitly deferred 1,412 other references. The separate witness pass checked all ten historical patch correspondences, including the three variants outside the eleven-finding scope.

The downloaded ZIPs matched their Actions SHA-256 digests. The inner fix-history report SHA-256 is `382fe4f9c1bca6d2181dcdc7910093c0a04f6bf71da24533f38bf90aa3eac766`. The source-witness report SHA-256 is `61af4769c6c51824f023e41438d22e7d5a35fb91d2d9ea3bc8273d60987e7223`. For surviving C and header files the review retrieved the file contents by object ID and verified each with Git's blob hash before interpreting the guard. The path evidence for removed files comes from the checked release tree.

| Finding | Observation at Ubuntu-7.0.0-43.43 |
| --- | --- |
| CVE-2022-50240 | Binder's allocator uses a mapped-state flag and obtains the VMA under read-side synchronization. Its allocator structure no longer stores the historical VMA pointer. The old self-test path is absent. The implementations at the ancestor and tag differ. |
| CVE-2025-40190 | The ext4 EA inode reference-count update checks both decrement at zero and increment at the maximum, reports corruption and exits before changing the count. |
| CVE-2026-72198 | The classic NTFS removal deleted fs/ntfs/attrib.c and the path is still absent at the tag. Changes to surrounding build files and other NTFS implementations have separate histories. |
| CVE-2026-68451 | All three s390 variants share the same ordered edits. The Ubuntu tag still bounds the ECC key length and rejects excessive lengths before constructing the request. Later changes in the file affect alignment. This CVE belongs to the broader inventory. |
| CVE-2026-98890 | All seven Libertas variants share the same ordered edits. Comparing the entire historical downstream file with the release-tag file shows that the tag omits the added short-frame guard. A historical match cannot support closing this finding as fixed. |

The reviewed observations are tied to the tag, upstream and downstream commits, changed-line digests, stable patch IDs and exact file objects in `security/evidence/dev10-run533-leads.json`. Divergent evidence yields a review-required result.

The digest-verified Debian archives contain 1,039 headers on amd64 and 1,010 on arm64, plus two documentation files per architecture. Neither archive contains an ELF object, static archive or executable-mode file. Scanning their installed headers found zero literal include operands naming a CNA-affected file for the eleven findings. The package inventory, source semantics and Canonical five/six split answer different questions. Generated interfaces, ABI effects, consumer builds and host-kernel exposure require separate evidence. The binary disposition for all eleven remains under investigation.

For remaining incomplete searches the reporter now records the exact unavailable commit IDs, selected paths and last examined commit alongside the prior counts. The historical run retained counts only. The diagnostic fields apply to subsequent reports.
