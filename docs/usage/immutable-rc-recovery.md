# DEV-10 — Immutable release-candidate recovery

**Policy:** Release tags are immutable. A failed tagged workflow is evidence of
an unsuccessful candidate, not permission to rewrite its source.

## Required recovery

1. Preserve the failed tag, run ID, logs, digests and security evidence.
2. Fix the defect in a reviewed PR; merge only after required CI succeeds.
3. Select the exact reviewed commit on main. Use the read-only planner:
   `python3 scripts/plan_rc_recovery.py --failed-tag v1.5.2-rc.1 --replacement-sha <40-character-reviewed-commit>`
4. Recheck the remote immediately before creation. Create **only** the new
   numbered RC tag at that commit, then push without `--force`.
5. Run the entire tagged pipeline again: all target builds/scans, exact digest
   signing, SBOM/provenance, protected human approval, and promotion.
6. Only a successful qualified RC may supply `DEV10_QUALIFIED_RC_RUN_ID`
   for GA. GA must reuse the RC OCI digests, not rebuild.

**Prohibited:** `git tag -f`, `git push --force` to release refs,
deleting/recreating published tags, silently treating a rerun of an old
immutable tag as incorporating mainline changes, and marking a failed RC
qualified.

**Repository administrator control required:** Protect `refs/tags/v*` using
a GitHub ruleset with update/deletion restrictions and narrowly controlled
creation privileges. CI and a read-only planner cannot prevent a privileged
actor from force-moving a tag unless repository rules enforce immutability.
Verify ruleset enforcement separately before declaring this control complete.

The planner checks remote refs and main ancestry but cannot atomically reserve
a tag name. A second remote absence check and server-side tag rules are required
at creation. Security exceptions remain separately scoped and never transfer
automatically to the replacement candidate.
