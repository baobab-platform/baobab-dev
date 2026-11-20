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
6. GA discovers a successful qualified RC for the exact same source and
   version family. It reuses that RC's OCI digests.

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

## Required repository-side enforcement (administrator)

Under **Settings → Rules → Rulesets**, target release tag names `v*` for both
RC and GA. Enforce **Restrict updates** and **Restrict deletions** without
bypass. Use a separate **Restrict creations** rule when authorized release
maintainers need a creation-only bypass. Check the effective organization and
repository rulesets and their bypass actors before enabling publication.

Verify the ruleset with a disposable test tag and a deliberately rejected
update/deletion attempt by the actual release credential; retain the ruleset
ID, configuration, test run and reviewer evidence in DEV-10 qualification.
Do not test by rewriting a real published release tag.

CI also executes `scripts/verify_remote_release_tag.py` for every tagged
run, refusing a tag that no longer resolves to its event commit. This detects
drift but cannot undo a server-side tag mutation or replace the ruleset.
Verify that the tag resolves to the exact merge of an independently approved
main PR and that the manifest and generated files match the reviewed head.
The recovery planner requires a different source commit from the failed RC.

Publish serializes protected GHCR tag promotion. For a partially applied
promotion, retain the journal before investigating. Automatic compensation
reads back each mutable alias and restores its snapshot only while the alias
still carries this run's digest. A concurrent change or an indeterminate
remote response requires independent readback and a new recovery decision.
To roll back a consumer, take the previous qualified index digest from its
signed release contract, verify the exact profile and source, restore that
digest with the corresponding project pins, and rerun the frozen lifecycle.
