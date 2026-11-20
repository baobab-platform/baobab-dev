# DEV-10 security policy administration — activation checklist

This document describes required GitHub administrative settings. Committing this
file or CODEOWNERS does not apply a ruleset, create a variable, or configure an
environment. Do not mark security-policy custody active until an authorized
repository administrator has verified the settings through GitHub.

## Repository-level Actions variables

The reusable Foundation and Publish scan jobs read these non-secret values
through the `vars` context without referencing an environment. This is
intentional: routine PR qualification must not pause for a manual environment
approval.

- `DEV10_SECURITY_APPROVER_LOGINS`: comma-separated GitHub logins of the
  independently authorized reviewers. This is a repository-level variable,
  not an environment variable. The provisioning and scan workflows resolve
  these logins to immutable numeric GitHub user IDs at runtime.
- `DEV10_PROTECTED_DECISION_SHA256`: the lowercase 64-hex SHA-256 of the exact
  approved, merged policy JSON bytes. This is a repository-level variable
  created and read back by `scripts/provision_protected_risk_policy.py`
  through the repository Actions Variables API. Do not manually set or
  overwrite it. The provisioner refuses to replace a different existing hash.

These values are not credentials. They do not independently authorize a scan;
the evaluator still verifies the exact decision, trusted reviewer custody,
numeric maker-checker separation, event/ref/repository scope, finding inventory
and expiry. Their administrator access and change history must be reviewed.

## Protected environments

- `dev10-security-policy-read`: human approval gate for the manual
  `Provision DEV-10 development risk policy` workflow's authorization job.
  Restrict it to `main` and require the designated human reviewer. This job
  receives no provisioning credential and does not run for routine PR scans.
- `dev10-security-policy-provision`: holds the fine-grained
  `DEV10_POLICY_PROVISIONER_TOKEN` secret. Restrict it to `main` and expose
  the token only to the provisioning job after the read/authorization job
  succeeds. Keep its permissions limited to Variables read/write, Contents
  read, Pull requests read, Issues read and Metadata read.

The Foundation and Publish scan jobs must not reference either environment.
They use only the repository-level non-secret variables and read-only
`GITHUB_TOKEN`; this avoids per-PR human approval and prevents the
provisioning credential from reaching candidate workflows.

## Repository review controls

- Require current-head independent review for changes to the protected
  decision, custody verifier, evaluator, workflow and their tests.
- Use the individually requestable security reviewers
  `@sknabusiu` and `@sdnabusiu`; do not add unavailable team slugs.
- Review direct pushes, administrator bypasses and changes to repository
  variables. CODEOWNERS is advisory unless branch protection enforces it.
- Preserve read-only token permissions in PR workflows and never pass the
  provisioning token to PR, build, scan or release jobs.

## Manifest lock writer and release settings

- `dev10-lockfile-write` holds `DEV10_LOCKFILE_APP_PRIVATE_KEY`. Set the associated client ID in `DEV10_LOCKFILE_APP_CLIENT_ID` and install the approved App on this repository with Contents write. Restrict the environment to the trusted main-target context. This App only receives generated files after the trusted resolver attests the source head. Keep the App outside release-tag, main and protected policy bypass lists.
- Main release qualification checks the effective GitHub branch rules for required independent PR review, stale-review dismissal, approval after the last push and up-to-date checks.
- The release tag ruleset must cover the canonical release namespace. GitHub's API should show `refs/tags/v*`, including normal stable and RC tags, with creation, non-fast-forward and deletion restrictions. Inspect administrator and App bypasses separately. A clean scan or passing verifier does not authorize a settings change.

## Required activation proof

1. Record the repository variable names, environment IDs, rules and required
   reviewers; never record secret values.
2. Verify the trusted reviewer accounts against live GitHub identities.
3. Verify the decision PR is merged and independently approved on its final
   head; reconcile issue #54 before any eight-CVE acceptance.
4. Verify the exact merged policy bytes against the repository-level SHA-256
   variable and the provisioning receipt.
5. Run actual GHCR child-digest Trivy qualification for each intended profile
   and architecture, plus negative tests. Preserve sanitized evidence.
6. Keep release qualification and promotion separate from development risk
   acceptance. No development decision authorizes tags, publication, signing,
   promotion, staging or production.

Current status: **CONFIGURATION CONTRACT COMMITTED; ADMIN SETTINGS MUST BE
VERIFIED IN GITHUB.**
