# DEV-10 CodeQL alert #2: cache-poisoning trust-boundary correction

Date: 30 October 2026
PR: baobab-platform/baobab-dev#48
Code scanning alert: https://github.com/baobab-platform/baobab-dev/security/code-scanning/2
Rule: `actions/cache-poisoning/poisonable-step`
Severity: HIGH

## Evidence and root cause

The read-only, security-events:read diagnosis job 41026050152 retrieved the actual CodeQL alert for PR #48.
GitHub reported: “Potential cache poisoning in the context of the default branch due to privilege
checkout of untrusted code from steps.release-context.outputs.checkout_ref. (workflow_dispatch).”
The identified sink was `.github/workflows/publish.yml` lines 258–265, which executed
`config/resolve.sh --locked` after checkout. A dispatch-controlled tag could override the
source ref. The same workflow uses shared Buildx and Trivy caches and can publish with higher
permissions. Validating tag syntax was not a trust guarantee; a syntactically valid tag could
still refer to code not approved for privileged execution.

## Correction

- All checkout steps use `github.sha` (the immutable triggering event commit) and disable
  persistence of Git credentials.
- `workflow_dispatch` no longer accepts a selected tag/ref. It is validation-only
  on `refs/heads/main` and fails closed for other branch selections.
- Registry/image publication, signing and release creation require a version-tag **push**.
  The manual rebuild-from-arbitrary-tag feature is withdrawn as unsafe; future explicit
  rebuilds require a separately reviewed, trusted-ref and provenance workflow.
- `pull_request` checkouts use GitHub's event SHA (typically the PR merge commit),
  not an untrusted branch name.
- Both the Foundation and Publish HIGH/CRITICAL gates are unchanged; no suppression
  or waiver is introduced.

## Verification

Source-level regression tests in `tests/test_publish_checkout_trust.py` prevent reintroducing
dispatch-controlled checkout refs, preserve immutable checkouts, and ensure the vulnerability
gate remains strict. Acceptance requires the new final-head CodeQL check to pass and normal
CI to remain green; source-level tests alone are not a substitute.

The separate Ubuntu `linux-libc-dev` kernel-header security assessment remains HELD.
