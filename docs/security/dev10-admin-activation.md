# DEV-10 security policy administration — activation checklist

This document describes required GitHub **administrative** settings. Committing this
file or CODEOWNERS does not apply a ruleset or set GitHub variables. Do not
mark security-policy custody active until an authorized repository administrator
has verified these settings through the GitHub administration API/UI.

## Repository ruleset (main, active; no bypass for security policy authors)

- Require pull requests for changes to main, with required code-owner review.
- Require at least one approval from an independent reviewer; dismiss stale
  approvals and require approval of the most recent reviewable push by a person
  other than the pusher. Restrict force pushes and deletion.
- Protect security/decisions/**, scripts/evaluate_protected_risk_decision.py,
  scripts/verify_protected_risk_custody.py, their tests, .github/CODEOWNERS,
  .github/workflows/dev10-protected-risk-qualification.yml and this document
  through @baobab-platform/security CODEOWNERS review.
- Confirm all four already-authorized security reviewers are eligible for
  repository code-owner review. The team must have repository write access.
- Review any administrator/bypass exemptions and document why they cannot
  silently self-approve security decisions.

## Trusted environment variables

Create GitHub Actions environment `dev10-security-policy-read` for **read-only**
qualification. Restrict deployment branches to protected main. No per-candidate
review approval is required: approval happens when a security policy is changed.

Set these environment-level variables **through an authorized admin**, not in
a PR, workflow_dispatch input or untrusted source file:

- `DEV10_SECURITY_APPROVER_LOGINS`: comma-separated GitHub logins of the four
  independently authorized reviewers, exactly as provisioned. Never invent
  identities or derive this list from the PR author's input.
- `DEV10_PROTECTED_DECISION_SHA256`: lowercase 64-hex SHA-256 of the exact
  independently reviewed, merged policy JSON bytes. This is a single-policy
  anchor; it must be rotated by the custodian for a new decision and cannot
  represent multiple simultaneous decisions. Multi-decision custody requires
  an authenticated manifest or signed policy registry before activation.

An environment variable is **not automatically immutable** or immune to an
administrator changing it. Its administrator access, change audit and
environment restrictions must be separately verified. GitHub variables do not
substitute for the independent PR approval record.

## Required activation proof

1. Record ruleset ID, active enforcement, code-owner review enforcement,
   team permissions, environment ID and variable names (never secret values).
2. Verify the four reviewers against live GitHub identities and permissions.
3. Verify the decision PR is merged and independently approved on its final
   head; reconcile issue #54 before any eight-CVE acceptance.
4. Verify the protected policy file hash against the trusted environment value.
5. Run real GHCR child-digest Trivy qualification for each intended profile
   and architecture, plus negative tests. Preserve sanitized evidence.
6. Only after independent verification, replace Foundation and Publish legacy
   allow-list checks. No silent fallback or weakening of release promotion.

Current status: **CONFIGURATION CONTRACT COMMITTED; ADMIN SETTINGS NOT VERIFIED**.
