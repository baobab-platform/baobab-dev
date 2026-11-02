
# Pull Request

## Summary

Provide a concise summary of the proposed changes.

---

## Related Issues

List the related GitHub Issues that this Pull Request addresses.

Example:

Closes #123

Related to #45

---

## Business Value

Explain how this change contributes to the Baobab platform.

- What business capability does it improve?
- Which Feature or User Story does it support?

---

## Type of Change

Select all that apply.

- [ ] New Feature
- [ ] Enhancement
- [ ] Bug Fix
- [ ] Refactoring
- [ ] Performance Improvement
- [ ] Security Improvement
- [ ] Documentation
- [ ] Test Improvements
- [ ] Infrastructure
- [ ] CI/CD
- [ ] Other

---

## Implementation Summary

Describe the technical implementation.

Include:

- Major classes added
- APIs implemented
- Database changes
- Configuration updates
- Architectural considerations

---

## Database Changes

- [ ] No database changes

OR

Describe any migrations, schema modifications or data updates.

---

## API Changes

- [ ] No API changes

OR

Describe any new, updated or deprecated endpoints.

---

## User Interface Changes

- [ ] No UI changes

OR

Describe the UI changes.

Include screenshots if applicable.

---

## Multi-Tenant Impact

Select all that apply.

- [ ] No tenant impact
- [ ] Tenant isolation maintained
- [ ] Tenant data model updated
- [ ] Tenant configuration updated

Provide details if necessary.

---

## Security Review

Select all that apply.

- [ ] No security impact
- [ ] Authentication updated
- [ ] Authorization updated
- [ ] Sensitive data handled securely
- [ ] Input validation completed
- [ ] Security review completed

Provide details if applicable.

---

## Performance Impact

- [ ] No measurable impact

OR

Describe expected performance implications.

---

## Testing Performed

Select all completed.

- [ ] Unit Tests
- [ ] Integration Tests
- [ ] End-to-End Tests
- [ ] Manual Testing
- [ ] Regression Testing

Provide additional testing notes if necessary.

---

## Documentation

Select all completed.

- [ ] README updated
- [ ] API documentation updated
- [ ] Architecture documentation updated
- [ ] User Guide updated
- [ ] ADR created/updated
- [ ] No documentation changes required

---

## Checklist

Confirm the following before requesting review.

- [ ] Related Issue linked
- [ ] Code follows project standards
- [ ] Self-review completed
- [ ] Acceptance Criteria satisfied
- [ ] Tests passing
- [ ] Documentation updated
- [ ] No unnecessary commented code
- [ ] No debug statements remain
- [ ] CI checks passing
- [ ] Ready for review

---

## Developer Toolchain Upgrade Gate (when applicable)

If this PR updates a Baobab Dev Container runtime, operating-system package,
package manager, build CLI, browser toolchain, Dockerfile, image supply chain or
consumer image reference, follow the
[Toolchain Upgrade Playbook](../docs/usage/toolchain-upgrade-playbook.md)
and review the
[DEV-10 / DEV-14 lessons learned](../docs/incidents/2026-10-30-dev10-dev14-toolchain-retrospective.md).

- [ ] Not applicable; this PR changes no development toolchain/image contract
- [ ] Exact old/new versions, archive hashes, image digests, dependent consumers and rollback recorded
- [ ] Frozen lock verification, actual installed and embedded dependencies audited
- [ ] Noninteractive Codespaces lifecycle, real command results and denial cases verified
- [ ] Four profiles × AMD64/ARM64 build/scans, Foundation and CodeQL qualified on the final head
- [ ] Original findings and any approved environment-scoped security risk, owner and expiry retained
- [ ] Consumer-owned fresh Codespaces and private-package access evidence attached where adopting images
- [ ] Publication, SBOM/signing, registry readback and release approvals separately qualified
- [ ] Outstanding gates clearly marked NOT DEMONSTRATED with owners; no protected release inferred from DEV CI

---

## Reviewer Checklist

For reviewers.

- [ ] Business requirements satisfied
- [ ] Code quality acceptable
- [ ] Architecture consistent
- [ ] Security considerations addressed
- [ ] Performance acceptable
- [ ] Tests adequate
- [ ] Documentation complete
- [ ] Ready to merge

---

## Deployment Notes

Describe any deployment considerations.

Examples:

- Database migration required
- Feature flag required
- Environment variables required
- Infrastructure changes
- Rolling deployment recommended

---

## Additional Notes

Include anything reviewers should know before approving this Pull Request.
