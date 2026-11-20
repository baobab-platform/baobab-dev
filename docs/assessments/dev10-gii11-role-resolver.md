# GII-11 typed GitHub role evidence

The reviewer independence audit now records the numeric actor ID, role, account classification and source with each reviewer observation. The result reports contributor independence. The custody and release verifiers remain responsible for approval and authorization. [Issue #81](https://github.com/baobab-platform/baobab-dev/issues/81) · [ADR-DEV10-001](../adr/ADR-DEV10-001-reusable-development-risk-policy.md)

| Role | Observed source | Custody boundary |
| --- | --- | --- |
| PR author | Typed GraphQL author and REST PR `user` | Corroborate the numeric ID. Exclude the author from independent review. |
| Commit author | GraphQL commit Git actor linked to a typed account | Use the exact commit and include the author in the contributor set. |
| Co-author | GraphQL `authors` connection at the exact commit | Require complete enumeration and exclude every contributor from independent review. |
| Committer | Linked GraphQL Git actor, or REST lookup for the exact SHA when the committer link is explicitly null | Require matching raw name, email and instant and a typed User. Use the fallback for contributor exclusion. |
| Reviewer | REST review record | Require a typed numeric ID. Authorization also needs a trusted appointment, effective exact-head approval and contributor exclusion. |
| Accountable owner | REST comment `user` on the decision PR | Require the appointed numeric owner and an attributable concurrence created and last edited before merge. |
| Workflow initiator | REST workflow run and attempt actor fields | Bind the actor to the exact run attempt and source. Protected reruns fail closed. |
| Merger | REST PR `merged_by` on the canonical merge | Bind provenance to the reviewed source. A merger's identity grants no approval. |

## Account classification

- A GitHub `User` records an account type. The model leaves human eligibility unverified.
- The known platform service User is identified by immutable ID `19864447`. Its contribution remains in the exclusion set.
- Bot and App observations retain distinct types and carry no approval authority.
- Unknown types, invalid IDs, conflicting API field representations, invalid source and role pairs, and missing commit SHAs fail closed. A nickname, email address, noreply ID, commit signature or AI trailer cannot supply an authenticated identity.

The role matrix is implemented as a provenance model. The read-only audit uses it for reviewer output. The other role combinations are exercised in the policy-contract test, with their live custody behavior defined by the existing verifiers. [Role model](../../scripts/github_identity_roles.py) · [Reviewer audit](../../scripts/audit_pr_reviewer_independence.py) · [Tests](../../tests/test_audit_pr_reviewer_independence.py)

Run `python3 -m unittest discover -s tests -p 'test_audit_pr_reviewer_independence.py' -v` for the provenance matrix, malformed identities and role-confusion refusals. The policy-contract workflow verifies the same unit coverage and retains authenticated historical evidence. [Policy workflow](../../.github/workflows/dev10-policy-decision.yml)
