# DEV-10 PROM-02 — digest-preserving protected release promotion

## Release candidate

RC tag pushes build, scan, sign and attest all four profiles, then publish
candidate digests and enter the independently reviewed promotion environment.
RC candidate artifacts retain for 30 days.

## General availability

GA tag pushes do **not** rebuild or re-sign images. The `ga-reuse` job reads
`DEV10_QUALIFIED_RC_RUN_ID`, independently checks the successful completed
RC tag-push workflow, source SHA and version family, and downloads all four
published-info artifacts. It creates GA candidate records referencing the
**same OCI digests**, then uploads those records to the current GA run.

The protected `promote` job downloads those GA records and independently
re-fetches the selected RC run and its records. It refuses GA if any image
digest, source revision, release family or workflow identity differs.
Verification of signatures/provenance uses the **original RC tag context**,
not a fictional newly signed GA image. Existing version-tag immutability,
alias preflight, readback and compensating rollback remain in force.

GA aliases only move after all four versioned tags verify. GA GitHub Release
publication depends on successful protected promotion.

## Qualification boundaries

Unit tests cover four-profile digest reuse and negative RC run/source/version
cases. Workflow static inspection is not a substitute for a real protected
tag-push rehearsal. End-to-end acceptance requires:
1. a successful RC release workflow with retained candidate artifacts;
2. a new GA tag **at the same commit** and an independently approved
   protected promotion run;
3. exact digest readback for all four GA version tags and aliases;
4. signature, provenance and SBOM verification by original RC identity;
5. failure-injection evidence for drift, missing artifacts and rollback;
6. required CI passing at final PR head.

A GA tag on a different commit must fail: build new RC instead. The repository
variable must reference the selected qualified RC workflow run; it cannot
bypass the GitHub Environment. Security risk acceptances are not extended.

## Platform adoption

Reuse this pattern with configurable image profiles and registry names.
Separate publishing approvals from protected staging and production
deployments; each must independently attest artifact identity, authorised
deployment principal, rollback and post-deployment evidence.
