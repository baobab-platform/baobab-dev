# DEV-10 development vulnerability acceptance — minimal operating procedure

Baobab-dev builds **internal development environments**, not application staging or production deployments.

## Normal release path

1. Update `config/versions.yaml`; let the existing resolver and CI enforce the lock.
2. Review the actual Trivy findings. If there are **no findings** or only exact, previously accepted findings **within the current time-bounded decision**, CI may proceed without an additional per-PR security approval. If the findings change, an authorized human reviewer independent of the PR author must explicitly approve a narrowly scoped security decision (or the engineer must remediate) before changing the risk inventory/decision and rerunning CI.
3. After existing Foundation/Publish checks and independent release controls pass, use the established GHCR publication flow. No automatic publication from an ordinary PR.

## Automatic future PR qualification

A pull-request event for `baobab-platform/baobab-dev` is eligible for **reusing the existing decision** if its GitHub ref is exactly `refs/pull/<positive-number>/merge`. There is **no list of individual PR numbers to maintain**.

This is not blanket vulnerability acceptance: `scripts/dev10_kernel_risk_gate.py` still checks pinned inventory integrity, exact CVE/package/version/severity, HIGH/CRITICAL only, target and architecture, absence of secrets, no fixed-version signal, and the **2026-11-26 00:00 UTC expiry**. Unrecognized findings and expiry still fail CI. Never add a PR number to bypass them.

For changes requiring human review, use the existing two-account maker/reviewer PR process: the author presents the actual Trivy evidence and proposed narrow scope; the independently authorized reviewer explicitly approves/rejects the vulnerability risk; the approved inventory/decision and tests are changed in a reviewable PR. The author cannot approve their own decision. Merely opening a PR does not authorize new CVEs.

**Release tags are not covered by the automatic future-PR rule.** The legacy v1.5.0/v1.5.1 tagged-distribution boundaries, separate release approval and existing GHCR signature/provenance/SBOM/digest controls remain unchanged. A new release family requiring residual-risk acceptance must receive an explicit human decision; do not silently broaden tagged-release scope.

This is a streamlined development control only. Reserve heavyweight policy administration for staging/production.
