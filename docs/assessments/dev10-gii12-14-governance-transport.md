# GII-12–14 — Governance and transport gate assessment

## GII-12 — Branch custody and rulesets
Protected decision PRs should be updated by their accountable preparer. A base merge or conflict resolution may introduce commit authors or committers who later appear as reviewers; **all** such contributors remain excluded from independent review. Do not treat a merge commit as neutral merely because it is signed by GitHub. Reviewer write permission is not proof of approval independence.

Branch protection and rulesets must be inspected using authenticated read-only API calls. A 403 does **not** establish that protection is enabled or disabled; record it as unverified. CODEOWNERS is routing guidance unless an effective protection/ruleset enforces it. Required evidence: ruleset IDs, enforcement mode, bypass actors, required reviews, dismissal rules, branch update policy, final-head status and independent readback. No branch protection modifications authorized by this PR.

## GII-13 — Negative matrix
| Case | Required result |
| --- | --- |
| Null/unknown actor, Bot, App, missing/boolean numeric ID | Deny |
| Service User as human reviewer | Deny absent independently approved eligibility |
| Reviewer-authored merge commit or co-authorship | Deny reviewer |
| Stale/dismissed review or changed final head | Deny |
| Wrong exact SHA, inconsistent raw metadata | Deny |
| REST 403/404/5xx, invalid JSON, oversized payload | Deny |
| Truncated GraphQL commit/co-author history | Deny |
| Missing GitHub signature | Never substitute signature for numeric custody |
| Rerun triggered by different actor | Recheck original and triggering IDs |
| Missing pre-merge owner concurrence | Deny |
| Unauthorized provisioning or changed protected variable | Deny, never overwrite |
| API redirect to non-GitHub origin | Deny, no credential forwarding |

The existing baseline includes unit coverage for many cases; the table is a **coverage target**, not a claim that every case has passed live.

## GII-14 — Transport boundary
`github_api_transport.py` defines HTTPS-only `api.github.com`, disallows userinfo and nonstandard ports, rejects cross-origin redirects and caps responses at 1 MiB. Both `custody_independence.py` and `provision_protected_risk_policy.py` import `open_github` and `read_bounded`. The provisioner also validates API paths and uses bounded paginated reads. Inspect other scripts/workflows and every call site before declaring repository-wide closure. In particular, transport exception reasons and arbitrary API messages must not leak into logs; GII-06 PR #87 addresses custody REST diagnostics but is not automatically included in this PR's #74 base.

## Outstanding acceptance
Obtain authenticated branch/ruleset evidence; run final-head tests and negative authorization workflow; inspect all workflow/API callers and live transport failures. No protected write, approval bypass, release promotion or merge is authorized by this assessment.
