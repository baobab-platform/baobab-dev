# GII-11 typed role boundary

Read-only prototype only. `github_identity_roles.py` represents immutable numeric actor IDs, role, classification, provenance and optional exact SHA. Unknown actor types, invalid IDs, non-committer REST fallback and implicit human approval are refused. A GitHub `User` object is **not** proof of a human.

The intentionally non-authorizing `require_human_eligibility` placeholder always refuses pending a separately approved authenticated human-eligibility source. It must **not** be substituted into the live provisioner as a completed authorization provider. Current protected custody logic remains unchanged.

Threats: forged noreply addresses and AI trailers, signed platform commits, login renames, bot impersonation, unknown GraphQL Actor variants and approval laundering. Noreply numeric IDs, if ever parsed, may be considered exclusion-only after a separate spoofing assessment, not as authorization. A production integration requires reviewed policy mapping and evidence contracts for all eight roles, and exact-head independent tests.
