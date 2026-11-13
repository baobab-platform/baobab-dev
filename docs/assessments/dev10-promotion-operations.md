# DEV-10 promotion operations — implementation contract

The GitHub Environment `dev10-release-promotion` remains the sole authorisation
gate. No notification, audit job or scheduled escalation may approve, reject,
bypass or impersonate a deployment reviewer.

## Approval evidence (implemented in this PR)

The protected promotion job retrieves GitHub's native deployment review records
for its workflow run **after** the environment has released the job. It fails
closed unless an approved review for `dev10-release-promotion` was submitted
by an actor other than the run initiator. The minimal JSON evidence records the
reviewer, submission timestamp, run ID, current attempt, tag and environment.
The run-attempt field is contextual: GitHub's review response does not bind a
review to an attempt; do not represent it as proof of attempt-specific approval.
The existing environment-policy verifier continues to require prevention of
self-review. The existing always-run evidence upload preserves the approval
record if later verification fails.

## Remaining operational work (not implemented by this PR)

1. A separate read-only workflow should detect pending deployments and send
   actionable reviewer notifications without invoking deployment approval APIs.
2. Escalation should use configurable reminders and an independent on-call
   contact; expiration should fail closed, never self-approve.
3. RC-to-GA continuity must use digest equality or a separately approved
   qualification waiver. Source SHA equality alone is insufficient.
4. The final evidence bundle should bind four image digests, signatures,
   scan results, the approval record, promotion journal and consumer evidence.
   An absent required field must fail final qualification.

Do not change the immutable v1.5.0-rc.5 tag as part of these improvements.
