# Business logic, state and concurrency

Use for money-like values, credits, entitlements, approval flows, one-time actions or multi-step workflows. Understand the business rule before changing parameters; unusual behavior is not automatically a security violation.

## Model the invariant

Write a short state table: actor, starting state, allowed transition, required prior action, invariant after completion. Examples: only the approver can approve; a voucher can be consumed once; refund value cannot exceed the eligible paid amount; a canceled job cannot later grant an entitlement. Verify these against observed product behavior or supplied requirements, not assumptions about how the business should work.

Map identifiers carried between steps: quote/order/payment IDs, approval grants, ownership, amount/currency, destination and expiry. Record which values the server should derive rather than trust from the client.

## Choose the smallest discriminating test

| Hypothesis | Controlled comparison | Confirmation |
|---|---|---|
| Step can be skipped | Same disposable object with/without prerequisite | Restricted final state reached without required step |
| Stale authorization survives role/state change | Grant created before change, then action after change | Actual effect contradicts the documented revocation rule |
| Client controls protected value | Legitimate value vs one benign alternate on an owned object | Server records/uses the unauthorized value |
| One-time action can be replayed | Original action vs bounded repeat | Two durable effects where one is allowed |
| Concurrent requests violate an invariant | Serial control vs minimum permitted concurrent pair | Reconciled final state exceeds the allowed effect |

Use test/sandbox currency or no-cost owned objects where possible. Scope and program restrictions govern real financial actions, concurrency and load. Define cleanup and any irreversible effect before testing.

## Sequential before concurrent

First prove the legitimate transition and serial duplicate behavior. If both duplicate serial requests are accepted, that may be a replay/idempotency flaw rather than a race. A concurrency test is justified when simultaneous processing plausibly changes the outcome and that technique is permitted.

For an allowed concurrent test, start with the minimum pair and a finite total budget. Save per-request start/end times, request IDs, response bodies and final authoritative state. Do not increase volume until a lucky response appears. Distinguish accepted requests from committed effects and eventual reconciliation. Two successful responses can still correspond to one ledger event.

If the result is intermittent, preserve both successful and unsuccessful trials and state the conditions. Do not claim a reliable arbitrary-volume exploit from a single pair. Report state-changing side effects and verify cleanup independently; do not reverse transactions using unrelated accounts.

## Evidence and impact

Capture before/after balance or entitlement, authoritative event IDs and control outcomes. Tie the consequence to an actual permission or invariant: 'viewer can approve their own request' or 'one voucher grants two credits under a concurrent pair'. Avoid unbounded profit estimates unless the required repetition, costs, caps and reconciliation behavior are established.

Remediation should address the invariant: atomic check-and-change, server-derived values, explicit transition guards or appropriate idempotency. Do not prescribe a specific database lock without understanding the execution path.
