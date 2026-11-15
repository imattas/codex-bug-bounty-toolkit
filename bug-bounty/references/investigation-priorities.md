# Investigation priorities

## Start with the application, not a payload list

Map what the application does, who can act, what they can access and where trust changes. Use supplied traffic, architecture, source code or permitted browsing. Begin with existing evidence when available; do not repeat reconnaissance to satisfy a fixed sequence.

Record identities and roles, workspaces/tenants, sensitive objects, high-value actions, API/UI boundaries, asynchronous jobs, imports/exports, callbacks, caches and external integrations only where relevant. For source-assisted work, trace user-controlled inputs through authorization and sensitive operations. Cite file locations; static reachability alone is not runtime confirmation.

## Choose hypotheses

For each candidate, write: 'Given [attacker access], can [action/input] cross [boundary] and cause [specific effect]?' Name a falsifying control and the smallest permitted test.

Prioritize using potential demonstrated impact, confidence in reachability, available accounts/evidence, program relevance, test cost and side effects. Explain the reason in one sentence. Novel-looking endpoints are not automatically higher value, and scanner counts are not impact.

| Application clue | Useful first question | Minimum control |
|---|---|---|
| Objects belong to users or workspaces | Is access checked for this actor and object? | Owned A/B object with verified isolation |
| Different roles perform sensitive actions | Does the server enforce the role at the action endpoint? | Authorized role vs lower role, same operation |
| Login, recovery or invitation changes identity | Is each step bound to the intended identity and session? | Intended flow with owned accounts |
| Orders, credits, approvals or one-time actions | Are state transitions and limits enforced consistently? | Valid transition vs one targeted invalid transition |
| Imports, URL fetches or callbacks | What input reaches which parser or destination? | Controlled benign marker and observed processing |
| Cache or background processing crosses users | Is the result keyed and delivered to the correct principal? | Separate owned sessions and unique markers |
| Code shows a suspicious sink | Can permitted input reach it with the necessary privileges? | Call path plus a non-destructive distinguishing result |

These are starting questions, not confirmation rules or permission for sensitive techniques. Race conditions, resource exhaustion, credential attacks and infrastructure testing must satisfy explicit program restrictions before execution.

## Hypothesis queue

Store ID, boundary, prerequisite, rationale, test, control, budget, result and next action. Use states queued, testing, supported, rejected, inconclusive or blocked. A negative result rejects the tested hypothesis under recorded conditions; it does not establish that an entire vulnerability class is absent.

Queue state is distinct from finding confirmation: queued/testing map to a finding hypothesis; supported means evidence favors the hypothesis but does not automatically mean confirmed. Promote to confirmed only after the evidence contract in [evidence and validation](evidence-and-validation.md) is satisfied. Rejected, inconclusive and blocked retain those meanings in both records. Link a supported queue item to its finding record so a resumed session can inspect the confirmation decision.

Investigate one discriminating uncertainty at a time. Expand testing only if it changes a material claim. Stop after enough evidence for the bounded finding. If the agreed budget ends with no confirmed findings, deliver tested coverage, negative results and limitations rather than a fabricated report.
