# Operator workflow: choose, prove, record

Use the shortest path from the user's material to a supported decision. This is a decision loop, not a mandatory sequence of all phases.

| Starting material | First useful action | Avoid |
|---|---|---|
| Policy | Extract exact scope/restrictions and available roles | Asking for facts already supplied |
| Application access | Capture one valuable legitimate flow; map actor/object/action | Scanning before understanding the product |
| HTTP trace | Check actor, ownership, content/state and a control | Declaring a flaw from status alone |
| Source location | Trace input and guards to the sensitive action | Broad scanning for a narrow question |
| Scanner/advisory | Check prerequisites and a discriminating proof | Repeating advisory worst-case impact |
| Existing report | Edit supported facts and identify missing reproduction | Unnecessary re-exploitation |

## Intake without bureaucracy

Collect facts that affect the next action: exact target/operation, scope rule, access and side effects. Read supplied artifacts before asking. Where routine limits are absent, select a conservative task-specific bound, state it briefly and proceed within existing authorization. Do not turn optional settings into approval gates. A blocked technique need not stop independent evidence review.

Keep policy source/capture time. Reward exclusion differs from testing prohibition: self-XSS being unrewarded does not prohibit all browser testing. Explicit third-party exclusions still govern the target boundary.

## Hypothesis card

```text
H03: member A may read B's private export using its known job ID.
Basis: export download is a separate operation from export creation.
Setup: two isolated owned workspaces; completed export per account.
Test: keep A's valid session; replace only A's download ID with B's.
Controls: B can retrieve B's marker; A session verified; no sharing.
Confirm: B's file content returned to A.
Reject for this path: A denied while positive controls succeed.
Inconclusive: missing body, invalid session, unfinished job, unknown sharing.
Bound: smallest request set for controls and one comparison.
```

Record expected and actual outcomes separately. After each useful test, confirm the narrow boundary, reject under tested conditions, resolve one material uncertainty or stop the affected action. Do not repeat an inconclusive test without changing what prevented a conclusion. Further impact testing should change a material claim, not merely enlarge the report.

## Progress and handoff

Updates should explain changed understanding and the next decision. Example: 'The detail endpoint denies A correctly. The download path is separate, so I’m checking it with the same two owned accounts.' Avoid command-by-command narration.

Leave scope/mode, consumed/remaining budgets, actors and credential references, tested hypotheses including negatives, evidence paths, confirmed findings/readiness, incomplete cleanup and the next useful action. No confirmed findings is a valid outcome; negative coverage is not proof the application is secure.
