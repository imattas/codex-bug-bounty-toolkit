# Report lifecycle and retests

Use this for ongoing findings, fix retests and sibling-surface investigations. Keep history separate from the current report; do not silently overwrite prior observations.

## Create and update

Create one finding per distinct eligible root cause only after [pre-report triage](pre-report-triage.md), using the [bundle layout](finding-bundles.md). Keep related endpoints as instances where justified; separate them when prerequisites or fixes materially differ. Known duplicates update the existing record instead of generating reports. Before updating, read current contents and revision/hash or modification time; reconcile concurrent changes rather than overwriting another worker's evidence.

Attach each amendment's time, evidence IDs, rationale and changed claims. Keep internal hypotheses in notes rather than duplicating them as confirmed reports. Do not imply a reporting API exists: local Markdown records are sufficient. External writes require the user's applicable authorization.

## Retest

Record original finding ID, current build, eligible target, test time, actor and prerequisites, positive control, attempted reproduction, result and evidence. Check that the originally relevant conditions still hold.

| Outcome | Required basis |
|---|---|
| reproduced | Current evidence demonstrates the same boundary violation |
| not_reproduced | Valid setup and functioning authorized positive control, followed by the tested behavior being denied or corrected under equivalent conditions |
| inconclusive | Missing access, unverified identity, failed positive control, unreachable service, partial test or materially different prerequisites |

An expired or wrong session returning 401/403 is not evidence of remediation. A negative result covers the specific tested path and conditions, not every instance or historical exploit chain. Do not claim a fix merely because the endpoint disappeared unless the relevant behavior and coverage justify it.

Append the assessment and supporting artifacts. Update the report's current status only when the user-requested workflow and evidence support that transition; retain the original finding and earlier assessments.

## Sibling investigation

Choose a bounded candidate set from a plausible shared root cause: analogous API methods, export paths or role variants. Record why each candidate is related and verify its scope separately. Share the engagement's total request/concurrency budget; spawning a worker does not create a new budget.

For each candidate record reproduced, ruled_out_under_tested_conditions, inconclusive or not_examined. A negative runtime conclusion needs a working positive control on that surface. Source evidence may establish a particular guard with cited call-path coverage, but does not become a runtime observation. Missing access remains inconclusive. State the tested set and limitations; do not describe sibling hunting as exhaustive.

## Handoff

Store assessments in the engagement project with relative paths from the finding record. Include who performed the test, whether it was independent analysis or a separately executed supplied procedure, and which artifacts were actually inspected. Surface any inaccessible child artifacts or verification gaps in the final conclusion.
