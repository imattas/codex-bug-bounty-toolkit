# Reports that read like a researcher wrote them

Human style comes from precise observations and useful omissions, not deliberate errors, casual filler or pretending to have run a test.

| Part | Useful content | Typical waste |
|---|---|---|
| Title | Actor + unauthorized action + affected object/flow | 'Critical security vulnerability discovered' |
| Opening | Mechanism and consequence in 1–3 sentences | Generic definition or discovery diary |
| Setup | Target/build, roles, ownership, unusual prerequisites | Irrelevant browser/system details |
| Steps | Actions and exact inputs another tester needs | 'Manipulate the request accordingly' |
| Actual result | Distinguishing body/state tied to evidence | Only status or 'it worked' |
| Impact | Attacker gain and real prerequisites | Imagined revenue/reputation costs |
| Remediation | Optional focused fix for the boundary | Universal best-practice checklist |

## Before and after

**Before:** 'I discovered a severe IDOR vulnerability which could potentially allow a malicious threat actor to leverage improper access controls, leading to catastrophic reputational damage.'

**After, if supported:** 'A member can download another workspace’s export by replacing the export ID. The API returns the other workspace’s file without checking the requesting member’s access.'

**Before:** 'Change the ID and observe the successful response.'

**After:** 'Keep A’s session cookie and replace `export-a` with B’s completed export ID. The response contains B’s marker, `B-ONLY-742` (E3). A and B are in separate workspaces with sharing disabled.'

**Before:** 'This gives full account takeover across all customers.'

**After, when only a read is established:** 'A member who knows another workspace’s export ID can read that export. The test established file disclosure between two owned workspaces.'

Avoid appending a checklist of every untested vulnerability to the impact section. Include limitations when they prevent a likely misreading or change severity. Keep necessary request/body structure, ownership relationships and timing details even when lengthy.

## Match the report to the finding

For a direct API issue, include a literal redacted request or precise replay and the relevant response excerpt. The triager should create equivalent owned state without your private account.

For identity/logic issues, group steps by actor and transition; identify each session and show the final protected state. Explain the normal prerequisite bypassed. Include timing only when it affects the result.

For source-confirmed issues, lead with reachable entry point and consequence, cite the guard/sensitive call path and supply a reproducer or complete argument. Distinguish local execution from deployment assumptions.

## Title calibration

- Read: 'Members can read private invoices from another workspace.'
- Mutation: 'Viewers can change a project’s billing contact through the update API.'
- Identity: 'An invitation for account A can be accepted as account B with the invited role.'
- Partial proof: 'Possible cross-workspace invoice access; response evidence missing' belongs in internal notes.

Examples are wording patterns, not discovered findings. Do not fill fictional URLs, roles, requests or screenshots into a report just because the template has a slot.

## Missing evidence and final edit

For an existing supplied report, provide diagnostic edits and a short gap list in working notes. If scope, validation, actionability or duplicate checks fail, do not create a report or report draft. Once all gates pass, render the supported facts into the current exact report frame. Existing historical reports are retained, not silently deleted because a later review changes eligibility.

Read the opening alone: is flaw/consequence clear? Read the steps alone: can someone reproduce with their own permitted accounts? Read impact alone: does each gain trace to evidence? Cut sentences that help with none of those decisions. No arbitrary word count or phrase blacklist replaces judgment.
