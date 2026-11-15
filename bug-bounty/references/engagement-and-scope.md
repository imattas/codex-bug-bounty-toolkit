# Engagement and scope

## Establish a working contract

For supplied-artifact analysis, record the source and limitations and begin. For live testing, record program identity, policy URL or supplied text, capture time, precise eligible assets, exclusions, permitted techniques, account rules, traffic limits, disclosure terms and the user's requested mode. A public program name or a discovered hostname alone is not a complete scope decision.

Distinguish three questions: is testing authorized, is the asset/technique eligible, and is the finding reward-eligible? A reward exclusion is not automatically a testing prohibition; a vulnerability class being eligible does not authorize it on every asset.

Use the program's explicit interpretation of wildcards, paths, ports, mobile builds and environments. Keep the policy's actual wording with the decision. Do not silently invent rate limits or convert optional recommendations into requirements.

## Scope ledger

For each asset or technique, record its exact identifier, eligible/excluded/unresolved status, policy source and section, relevant quotation, reasoning, constraints and last checked time. Classify an unlisted asset as unresolved unless the policy establishes its status. Apply explicit exclusions within otherwise broad scope. If authoritative instructions conflict and precedence is unspecified, hold the affected test while continuing independent eligible work.

Ownership clues (certificate names, branding, IP neighbors, CNAMEs, acquisitions, repository references) support discovery, not authorization. Third-party infrastructure requires the program's explicit coverage and applicable restrictions. An eligible application may use hosted infrastructure; testing application behavior does not automatically permit testing the hosting vendor's control plane.

Before sending requests, resolve redirects against scope. Recheck each destination; do not automatically follow a request outside the authorized boundary or carry credentials across origins. DNS and URL parsing must preserve exact host boundaries; `example.test.attacker.invalid` is not `example.test`. Do not expand wildcard scope to the bare domain unless the policy says it is covered.

## Autonomy and limits

Use existing authorization and user direction rather than asking about each routine request. Establish a bounded test budget (time, requests, concurrency and maximum retries appropriate to the task), test accounts and permitted state changes before an autonomous run. If the program has a stricter limit, it controls. If a limit is missing, propose a conservative task-specific limit rather than claiming it came from policy.

For a mode switch, record effective time, phase, new initiative level and unchanged restrictions. The user can authorize scope-preserving next steps in ordinary language; no special phrase is required.

Stop the affected activity on an explicit prohibition, unresolved authorization, rate-limit/service-distress signals, unexpected sensitive third-party data, exhausted budget or a user stop. Preserve minimal evidence, explain what stopped, and continue unaffected work where appropriate. Do not retry around a policy restriction or evade throttling.

Inspect only the minimum needed to establish impact. Prefer researcher-owned objects and accounts. Keep a cleanup ledger for objects created or modified. Do not delete evidence or unrelated objects under the label of cleanup.

## Resume

Read state and completed hypotheses first. Refresh policy when testing resumes after a gap, a policy change is signaled or the planned action differs from prior coverage. Preserve prior snapshots rather than rewriting history. Reconcile current exclusions before issuing requests. Track remaining budget and incomplete cleanup. Refer to credentials by environment variable or secret-store handle; do not persist tokens in engagement YAML.

## Working outputs

Produce a short eligibility decision when the question is narrow. For a full intake, use the engagement template and summarize confirmed scope, blocked questions, operational limits and the next permitted action. Avoid turning intake into a generic compliance questionnaire.

Before report creation, use [pre-report triage](pre-report-triage.md) to check exact report/reward exclusions, actionability and known duplicates as well as testing scope. A permitted test can end in an informational or excluded observation; keep that result in candidate notes rather than generating report.md.
