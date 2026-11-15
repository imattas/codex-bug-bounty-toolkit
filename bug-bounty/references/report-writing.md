# Report writing

## Write for the triager's decision

Before creating a report, pass [pre-report triage](pre-report-triage.md). Out-of-scope, informational, duplicate and unresolved candidates stay in notes. For accepted findings use the exact [report frame](../assets/report-template.md) and [bundle layout](finding-bundles.md): Asset, primary Weakness and calculated CVSS 4.0 Severity; Description containing Summary, numbered Steps To Reproduce (setup first), Expected vs. Actual Behavior and Supporting Material / References; then Impact. Do not add template markers, generic introductions or internal triage sections. Map into destination-specific fields only when actually exporting/submitting.

Start from the internal finding, not from a vulnerability-class essay. Use natural, direct sentences with concrete actors and objects. Preserve the researcher's voice when editing. Human-sounding means clear and specific; it does not mean pretending to have performed work, inventing personal reactions or inserting deliberate mistakes.

Good title: 'A workspace member can read another workspace's invoice by changing its ID.'

Weak title: 'Critical security vulnerability with devastating business impact.'

## Evidence-to-prose recipe

1. State the lowest privilege and precise action that crosses the boundary.
2. Give the setup needed to reproduce it using the triager's own accounts and objects.
3. Write each step as an action with the input and expected observation. Reference the corresponding artifact.
4. State what was exposed or changed and under which prerequisites. Separate conditional downstream consequences.
5. Include remaining uncertainty only where it changes assessment or reproduction.

Use active voice and ordinary technical terms. Keep necessary request bodies, headers, role relationships and timing details even when they take space. Prefer concise explanations over deleting information needed for reproduction. Code blocks are evidence, not prose padding.

Remove greetings, generic definitions, repeated impact sections, self-promotion, bounty negotiation, speculative financial figures, dramatic adjectives and unrelated headers. Avoid 'an attacker could potentially leverage this critical issue to...' when the evidence supports a direct sentence such as 'A member can read invoices outside their workspace.' Do not add a CWE label unless its classification is supported and useful.

For remediation, target the demonstrated boundary: e.g., verify the requesting principal can access the specific invoice at the server operation. Avoid asserting that UUIDs, hidden buttons or client checks solve authorization. Where source is unavailable, frame the suggestion as a recommendation rather than a claim about the root cause.

## Worked evidence and rendering

The [fictional finding packet](../assets/examples/authorization-case.md) illustrates how a control can contradict an apparent successful write. It is reasoning material, not a substitute report frame. The bundle generator renders only accepted data into the current exact frame; its tests verify heading order, relative PoC/evidence links and absence of the ignored frame marker. Never copy fictional observations into a real report.

## Editing pass

Use [report editing](report-editing.md) for before/after rewrites and [the worked finding packet](../assets/examples/authorization-case.md) for a full example that distinguishes response echoes from durable unauthorized changes.

Read once for correctness and once for economy. Every claim should trace to an artifact or an explicit inference. Every paragraph should help locate, reproduce, assess or fix the flaw. Keep material limitations; remove repeated disclaimers. If a report gate fails or evidence is incomplete, produce an evidence-gap note rather than creating a report or report draft.
