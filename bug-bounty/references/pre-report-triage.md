# Pre-report triage: report only qualifying findings

Before creating report prose or a finding bundle, assess the exact issue against current program rules, actual evidence and accessible known reports. This gate applies to autonomous and assisted workflows alike. Never generate an excluded, informational or known-duplicate report just to fill a template.

## Four decisions

| Gate | Passing basis | Hold or reject |
|---|---|---|
| Scope | Exact asset/build/path and technique covered; submission eligibility and explicit exclusions checked against a cited rule | Out of scope, prohibited technique, reporting/reward exclusion relevant to this issue, unresolved policy conflict |
| Validation | Reproducible boundary violation with the relevant controls and bounded demonstrated consequence | Scanner/advisory label, status-only signal, failed setup or untested necessary chain |
| Actionability | A real confidentiality, integrity, availability or other security consequence supported in this application | Best-practice observation without effect, intended public data/behavior, unsupported impact |
| Duplicate | Accessible local and program records searched; no same-root-cause issue identified; comparisons recorded | Known duplicate, unreviewed similar root cause or no meaningful search performed |

Record the source, checked time, observed facts and rationale. For this workflow, `in_scope` means both testing coverage and report eligibility were checked. An unrewarded class is not permission to test prohibited assets, and permission to test is not a promise a report qualifies. Low severity alone is not informational; use the actual consequence and the program's criteria.

## Scope check

Read the program's exact eligible assets, exclusions, vulnerability-class rules, known issues and proof requirements. Match the actual hostname/environment/path/build and any third-party handling. Preserve the relevant text or source section. Confirm the PoC technique is permitted. If policy cannot be obtained or a material ambiguity remains, keep scope unresolved and continue only independently authorized work.

## Informational check

Ask what protected data, action, identity or service property the attacker actually gains. A version banner, missing header, fingerprint, library match or permissive-looking setting is a lead until that consequence is established. The same observation can become actionable when a concrete reachable effect is proven; avoid permanent class-wide exclusions invented by the skill. Do not inflate CVSS to avoid an informational decision. The bundle requires a nonzero calculated score, but a nonzero number alone never proves actionability.

## Duplicate check

1. Search existing local findings and candidate decisions for the same program, component, violated boundary and root cause. Titles and URLs are clues, not identity.
2. Inspect supplied/accessible program known issues, disclosed reports, previously submitted reports the user can access and applicable advisories. Use a connected source when available; do not claim searches against inaccessible private submissions.
3. Compare the actual cause, actor prerequisites, affected operation and remediation. Multiple endpoints with the same missing object-access guard can be one finding. Two distinct root causes on the same endpoint can be separate. An advisory/version match alone does not establish either exposure or a duplicate application report.
4. A known duplicate goes into notes with the existing report ID/path; add evidence to that finding when appropriate. Similarity that cannot be resolved stays `uncertain`, not 'unique'. A regression after a verified fix needs a dated comparison rather than automatic duplication or automatic novelty.

The passing status is **no_known_duplicate within the checked sources**, never 'guaranteed unique'. Disclose inaccessible private records in the assessment. If reasonable accessible searches are complete and no unresolved matching lead exists, lack of access to every private report is not an endless blocker. The helper additionally catches exact local program/root-cause-key matches and refuses unreviewed legacy reports; semantic matching remains Codex's responsibility.

## Files and final decision

Keep candidates and raw restricted working material under `.bug-bounty/candidates/<id>/`; record `hold`, `out_of_scope`, `informational`, `duplicate` or `eligible` in notes. Do not call these files `report.md`, create a findings bundle for them or automatically promote them later.

Only an eligible, confirmed, actionable finding with a completed no-known-duplicate check may be rendered. Then classify the primary weakness, justify the CVSS 4.0 metrics, verify the score and review the selected PoC/evidence for secrets and unrelated data. Use [finding bundles](finding-bundles.md) to create the accepted artifact. Missing scoring or files holds publication of the local report; it is not permission to invent content.
