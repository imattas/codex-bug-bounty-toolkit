# CVSS scoring

## Select the scoring contract

Use the program's required CVSS version and metric groups. If unspecified, propose v4.0 and label that choice; use v3.1 when the program requires it. Keep priority labels, reward eligibility and CVSS as separate assessments. A requested numeric score is not evidence.

For this package's current external report profile, the user specifically requires CVSS 4.0 vector/score in report.md. If the program also requires 3.1, calculate it separately and retain both assessments rather than substituting or relabeling versions. The report bundle verifies its 4.0 score mechanically; metric selection still requires the evidence worksheet.

Read the relevant FIRST definitions for disputed metrics. These sources were checked on 2026-11-15; verify them again when definitions, examples or tools matter to a new assessment:

- [FIRST v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [FIRST v4.0 user guide](https://www.first.org/cvss/v4.0/user-guide)
- [FIRST v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
- [FIRST v3.1 user guide](https://www.first.org/cvss/v3.1/user-guide)
- [FIRST v4.0 calculator](https://www.first.org/cvss/calculator/4.0)
- [FIRST v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

Do not transplant a vector between versions by changing its prefix. v4.0 has separate vulnerable/subsequent-system impacts and Attack Requirements; these do not map mechanically to v3.1 Scope/Complexity. Reassess from the actual exploit conditions.

## Assessment procedure

Describe the attack path, attacker starting access, required victim actions and affected system boundary. For each applicable metric, record proposed value, evidence/definition, assumptions and confidence. Leave unresolved metrics open in the internal worksheet; an incomplete worksheet is not a valid complete vector.

When evidence supports a complete vector, validate its syntax and calculate with FIRST's calculator or a tested, version-matched implementation. Record calculator/library version or URL, exact input, output and verification date. If no calculator is available, offer a candidate vector and explicitly leave the numeric score unverified. Do not calculate from memory or attach a remembered score from a superficially similar issue.

This package includes a tested [offline CVSS 3.1 Base helper and an optional extended/4.0 adapter](local-helpers.md). Use the Base helper for complete v3.1 Base vectors; use the dependency-backed adapter for extended 3.1 and 4.0. Record the actual implementation/version and metric groups used.

If a metric depends on unknown deployment facts, ask a focused question or present clearly conditional alternatives. Do not choose the highest alternative as fact. A defensible worst-case impact can be reasoned from system behavior without destructive exploitation; document the causal basis separately from what was directly observed.

## Decision prompts

Use these prompts to locate evidence, not as replacements for FIRST's definitions.

| Question | Evidence to inspect |
|---|---|
| How is the vulnerable operation reached? | Actual attack interface and required proximity |
| What must the attacker possess beforehand? | Necessary authenticated role or other access, independent of how cheaply it can be acquired |
| What must another person do? | Required victim interaction, distinguished from attacker actions |
| What special conditions must hold? | Conditions outside attacker control; evaluate under the chosen version's definitions |
| Which system suffers which effect? | Security authorities for 3.1; vulnerable and subsequent systems for 4.0 |
| What access or control is lost? | Specific confidentiality, integrity and availability consequences with evidence or defensible reasoning |

Public signup does not itself make required privileges None. Another tenant does not itself establish changed Scope in v3.1. A serious flaw does not itself establish availability impact. Vulnerability names such as XSS, SSRF or IDOR do not determine a score.

## Version-specific checks

For v3.1, assess Base metrics AV, AC, PR, UI, S, C, I and A. Resolve Scope using the applicable security authority rather than hostname or tenant count. Use Temporal or Environmental metrics only when included in the assessment and supported by facts.

For v4.0, assess Base metrics AV, AC, AT, PR, UI, VC, VI, VA, SC, SI and SA. Separate effects on the vulnerable system and subsequent systems without double-counting the same loss. Identify the used groups with FIRST's nomenclature: CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE. Supplemental metrics add context without changing the numeric score. Consult the current user guide for defaults and edge cases rather than inventing values for missing information.

## Output

Return version and assessment type, complete vector if justified, verified score (or 'not calculated'), calculator provenance, metric rationale, assumptions and program-priority assessment if requested. Keep the detailed worksheet in the internal finding; include only the severity explanation useful to the program in the external report.
