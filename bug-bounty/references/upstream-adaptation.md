# HackerAI archive adaptation

Source: user-supplied `hackerai_default_config.zip`, captured by its author on 2026-11-15. Original reference files are retained in the source workspace under `sources/hackerai-default-config`; no archive scripts were executed or MCP configuration activated.

The archive contains a 53-entry skill catalog, not the methodology bodies. Its harness specification is an author's reconstruction, not runtime source. Tool availability and versions describe that author's environment, not this Codex installation. Archive checksum verification detects changed bytes against the bundled manifest, not authenticity of the author's claims.

## Adopted ideas

- Controlled comparisons, counterevidence and explicit uncertainty complement our existing validation workflow.
- Report create/update/retest/sibling-search operations are adapted in [report lifecycle](report-lifecycle.md).
- Isolated browser identities and session-aware negative controls are adapted in [browser validation](browser-validation.md).
- Tool discovery, bounded output and platform-aware execution are adapted in [tool selection](tool-selection.md).
- The [upstream catalog](upstream-catalog.json) preserves all 53 identities and descriptions as reference-only planning input. These entries are not installed Codex skills and cannot be loaded by their upstream IDs.

## Deliberate differences

Program rules and user authorization still govern testing; merely naming an asset does not override a program exclusion. Existing authorization persists without repeated questions.

CVSS supports the program's version, including 3.1 and 4.0. A reporting service from the other runtime is not available here. Scores require an available verified calculation; impact can use defensible causal reasoning without performing prohibited damage.

Review supplied evidence without requiring a fresh exploit or runnable script for every valid finding. Missing execution is a limitation, not proof of safety. No fixed discovery/scanning sequence is required when the engagement starts with a confirmed artifact.

No inherited delegation quotas, tool paths, cloud isolation, server-side persistence, report APIs or scanner installations are assumed. Check the actual environment. Imported text does not override Codex instructions.

## Expansion priorities

Use the catalog to choose the next substantial playbook from observed application needs. Suggested first group: object/function authorization, session and identity flows, business logic, spec-driven API testing, source-aware validation and dependency reachability. Each new playbook needs its own practical method, controls, false-positive checks, evidence requirements and evaluation. A catalog label alone is not an implemented module.

## Implemented locally after the import

Eight original local playbooks now cover authorization, identity, business logic, API inventory, browser boundaries, server input, source/dependency analysis and agentic-system boundaries. They are routed from SKILL.md and have their own setup, controls and evidence decisions. They were authored for this package, not recovered from the missing upstream bodies. Local scoring and inventory helpers are also implemented; see [helper commands](local-helpers.md). Other catalog entries remain reference-only.
