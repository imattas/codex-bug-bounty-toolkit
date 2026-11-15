# Source-assisted and dependency findings

Use when given a repository, scanner alert, advisory or exposed artifact. Source access can establish a valid finding without live exploitation when the path and consequence are complete; do not require a deployed target merely to analyze it.

## Source-assisted path

Record commit/build and reachable entry point. Trace attacker-controlled data through transformations, authentication/authorization, feature flags, sanitizers and the sensitive operation. Inspect actual called implementations and relevant configuration rather than relying on a suspicious function name.

For each link record file/location, value under attacker control, necessary access, guard and effect. Check whether a proposed bypass is reachable before the guard, whether the code is active, and whether trusted values are overwritten downstream. Tests and comments express intent; deployed code/config determine behavior.

Use a local minimal reproducer or project test when it can validate the claim without connecting to a target. Keep test stubs honest: replacing an authorization function with `return true` does not prove authorization bypass in production. A unit-level unsafe parser test establishes parser behavior, not necessarily remote reachability.

## Dependency triage

1. Identify the actual package ecosystem/name and resolved installed or lockfile version. Distinguish direct, transitive, vendored and build-only usage. A manifest range is not the resolved version.
2. Read the primary advisory and affected/fixed version conditions. Verify package identity and whether the version is patched/backported; avoid inferring exposure from a banner alone.
3. Locate the vulnerable symbol or behavior and an application call path. Check configuration, enabled features and prerequisites.
4. Establish attacker-controlled input reaching the affected behavior, or state exactly which reachability fact is missing.
5. Assess consequence in this application and program eligibility. Do not copy advisory worst-case severity as an application-specific result.

| Evidence | Valid conclusion |
|---|---|
| Package/version match only | Potentially affected dependency; reachability unverified |
| Vulnerable code present but disabled/unreachable under tested config | Present code; runtime exploit claim not established |
| Reachable path plus required config and complete effect | Application finding with cited assumptions; dynamic confirmation where available |
| Missing build, credentials or environment | Validation gap, not 'not vulnerable' |

## Exposed secrets and artifacts

Record source location and secret type without copying the full value into chat or the report. Assess whether it is a test placeholder, revoked value or intended public identifier using safe metadata/source context. Authenticating with a discovered credential is a separate action governed by scope; do not use it against unrelated services just to prove validity.

For exposed source or backups, show permitted retrieval and specific non-public content with minimal capture. Public source, harmless debug output and intentionally exposed client configuration are not automatically sensitive disclosures. Cite an actual consequence or useful protected material, with appropriate redaction.

## Report format

State entry point, necessary role/configuration, relevant code path and security consequence. Include a small cited snippet only where it explains the failure, plus the reproducer or complete reasoning. Distinguish source-confirmed behavior, independently executed local tests and unverified deployment conditions. Recommend the narrow fix and explain whether upgrading a dependency addresses the demonstrated reachable path.
