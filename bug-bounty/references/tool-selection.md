# Tool selection and environment adaptation

The upstream toolchain is an inventory from a different Kali environment, not a dependency list. Do not install every listed tool or activate example MCP configurations. Match tools to the current hypothesis and permitted operations.

## Discover before depending

Check OS, shell, available executables, actual command identity and supported options. On Windows use `Get-Command`; on POSIX use `command -v`. A matching name is insufficient: `httpx` may refer to an unrelated package. Inspect trusted help/version output when needed. Capture executable path, observed version, verification time and planned role.

Avoid shell interpolation of URLs, tokens, payloads or imported commands. Use structured arguments and files where practical. Prefer existing tools over custom scripts only when their behavior and output meet the task. Missing tools are a capability gap; continue offline analysis or propose a scoped setup instead of pretending a command ran.

## Capability families

| Need | Examples from the archive, not assumed installed | Decision |
|---|---|---|
| Asset discovery | subfinder, DNS utilities | Discovery clues must still pass scope checks |
| Service fingerprinting | nmap, whatweb | Limit target/ports/probes to the agreed task |
| Web inventory | katana, ffuf, directory discovery tools | Bound crawl depth, request count and output |
| Candidate scanning | nuclei, ZAP, sqlmap | Inspect selected checks and side effects; no blanket run by default |
| Source/dependency leads | trivy, secret scanners | Validate reachability and actual exposure; protect discovered secrets |
| Browser flows | browser automation or available connector | Isolate actors and verify identity |
| Data processing | Python, jq, rg | Parse retained output instead of flooding the conversation |

## Execution contract

Before a network tool runs, record target allowlist, selected checks/options, credentials by reference, total/per-tool budgets, rate and concurrency, timeout/retries, stop signals, output location and side effects. Preserve program-mandated identification fields exactly. Propagate reduced limits across all concurrent work and account for retries in the same budget.

Write verbose output to task-specific files; summarize with evidence paths and actual exit status. Preserve negative checks and contradictory observations. An empty result may reflect wrong setup or filtering; investigate a discriminating control within the budget, not endless broader scanning.

Separate probe completion, candidate discovery, validation and confirmed impact. A successful tool exit is not a confirmed finding. Keep raw evidence needed for assessment; clean only this task's disposable files, without deleting unrelated project files or other workers' artifacts.
