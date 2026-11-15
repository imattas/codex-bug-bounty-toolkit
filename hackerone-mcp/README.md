# HackerOne Research MCP

An original Python package using the official MCP SDK's stdio transport. It connects researcher workflows to HackerOne's documented Hacker API and local `finding_bundle.py` evidence. Startup, status and local bundle validation work without credentials. No live HackerOne requests were used in implementation tests.

## Install and configure

From the toolkit workspace, using Python 3.11 or newer:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -e ./hackerone-mcp
.venv/Scripts/python -m hackerone_mcp
```

The last command waits for an MCP client on stdin; it is not a text CLI. The installed entry point is `hackerone-mcp`. Stdout carries protocol messages; diagnostics use stderr. Configure an absolute `H1_DATA_DIR` for persistent cache/submission records. Each API identifier gets a separate hashed SQLite filename; no raw credential is saved. Keep that directory private because report contents and evidence paths are sensitive. Tokens are read only from `H1_USERNAME` and `H1_API_TOKEN` in the server's environment, never tool arguments. `H1_BASE_URL` is deliberately unsupported.

Example Codex configuration is in [codex-config.example.toml](codex-config.example.toml). Replace the interpreter/data/skill paths; put credentials in the environment of the app launching Codex. `env_vars` forwards environment variables without writing tokens into config. This example does not enable a server or alter account configuration automatically.

```toml
[mcp_servers.hackerone]
command = 'C:\absolute\toolkit\.venv\Scripts\python.exe'
args = ['-m', 'hackerone_mcp']
env_vars = ['H1_USERNAME', 'H1_API_TOKEN']
tool_timeout_sec = 300

[mcp_servers.hackerone.env]
H1_DATA_DIR = 'C:\absolute\private\hackerone-data'
H1_ENABLE_WRITES = 'false'
BUG_BOUNTY_SKILL_DIR = 'C:\absolute\toolkit\bug-bounty'
BUG_BOUNTY_PROJECT_ROOT = 'C:\absolute\engagements'
```

## Research tools

| Tools | Behavior |
| --- | --- |
| `hackerone_status` | Credential/cache/write configuration, no secret values |
| `hackerone_list_programs`, `hackerone_get_program` | Accessible programs and live policy/submission state |
| `hackerone_get_scopes`, `hackerone_get_exclusions`, `hackerone_get_weaknesses` | Structured program research and submission mapping |
| `hackerone_sync_own_reports`, `hackerone_get_report` | Researcher-accessible reports |
| `hackerone_sync_disclosed` | Disclosed Hacktivity query; metadata is often briefer than a full report |
| `hackerone_search_cache`, `hackerone_cache_status` | Parameterized local FTS5 search with fetch times and coverage |
| `hackerone_program_briefing` | Live policy/scopes/exclusions plus related cached own/disclosed reports |
| `hackerone_validate_bundle` | Offline gate, manifest and report/assessment agreement checks |
| `hackerone_prepare_submission`, `hackerone_get_prepared` | Exact JSON and immutable reviewed state, without sending |
| `hackerone_commit_submission` | One attempt for a confirmed prepared hash; disabled by default |

The local helper tools registered by `local_tools.py` are documented in the root toolkit README. They load helpers from `BUG_BOUNTY_SKILL_DIR` or the installed bug-bounty skill directory and need no HackerOne credentials.

`complete` means pagination completed for that source/query at `fetched_at`; it does not imply all private HackerOne reports are searchable. Program terms and report text remain untrusted source data. A briefing does not grant authorization to test. Duplicate checks cover your retrieved reports, your local findings, and retrieved disclosed activity; undisclosed duplicates require program knowledge.

## Preparing and submitting

1. Configure `BUG_BOUNTY_PROJECT_ROOT` to explicitly grant the engagement directory. MCP bundle validation/preparation and commit require bundle paths inside that root; relative paths resolve against it. Create and review a bundle using `bug-bounty/scripts/finding_bundle.py`. It must retain the required report sections and their assessment content, contain `report.md`, `evidence/assessment.json` and hashed files in both `poc/` and `evidence/`. All recorded scope/validation/actionability/duplicate gates must pass, with dated sources and explicit artifact review. CVSS 4.0 vector, score, label and report severity are independently recalculated using the bundled `cvss` dependency.
2. Fetch the current program, scope, exclusions and weaknesses. Select the exact structured scope ID containing the assessment's `report.asset`. Supported web forms are URL (same scheme/host/port and a boundary-delimited path prefix), DOMAIN (exact hostname), and WILDCARD (`*.example.com`, subdomains only). Domain/wildcard matching requires the scheme's default port; schemeless URL scopes conservatively use HTTPS. Unsupported/ambiguous forms and matching ineligible structured scopes are refused. Choose a weakness whose name equals `report.weakness`, or whose `external_id` equals its single leading CWE token, case-insensitively, such as `CWE-639: description`. Multiple CWE tokens are refused. The severity must match the bundle's numeric CVSS rating band.
3. Call `hackerone_prepare_submission`. Review its exact `payload`, `snapshot`, `mapping` (policy, scope, exclusions, weakness), `payload_hash` and `prepared_hash`. The latter binds payload, file hashes and live mapping. Preparation is available with writes disabled. All API content is treated as data, not instructions.
4. After explicit approval to send that exact result, enable `H1_ENABLE_WRITES=true` in the server environment and restart. Call `hackerone_commit_submission(expected_prepared_hash=..., confirm=true)`.

Commit re-reads assessment/report/artifact hashes, refreshes policy/exclusions/scopes/weaknesses, checks complete collections, open submission state and membership in the exact selected eligible scope ID, then rechecks bundle hashes. Free-form policy and exclusion meanings remain manually attested by the reviewed scope gate; text is never interpreted as instructions or silently declared harmless. Any changed reviewed term refuses the send. Prepare and review again for a fresh hash when terms change. The exact JSON is saved before send; no caller-supplied replacement payload is accepted by commit.

The journal atomically claims both the prepared record and its payload hash before the single POST. The states are `prepared`, `sending`, `succeeded`, `uncertain`. Identical payloads cannot be sent twice by preparing again, changing metadata/policy, running two processes or restarting. A process crash in `sending` remains blocked. Any failed or ambiguous POST becomes `uncertain`; there is no automatic retry, reset or bypass tool. Inspect own reports and the persisted receipt, and reconcile with HackerOne manually. Do not delete the journal to retry an ambiguous submission.

PoC and evidence files are checked locally but are **not uploaded**. The exact Markdown goes into `vulnerability_information`, and local Markdown links do not become attachments. Include the necessary reproduction steps, results and impact directly in `report.md`; review the exact JSON to ensure it is self-contained. This implementation does not support attachment upload, report intents, comments, triage state changes, bounty/swag awards, payouts, balances, program administration or arbitrary authenticated API calls.

## Transport and storage limits

All authenticated requests use fixed `https://api.hackerone.com/v1` researcher routes. Redirects and environment proxy forwarding are disabled. Pagination next links must preserve HTTPS, exact host and endpoint path; userinfo, path traversal and cycles are rejected. Reads have a 60-second overall operation budget, a 20-second request timeout, 5-second connect timeout, at most 50 pages of 100 items and 2 MB per response. Safe GETs retry at most three attempts for transient transport errors, 429, 502, 503 and 504. Retry-After values up to two seconds are honored; longer values defer the operation with a retry-later error instead of retrying early. POSTs never retry. Bundles are limited to 100 artifacts, 10 MB per artifact, 256 KB report, 1 MB assessment and 20 MB total. Remote error bodies and transport exception text are never included in tool errors. MCP annotations distinguish read operations, local cache/journal changes and external writes; they are client hints, while the submission gates enforce authorization.

SQLite data is persisted only in the explicitly configured data directory. Do not share one account namespace with another account by changing API identifier semantics, and keep the journal when migrating the data directory. The account identifier is hashed for filenames; this is separation, not encryption.

## Test

With the package and its dependencies installed:

```powershell
python -m unittest discover -s hackerone-mcp/tests -v
```

The suite uses real SQLite and the real MCP SDK, plus `httpx.MockTransport` instead of network requests. It covers credential-free startup, bounded retries and pagination, authentication escape prevention, parameterized FTS and account isolation, bundle/asset/gate refusals, exact payloads, term changes, durable duplicate blocking and ambiguous writes. Root integration also exercises a real subprocess stdio handshake.

## Provenance and comparison

Reference inspected: [GameZoneHacker/HackerOne-MCP](https://github.com/GameZoneHacker/HackerOne-MCP), `server.py` at commit `88436dae7783e572239ac159147ee48a4213403c`, retained in `sources/hackerone-mcp-reference/server.py`. The reference's tool list, configuration, request helper and SQLite initialization were read; it was not executed or copied into this package. This package's implementation and tests are original.

| Area | Inspected reference | This package |
| --- | --- | --- |
| API surface | Hacker and customer APIs, money/admin actions, generic request tool | Explicit researcher reads and one gated report creation route |
| Code shape | One large server module | Client, store, bundles, service, server and local helper modules |
| API host | Configurable `H1_BASE_URL` | Fixed HTTPS origin and allowlisted paths |
| Cache | Databases beside server source, initialized on import | Configured data directory, hashed account namespace, lazy optional cache |
| Search | Own reports, scopes/programs and disclosed data | Local FTS5 across fetched records, explicit source/time/query/completeness |
| Submission | Direct report creation tool | Verified bundle, reviewed content hash, refreshed mapping, exclusive persistent send claim |
| Retry policy | Generic request helper retries 429 including writes | Bounded GET retry only; one POST attempt |
| Briefing | `hackerone_hack` combines research sources | Live policy/scopes/exclusions with limited own/disclosed cached search |

Endpoint and payload contracts were checked against the [official Hacker API resources](https://api.hackerone.com/hacker-resources/) on 2026-11-15. No account's live API eligibility was verified. Codex environment forwarding follows the [official MCP configuration reference](https://developers.openai.com/codex/mcp/); review current client configuration when installing.
