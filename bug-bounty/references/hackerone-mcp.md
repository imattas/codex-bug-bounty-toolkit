# HackerOne MCP workflow

The toolkit's separate `hackerone-mcp` package exposes the local helpers and a researcher-focused HackerOne API integration. Use the connected tool namespace when available; installed skill text alone does not mean the server or account is connected. Full setup is in the toolkit root README and `hackerone-mcp/README.md`.

## Engage a program

1. Check server status without exposing credentials. Missing account credentials do not block local scoring, supplied-evidence review or the local pilot.
2. Fetch the exact program's live policy, structured scopes, scope exclusions and weaknesses. Check submission state, eligible assets and relevant class/technique exclusions. API reachability and Daybreak access are not target authorization.
3. Sync accessible own reports and relevant disclosed activity, then search the local cache and local finding keys. Inspect freshness, query and pagination completeness. Neither Hacktivity nor own reports covers all private submissions. Compare root cause, not just title or CWE.
4. Record program/scope IDs, sources/times and actual decisions in the engagement. Turn a structured eligible row into an explicit runtime allowlist only after resolving actual targets and relevant exclusions. The HTTP runner uses exact origins/path boundaries, not broad wildcard discovery rules.

## Local execution tools

MCP exposes budget initialization/status, bounded HTTP replay, isolated browser captures, scoring, OpenAPI inventory, local duplicate candidates, gated bundle creation and a loopback pilot. Filesystem tools require an explicitly configured `BUG_BOUNTY_PROJECT_ROOT`; paths cannot escape it. Authentication headers are supplied by environment references. Do not place secrets in tool arguments or arbitrary headers.

Read [execution runtime](execution-runtime.md) before live requests. Every attempt consumes the engagement budget, including retries and allowed redirects. Default state-changing tests are blocked unless separately authorized. Browser captures use separate contexts and ordinary protections; inspect images and masks before sharing.

## Reviewable submissions

Only an accepted `findings/<slug>` bundle can enter preparation. The platform mapping verifies the selected program, structured scope ID/eligibility, conservative asset membership and primary weakness against fresh data. Program policy and exclusions remain material human/Codex checks; the API cannot interpret every prose restriction for you.

Preparation returns the exact JSON payload, reviewed bundle/content hashes and live mapping. Review the full report, destination, impact and severity. The server does not upload PoC/evidence files: local relative links are not platform attachments. Essential reproduction and results must be understandable in the report itself; attach other files manually through the intended platform workflow where needed.

Sending is a separate explicitly authorized commit of the reviewed hash with writes enabled. The server refreshes the mapping, rechecks files and persists the send claim before one POST. It does not automatically retry an ambiguous write or permit re-preparing identical content to bypass the journal. Use the receipt and own-report listing to reconcile `sending`/`uncertain`; do not delete state to force a resend.

## Limits

This implementation intentionally exposes researcher workflows, not bounty awards, payouts, program administration or arbitrary authenticated API requests. It provides source-aware duplicate research, not a uniqueness guarantee. Offline tests validate behavior using mocks and owned loopback fixtures; live API credentials and program access require actual verification in the user's environment.
