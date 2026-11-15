# Controlled local execution

`scripts/engagement_runtime.py` uses the Python standard library. It performs real
HTTP requests only after an explicit URL allowlist check and an atomic shared
budget reservation. Importing either runtime performs no network activity. Supply
an authorized engagement project directory; the helpers do not determine program
authorization or whether an HTTP observation proves a vulnerability.

## HTTP import API

```python
from engagement_runtime import init_budget, replay, budget_status

# Create once per engagement; an existing budget cannot be reset accidentally.
init_budget(project, max_requests=12, rate_per_second=2,
            concurrency=1, duration_seconds=60)

# Environment variable contains the complete header, e.g. "Bearer owned-lab-a".
result = replay(project, "alice", "http://127.0.0.1:8000/exports/b1",
                allowlist=["http://127.0.0.1:8000/exports"],
                credential_env={"Authorization": "LAB_ALICE_AUTH"})
assert result["status"] == 200
print(result["body"], result["response_path"])
```

Add the skill's `scripts` directory to your import path. Public signatures:

```python
init_budget(project, *, max_requests=30, rate_per_second=2.0,
            concurrency=1, duration_seconds=300) -> Path
budget_status(project) -> dict
reserve(project, *, timeout=10, wait=False) -> str
release(project, token) -> None
stop_budget(project, reason="target-distress") -> None
replay(project, actor, url, *, allowlist, **options) -> dict
ReplayClient(project, *, allowlist).replay(actor, url, **options) -> dict
```

Replay options are `method="GET"`, `credential_env=None`, `headers=None`,
`body=None` (text or bytes), `allow_write=False`, `timeout=10`, `retries=0`,
`max_response_bytes=1048576`, `follow_redirects=False`, `max_redirects=3`,
`secret_envs=()`, and `secret_literals=()`. Sensitive headers must be supplied as
environment references through `credential_env`, rather than literal `headers`.
Explicit redaction literals are for fixture markers or additional sensitive
content; credentials belong in environment references. HTTP cookies remain in
memory in separate jars for each `(actor, origin)`; the module-level function
reuses clients within one Python process. `ReplayClient` provides explicit jar
lifetime. Neither API exports cookies or credential values to disk.
Reserved routing/framing headers, including Host, Content-Length,
Transfer-Encoding and proxy authorization, are rejected in both ordinary headers
and credential environment references before budget consumption. Every repeated
Set-Cookie value and accepted cookie-jar value is collected for same-response
body redaction; duplicate cookie headers are preserved until that collection.

GET and HEAD are the defaults. Owned state changes require `allow_write=True`;
automatic retries and redirects for writes are disabled. Retries are finite
(0–3) and cover transport errors on reads. Each attempt and each followed redirect
consumes a fresh reservation. Default redirects are captured without being
followed. Explicitly enabled redirects must pass the allowlist again; credentials
and cookies never transfer between origins. Environment proxy configuration is
ignored; HTTPS uses ordinary certificate verification.

Allowlist entries are exact normalized HTTP(S) origins with an optional path
prefix. A root origin permits its paths. `/api` permits `/api` and `/api/...`,
but not `/apix`. Scheme, hostname and port must match; the default port is
normalized. Userinfo, fragments, ambiguous slash encodings, backslashes and dot
traversal are rejected. Hostname suffixes and wildcard targets are not accepted.
Loopback endpoints are allowed only when explicitly listed.

Every response has `status`, redacted decoded `body`, `body_source`, `truncated`,
`captured_bytes`, `sha256`, `hash_source`, `error`, `actor`, UTC timestamp and
`observations`. All filesystem paths are absolute: `evidence_dir`,
`request_path`, `response_path`, `metadata_path` and `attempt_paths`. A transport
failure returns `body_source="transport-error"` and a safe exception class name,
without copying exception text. Status codes alone never confirm a finding.
Replay requests identity encoding; unexpected encoded response bodies are omitted
from persisted evidence to avoid storing encoded secrets. The hash describes
the capped original bytes before redaction, not the redacted text file. A
truncated capture cannot stand in for a complete response. Bodies are decoded
with UTF-8 replacement for evidence; the helper is not a binary downloader.

Evidence is saved under task-unique `project/evidence/http-.../` directories as
redacted `request.json`, `response.json` and `metadata.json`. Authorization,
cookies and common structured secret fields are removed. Known credential values
and explicitly supplied markers are also removed from text, including common
JSON/URL escaped forms. Session credentials remembered in memory remain redacted
on subsequent calls. Inspect artifact content before sharing; unknown application
secrets require explicit redaction inputs. Meaningful response-content proof,
expected authorization and ownership remain analyst decisions.

## Persistent shared budget

`project/.engagement/budget.sqlite3` stores limits, counts, a stop condition,
the next permitted start time and active concurrency leases. No URLs or
credentials are stored there. SQLite immediate transactions serialize reservations
across independent scripts and processes. Rate limiting spaces request starts;
it is not a per-client burst allowance. Total requests and wall-clock deadline
persist across client restarts. Lease expiry is `timeout + 1` seconds to recover
from a crashed process, while bounded transports stop their active sockets by
their timeout. Explicit `release` only releases concurrency; it never refunds an
attempt. Do not delete or edit the database to bypass a live engagement limit.
Each internal path is resolved and checked against the configured project before
use. Child symlinks, NTFS junctions and files with multiple hard links are rejected for the budget database,
SQLite companion files, evidence directories, JSON files and screenshots. The
project itself must remain caller-owned: this is not protection against a local
adversary concurrently replacing directories between filesystem operations.

429, 503 or `Retry-After` signals stop the whole project persistently. Subsequent
HTTP and browser reservations fail with `BudgetExceeded`. Create a distinct
project only for a separately authorized engagement. `RuntimePolicyError` and
its `ScopeError`/`BudgetExceeded` subclasses identify policy failures. Policy
failures before sending do not consume request total. Some failures after a
reservation may have reached the target and always consume that reservation.

## Browser API

Browser support uses optional Playwright's synchronous Python API and a locally
installed Chromium binary. Missing dependencies raise an actionable
`BrowserUnavailable`; the runtime never installs or downloads dependencies.
The manager must launch its own Chromium. Supplying a caller-managed `browser=`
raises `BrowserUnavailable`, because the adapter cannot establish that process's
launch-time network restrictions.

```python
from browser_sessions import BrowserSessionManager

with BrowserSessionManager(project,
        allowlist=["http://127.0.0.1:8000"], timeout=10,
        max_response_bytes=1048576) as browser:
    browser.new_session("alice", credential_env={
        "Authorization": "LAB_ALICE_AUTH"})
    browser.new_session("bob", credential_env={
        "Authorization": "LAB_BOB_AUTH"})
    navigation = browser.navigate("alice", "http://127.0.0.1:8000/dashboard")
    capture = browser.screenshot("alice", mask_selectors=[".private-email"])
```

```python
BrowserSessionManager(project, *, allowlist, browser=None, headless=True,
                      timeout=10, allow_write=False,
                      max_response_bytes=1048576)
manager.new_session(actor, *, credential_env=None, secret_literals=()) -> dict
manager.navigate(actor, url) -> dict
manager.screenshot(actor, *, mask_selectors=()) -> dict
manager.close() -> None
```

Every identity gets a fresh, independent, non-persistent browser context. Cookie
and storage isolation is enforced by Chromium contexts. Each identity binds to
its first navigation's exact origin; other-origin navigation and subresources
are blocked even when another origin appears in the engagement allowlist. Use
another identity for that origin. This conservative restriction also prevents
browser domain cookies from leaking across different ports on the same hostname.
Unscoped redirects, subresources, requests before initial navigation and writes
without `allow_write` are blocked. Service workers and WebSockets are blocked so
they cannot bypass routing. Downloads are disabled. TLS, CSP and browser sandbox
protections remain enabled.

Owned Chromium is launched with a local deny-only HTTP proxy and
`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`. The proxy performs no
DNS resolution, forwarding or CONNECT tunneling and has no direct fallback.
Chromium's implicit loopback bypass is explicitly removed using `<-loopback>`.
Allowed HTTP traffic is fetched only by the scoped, budgeted Python transport
and fulfilled into the browser. Native WebRTC UDP is prohibited; TURN over TCP
or TLS reaches the rejecting proxy instead of its destination. These are
browser-process controls, rather than JavaScript constructor replacements, so
new frames cannot restore an unrestricted WebRTC constructor. Chromium documents
the [forced WebRTC policy switch](https://raw.githubusercontent.com/chromium/chromium/main/content/public/common/content_switches.cc),
the [non-proxied UDP restriction](https://raw.githubusercontent.com/chromium/chromium/main/third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.cc)
and [proxy loopback bypass removal](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md).

Each browser request uses the same SQLite budget and a bounded HTTP transport,
then is fulfilled into the actual browser page. Responses exceeding the byte
cap are captured as truncated evidence and blocked from rendering. This routing
is designed for controlled HTTP application testing; it does not reproduce a
browser's native HTTP/2 transport, client certificates, streaming, WebSockets or
service worker behavior. WebRTC/STUN/TURN testing is intentionally unsupported.
Browser reservations fail closed when rate or
concurrency limits are busy. A navigation timeout closes that identity's context.
Do not treat a partially loaded page as a successful scenario.

`navigate` returns `status`, `body_source="browser-navigation-status"`, absolute
`network_paths` for captured response metadata, and redacted blocking
observations. Browser response directories contain redacted request, response
and metadata JSON with capped-body hashes. `screenshot` returns an absolute
`screenshot_path`, `metadata_path`, SHA-256 hash, actor and UTC time. Screenshots
mask password inputs, known secret text and (when credentials are present) form
controls; supply additional `mask_selectors` for application-specific private
data. No browser storage state or profile is exported. The page remains available
through `manager.sessions[actor]["page"]` for caller-driven owned fixture actions;
HTTP traffic still passes the interception controls, and native WebRTC traffic
is denied by the launch policy/proxy. This is application-level confinement
tested against the installed Chromium, rather than an operating-system network
sandbox for a compromised browser binary or malicious caller with Python access.

## CLI and local validation

```powershell
py -3.15 bug-bounty/scripts/engagement_runtime.py init C:/tmp/owned-lab --max-requests 12 --duration-seconds 60
py -3.15 bug-bounty/scripts/engagement_runtime.py replay C:/tmp/owned-lab alice http://127.0.0.1:8000/exports/b1 --allow http://127.0.0.1:8000 --credential-env Authorization=LAB_ALICE_AUTH
py -3.15 bug-bounty/scripts/engagement_runtime.py status C:/tmp/owned-lab
py -3.15 bug-bounty/scripts/browser_sessions.py C:/tmp/owned-lab alice http://127.0.0.1:8000/ --allow http://127.0.0.1:8000 --screenshot
```

Browser setup belongs in an explicitly selected local environment, for example:

```powershell
py -3.15 -m pip install --target .browser-deps playwright
$env:PYTHONPATH="$PWD/.browser-deps;$PWD/.validation-deps"
$env:PLAYWRIGHT_BROWSERS_PATH="$PWD/.browser-binaries"
py -3.15 -m playwright install chromium
$env:BUG_BOUNTY_REAL_BROWSER='1'
py -3.15 -m unittest discover -s bug-bounty/tests
```

Tests use only loopback HTTP, UDP and TCP fixtures. Opt-in real-browser tests
exercise Chromium cookie/localStorage isolation, identity credentials, blocked
writes, capped responses, PNG capture and zero STUN/TURN UDP datagrams or
unlisted TURN TCP/TLS connections after the budget is exhausted. The WebRTC
regression keeps positive-control listeners alive throughout browser startup and
tests native constructors in both the top-level page and a fresh frame. Without
the flag, injected launch-adapter tests still run and real-browser tests report
skips. NTFS junction tests execute on Windows; other platforms use directory
symlinks. No real program or external target is contacted by validation.
