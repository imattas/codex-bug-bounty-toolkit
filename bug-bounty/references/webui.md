# Local findings dashboard

Run with Python 3.11 or newer; no frontend packages or extra Python dependencies are needed:

```text
python scripts/webui.py --root /path/to/engagements --port 8765 --open
```

Open the printed `http://127.0.0.1:8765` URL. `--open` optionally opens your browser; omit it for terminal-only startup. Use `--port 0` for an available port. When the requested CLI port is occupied, the CLI starts its own server on an available port and prints/opens that actual URL. Other binding errors are reported. Ctrl+C stops the server. The installer creates an **Open Bug Bounty Dashboard** launcher pointing at your chosen engagement directory.

The root may be a single engagement or a parent containing engagements. Discovery checks the root and directories up to two levels below it. It reads `findings/<slug>/report.md`, the corresponding assessment subset, and `.bug-bounty/candidates` JSON or note files up to two levels beneath the candidates directory. It inspects at most 5,000 directory entries, displays at most 1,000 records, and verifies at most 32 MiB of artifacts per scan. A banner identifies truncated discovery; choose a narrower root when this occurs. Files larger than 4 MiB and assessment or state JSON larger than 256 KiB are excluded. Refresh rescans the root.

Reports and candidates appear separately under **Actionable** and **Held for review**, using the toolkit's existing recorded gates. A report without an assessment stays held. A JSON candidate with passing recorded gates may be actionable without a generated report. Unstructured notes remain held. The viewer never confirms a vulnerability, generates a report, changes gate metadata, executes a PoC, or submits to HackerOne.

Candidate JSON uses the toolkit's structured assessment schema, a `{title, program, reason}` note subset, or recognized rejection categories such as `informational`, `duplicate`, and `out_of_scope` mapped to explanatory strings. Arbitrary request/configuration JSON fields are ignored. Text notes are opaque held placeholders. Original supporting files already referenced by a report assessment's `poc_files` or `evidence_files` are excluded from candidate counts.

Select a finding to read the report, inspect recorded gate statuses, and preview or download supporting artifacts. A small safe Markdown subset displays headings, paragraphs, lists, and fenced code using text nodes; HTML and links remain literal text. Only reviewed artifacts listed in `artifact_sha256`, located directly inside the finding's `poc/` or `evidence/`, and matching their recorded SHA-256 digest are available. The internal assessment is excluded. Other internal configuration and credentials are never enumerated. Reports and supporting evidence may contain sensitive information intentionally captured by the operator; review and redact artifacts before creating a report bundle. PNG and JPEG previews require matching file signatures. Code, HTML, SVG, and other downloads are attachments with `nosniff`; text previews use text nodes and never execute markup. External report links are displayed as text.

Manual **Unreviewed**, **Reviewed**, **Submitted**, **Fixed**, and **Archived** statuses and review notes are saved only to `<root>/.bug-bounty-webui/state.json`. These are your tracking labels, independent of scope, confirmation, actionability, or duplicate gates. Selecting Submitted records your own action; it does not send anything. Back up this directory with your engagements if you want to preserve tracking. Avoid notes containing credentials.

The server binds exclusively to `127.0.0.1`. It validates the exact loopback Host and browser Origin, rejects cross-site requests and `Origin: null`, supplies no CORS headers, and requires a per-server CSRF token for bounded JSON updates. Use the printed IP URL, rather than localhost, a proxy, or a public tunnel. Discovery and reads reject symlinks, Windows junctions, and multiply hardlinked files. The caller-owned root and its directories must not be concurrently replaced by another local process; this standard-library tool does not provide a defense against a hostile process already able to rewrite engagement files.

Search by title, program, reference, or ID. Filter by program and workflow status. Use Tab and Enter to select findings, Up/Down to move between finding buttons, and `/` to focus search. Loading, empty, truncated, and failed requests show explicit states.

For embedding in local tooling, `create_server(root: Path, port=0)` returns an unstarted `ThreadingHTTPServer`. Call `serve_forever()` in your own thread, then `shutdown()`, `server_close()`, and join the thread. Its `origin` property gives the bound URL.

Tests run offline:

```text
python -m unittest discover -s bug-bounty/tests -p test_webui.py
```

Set `BUG_BOUNTY_REAL_BROWSER=1` and point `PLAYWRIGHT_BROWSERS_PATH` at an existing Playwright browser installation to enable the optional real browser test. It verifies rendering, local tracking, search, responsive width, and writes `artifacts/webui-preview.png`. It uses an ordinary local Playwright browser and temporary loopback fixtures, with no target testing or external requests.
