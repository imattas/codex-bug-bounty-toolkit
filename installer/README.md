# Interactive installers

From an extracted distribution or checkout:

```powershell
.\install.ps1
```

```sh
sh ./install.sh
```

The native scripts require standard, GIL-enabled CPython 3.11+ (`py -3`,
`python3`, `python` on Windows; `python3`, `python` on POSIX). Free-threaded
interpreters are skipped because native MCP dependencies may lack compatible
wheels. If a supported interpreter is absent, they offer the official user-local
[uv installer](https://docs.astral.sh/uv/getting-started/installation/) and a
uv-managed Python 3.13 download. Each step needs local interactive consent.
No administrator access, sudo, or global pip installation is used.

Setup asks for Codex CLI, Claude Code, both, or skip, then optional HackerOne MCP
and the local dashboard (offered by default independently of HackerOne).
Missing selected CLIs can be installed using Node/npm already present or a
consented user-local official Node LTS download. Node artifacts are checked
against the SHA256 manifest fetched over HTTPS from nodejs.org; the manifest
does not receive an independent signing-key verification. Automatic Node setup
supports Windows/macOS/glibc Linux on x64/arm64. Other platforms receive an
actionable manual prerequisite message. npm installs use an explicit private
user prefix, and selected client versions are checked. Agent authentication is
still the agent's normal local login step. PATH changes require a separate
prompt, preserve the user's existing PATH/profile, and take effect in a new
terminal. Declining a runtime/client leaves an honest skipped-client message.

HackerOne setup asks for dedicated runtime, private cache, and engagement-root
directories; optional Chromium; and optionally API identifier plus hidden token.
Windows uses current-user DPAPI and a protected current-user/SYSTEM DACL. POSIX
prefers an available system `keyring` backend inside the installed virtual
environment. If it is unavailable, a clearly labeled **plaintext** 0600 file in
a 0700 directory is offered only with explicit opt-in. No API request validates
the token. Tokens never appear in agent JSON/TOML, command arguments, or installer
logs. The launcher loads them locally and injects them into the server process.
Its standard streams remain available for MCP protocol traffic.

Skills go to `$CODEX_HOME/skills/bug-bounty` or `~/.codex/skills/bug-bounty` for
Codex, and `~/.claude/skills/bug-bounty` for Claude. MCP registrations go to
`$CODEX_HOME/config.toml` (or `~/.codex/config.toml`) and `~/.claude.json`.
Unrelated settings are preserved and existing configs get private backups.
Replacing an existing skill, runtime, or same-named MCP registration needs an
explicit backup-and-replace choice. Unusual TOML layouts that cannot be modified
while preserving all parsed unrelated values are left intact with an error.
Private/config paths reject symbolic links and Windows junction/reparse points.
Existing parent directory permissions, including HOME and LOCALAPPDATA, are
preserved. Only dedicated toolkit/credential directories and private files are
restricted. Reinstall replaces source subtrees while retaining credentials,
operator settings, the virtual environment, data and journals in place; declining
to connect a new HackerOne account keeps the stored account.

The dashboard needs only the Python standard library. Choosing it without MCP
installs a private runtime/virtual environment without HackerOne dependencies or
credentials. Setup writes `Open Bug Bounty Dashboard.ps1` and `.cmd` on Windows,
or `Open Bug Bounty Dashboard.sh` on POSIX, in the chosen runtime directory and
prints their exact paths. Run the launcher to open the browser on the loopback
dashboard at port 8765. Setup does not start a background dashboard. Existing
launchers need consent before replacement and receive backups. The launchers
pass the chosen engagement root as a literal argument.

The launcher's default forces `H1_ENABLE_WRITES=false`, including when its parent
environment says true. An operator can deliberately add `--enable-writes` after
`launcher.py` in their MCP `args` to opt in later. Setup never adds that flag.
The server's separate reviewed prepare/commit and program authorization checks
still apply. This does not grant target authorization or change agent permissions.

## Hosted / pipe execution

Release wrappers can embed an immutable archive URL and expected SHA256 using
the render markers `__TOOLKIT_SOURCE_URL__` and `__TOOLKIT_SOURCE_SHA256__`.
Their source archive contains the unrendered wrappers, avoiding a hash cycle.
An unrendered remote wrapper asks for the actual HTTPS ZIP URL and optional
SHA256. If no digest is supplied, it asks explicitly before trusting and running
the HTTPS archive. There is no assumed upstream hosting origin.

To supply a custom source URL without editing a wrapper:

```powershell
$env:BBT_SOURCE_URL = 'https://YOUR_HOST/PATH/toolkit.zip'
$env:BBT_SOURCE_SHA256 = 'YOUR_64_HEX_DIGEST'
# Then pipe the reviewed hosted install.ps1 to iex.
# Or: .\install.ps1 -SourceUrl $env:BBT_SOURCE_URL -ExpectedSha256 $env:BBT_SOURCE_SHA256
```

```sh
# Set these in the shell executing the downloaded wrapper:
export BBT_SOURCE_URL='https://YOUR_HOST/PATH/toolkit.zip'
export BBT_SOURCE_SHA256='YOUR_64_HEX_DIGEST'
# Then pipe the reviewed hosted install.sh to sh.
# Or: sh ./install.sh --source-url "$BBT_SOURCE_URL" --sha256 "$BBT_SOURCE_SHA256"
```

`BBT_SOURCE_DIR` explicitly selects a local checkout/extracted source directory,
including during pipe execution. `-SourceDir` / `--source-dir` do the same for
file execution. Remote downloads require HTTPS on every redirect, allow HTTPS
CDNs, reject embedded URL credentials, cap source archives at 64 MiB and expanded
content at 256 MiB / 20,000 entries, reject traversal/links/devices/duplicate
paths, and extract to a fresh temporary directory. Source download time and read
timeouts are bounded. Existing arbitrary files are never overwritten by archive
extraction. Interactive Python and POSIX prompts use the controlling terminal
(`CONIN$` / `/dev/tty`) rather than the pipe carrying script source.

## Offline checks / no-change plans

```powershell
.\install.ps1 -NonInteractive -Agents both -Mcp -Dashboard -HomeDir 'C:\temporary\test home'
python -B -m unittest discover -s installer/tests -v
```

```sh
sh ./install.sh --non-interactive --agents both --mcp --dashboard --home '/tmp/test home'
python3 -B -m unittest discover -s installer/tests -v
```

`--non-interactive` (alias `--plan`) emits JSON and never applies anything. It
accepts no secrets. The wrappers also recognize `BBT_NON_INTERACTIVE=1`, useful
for testing pipe execution. A missing Python prerequisite fails plan mode without
installing it. A remote plan still needs an explicit source URL and SHA256 to
avoid source-trust prompts; use a local checkout for a completely offline plan.

The tests perform real temporary-home file/config updates, DPAPI fixture
roundtrips on Windows, native junction rejection, hostile ZIP/TAR checks, mocked
HTTPS source downloads, mocked package/runtime installs, and plan-mode native
wrapper execution. They never contact a live HackerOne account or globally
install an agent or runtime. POSIX wrapper tests run only on POSIX hosts.

After changing `installer/archive_bootstrap.py` or wrapper templates, regenerate:

```text
python -B installer/render_wrappers.py
```
