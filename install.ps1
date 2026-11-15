# Generated from installer/templates/install.ps1.in + archive_bootstrap.py.
# Local: .\install.ps1    Remote: irm HTTPS_RELEASE/install.ps1 | iex
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$SourceUrl = $env:BBT_SOURCE_URL,
    [string]$ExpectedSha256 = $env:BBT_SOURCE_SHA256,
    [string]$SourceDir = $env:BBT_SOURCE_DIR,
    [switch]$NonInteractive,
    [string]$Agents,
    [switch]$Mcp,
    [switch]$Dashboard,
    [string]$HomeDir,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$InstallerArguments = @()
)
$ErrorActionPreference = 'Stop'
if ($env:BBT_NON_INTERACTIVE -eq '1') { $NonInteractive = $true }
$DEFAULT_SOURCE_URL = '__TOOLKIT_SOURCE_URL__'
$DEFAULT_EXPECTED_SHA256 = '__TOOLKIT_SOURCE_SHA256__'
if ($DEFAULT_SOURCE_URL.StartsWith('__TOOLKIT_')) { $DEFAULT_SOURCE_URL = '' }
if ($DEFAULT_EXPECTED_SHA256.StartsWith('__TOOLKIT_')) { $DEFAULT_EXPECTED_SHA256 = '' }
if (-not $SourceUrl) { $SourceUrl = $DEFAULT_SOURCE_URL }
if (-not $ExpectedSha256) { $ExpectedSha256 = $DEFAULT_EXPECTED_SHA256 }
if ($NonInteractive) { $InstallerArguments = @('--non-interactive') + $InstallerArguments }
if ($Agents) { $InstallerArguments += @('--agents', $Agents) }
if ($Mcp) { $InstallerArguments += '--mcp' }
if ($Dashboard) { $InstallerArguments += '--dashboard' }
if ($HomeDir) { $InstallerArguments += @('--home', $HomeDir) }

function Confirm-ToolkitStep([string]$Message) {
    if ($NonInteractive -or $InstallerArguments -contains '--non-interactive' -or $InstallerArguments -contains '--plan') { return $false }
    $reply = Read-Host "$Message (y/N)"
    return $reply -match '^(y|yes)$'
}

$pythonCommand = $null
$pythonPrefix = @()
foreach ($candidate in @('py', 'python3', 'python')) {
    $found = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { continue }
    $prefix = @()
    if ($candidate -eq 'py') { $prefix = @('-3') }
    try {
        & $found.Source @prefix -c 'import sys, sysconfig; raise SystemExit(sys.version_info < (3, 11) or sys.implementation.name != ''cpython'' or bool(sysconfig.get_config_var(''Py_GIL_DISABLED'')))' 2>$null | Out-Null
    } catch {
        # Windows application aliases may exist but fail rather than start Python.
        continue
    }
    if ($LASTEXITCODE -eq 0) { $pythonCommand = $found.Source; $pythonPrefix = $prefix; break }
}
if (-not $pythonCommand) {
    $uvCommand = Get-Command uv -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $uvPath = if ($uvCommand) { $uvCommand.Source } else { Join-Path $HOME '.local/bin/uv.exe' }
    if (-not (Test-Path -LiteralPath $uvPath -PathType Leaf)) {
        if (-not (Confirm-ToolkitStep 'Standard GIL-enabled CPython 3.11+ was not found. Download and run the official https://astral.sh/uv/install.ps1 installer to install uv for your user (no admin needed)?')) {
            throw 'Standard GIL-enabled CPython 3.11+ is required. Install from https://www.python.org/downloads/ or https://docs.astral.sh/uv/getting-started/installation/ and rerun.'
        }
        # HttpClient bounds the downloaded script and rejects HTTP redirects before requesting them.
        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(60)
        $uvUri = [Uri]'https://astral.sh/uv/install.ps1'
        try {
            for ($redirect = 0; $redirect -le 10; $redirect++) {
                if ($uvUri.Scheme -ne 'https' -or $uvUri.UserInfo) { throw 'uv installer redirect must remain HTTPS without credentials.' }
                $response = $client.GetAsync($uvUri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
                    if (-not $response.Headers.Location) { throw 'uv installer redirect has no location.' }
                    $uvUri = New-Object Uri($uvUri, $response.Headers.Location)
                    $response.Dispose()
                    continue
                }
                $response.EnsureSuccessStatusCode() | Out-Null
                if ($response.Content.Headers.ContentLength -gt 2097152) { throw 'uv installer exceeds size limit.' }
                $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $memory = New-Object System.IO.MemoryStream
                $buffer = New-Object byte[] 16384
                $readClock = [Diagnostics.Stopwatch]::StartNew()
                try {
                    while ($true) {
                        $readTask = $stream.ReadAsync($buffer, 0, $buffer.Length)
                        if (-not $readTask.Wait(30000)) { throw 'uv installer download timed out.' }
                        $count = $readTask.GetAwaiter().GetResult()
                        if ($readClock.Elapsed.TotalSeconds -gt 120) { throw 'uv installer download exceeded its total time limit.' }
                        if ($count -eq 0) { break }
                        if ($memory.Length + $count -gt 2097152) { throw 'uv installer exceeds size limit.' }
                        $memory.Write($buffer, 0, $count)
                    }
                    $uvScript = [Text.Encoding]::UTF8.GetString($memory.ToArray())
                } finally { $stream.Dispose(); $memory.Dispose(); $response.Dispose() }
                break
            }
            if (-not $uvScript) { throw 'uv installer could not be downloaded.' }
        } finally { $client.Dispose(); $handler.Dispose() }
        $oldInstallDir = $env:UV_INSTALL_DIR
        $oldNoModify = $env:UV_NO_MODIFY_PATH
        try {
            $env:UV_INSTALL_DIR = Join-Path $HOME '.local/bin'
            $env:UV_NO_MODIFY_PATH = '1'
            & ([ScriptBlock]::Create($uvScript))
        } finally { $env:UV_INSTALL_DIR = $oldInstallDir; $env:UV_NO_MODIFY_PATH = $oldNoModify }
        if (-not (Test-Path -LiteralPath $uvPath -PathType Leaf)) { throw 'uv setup did not produce the expected executable; setup stopped.' }
    }
    if (-not (Confirm-ToolkitStep 'Install a user-local Python 3.13 runtime with uv (download from the uv Python distribution)?')) { throw 'Python setup declined; toolkit setup stopped.' }
    & $uvPath python install 3.13
    if ($LASTEXITCODE -ne 0) { throw 'Python runtime installation failed.' }
    $pythonCommand = (& $uvPath python find --managed-python 3.13 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonCommand -PathType Leaf)) { throw 'Installed Python executable was not found.' }
    & $pythonCommand -c 'import sys, sysconfig; raise SystemExit(sys.version_info < (3, 11) or sys.implementation.name != ''cpython'' or bool(sysconfig.get_config_var(''Py_GIL_DISABLED'')))'
    if ($LASTEXITCODE -ne 0) { throw 'Standard GIL-enabled CPython 3.11+ validation failed.' }
}

# iex has no reliable PSScriptRoot. Also support an explicit checkout or checkout cwd.
if (-not $SourceDir -and -not $SourceUrl) {
    if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'installer/bootstrap.py'))) { $SourceDir = $PSScriptRoot }
    elseif (Test-Path -LiteralPath (Join-Path (Get-Location).Path 'installer/bootstrap.py')) { $SourceDir = (Get-Location).Path }
}
if ($SourceDir) {
    $bootstrap = Join-Path $SourceDir 'installer/bootstrap.py'
    if (-not (Test-Path -LiteralPath $bootstrap -PathType Leaf)) { throw 'Source directory is not a complete toolkit checkout.' }
    & $pythonCommand @pythonPrefix -B $bootstrap --source $SourceDir @InstallerArguments
    if ($LASTEXITCODE -ne 0) { throw "Toolkit setup failed (exit $LASTEXITCODE)." }
    return
}
$embeddedBootstrap = @'
"""Self-contained HTTPS ZIP bootstrap, embedded verbatim in the shell wrappers.

Keep this file dependency-free: it runs before any toolkit code is available.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 20000


class BootstrapError(RuntimeError):
    pass


def is_redirect(path: Path) -> bool:
    try:
        info = Path(path).lstat()
        return Path(path).is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)
    except FileNotFoundError:
        return False


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme.lower() != 'https' or not parsed.hostname or parsed.username is not None or
        parsed.password is not None or parsed.fragment or any(ord(char) <= 32 for char in url)):
        raise BootstrapError('Source URL must be HTTPS, with no embedded credentials or fragment.')
    return url


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


def open_https(url: str):
    return urllib.request.build_opener(HTTPSRedirects()).open(url, timeout=30)


def download(url: str, destination: Path, *, expected: str = '', max_bytes: int = MAX_ARCHIVE_BYTES,
             max_seconds: int = 180) -> None:
    validate_url(url)
    if expected and not re.fullmatch(r'[0-9a-fA-F]{64}', expected):
        raise BootstrapError('Expected SHA256 must contain exactly 64 hexadecimal characters.')
    digest = hashlib.sha256()
    destination = Path(destination)
    created = False
    deadline = time.monotonic() + max_seconds
    try:
        with open_https(url) as response:
            validate_url(response.geturl())
            length = response.headers.get('Content-Length')
            if length and int(length) > max_bytes:
                raise BootstrapError('Source archive exceeds the download limit.')
            with destination.open('xb') as outgoing:
                created = True
                count = 0
                while chunk := response.read(64 * 1024):
                    count += len(chunk)
                    if time.monotonic() > deadline:
                        raise BootstrapError('Source download exceeded its time limit.')
                    if count > max_bytes:
                        raise BootstrapError('Source archive exceeds the download limit.')
                    digest.update(chunk)
                    outgoing.write(chunk)
        if expected and digest.hexdigest().lower() != expected.lower():
            raise BootstrapError('Source archive SHA256 does not match; nothing will be executed.')
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise


def safe_extract(archive, destination: Path, *, max_total: int = MAX_EXTRACTED_BYTES) -> None:
    destination = Path(destination)
    if destination.exists() or is_redirect(destination):
        raise BootstrapError('Archive destination must not already exist.')
    if any(is_redirect(parent) for parent in destination.parents):
        raise BootstrapError('Archive destination must not traverse symbolic links.')
    try:
        with zipfile.ZipFile(archive) as source:
            entries = source.infolist()
            if not entries or len(entries) > MAX_ARCHIVE_FILES:
                raise BootstrapError('Archive contains an invalid number of entries.')
            total, seen = 0, set()
            for entry in entries:
                name = entry.filename
                components = name.rstrip('/').split('/')
                mode = (entry.external_attr >> 16) & 0o170000
                if (not name or '\\' in name or name.startswith('/') or
                    any(part in ('', '.', '..') or ':' in part for part in components) or
                    any(part.rstrip(' .') != part for part in components) or
                    any(re.fullmatch(r'(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part, re.I)
                        for part in components) or
                    any(ord(char) < 32 for char in name) or
                    mode not in (0, stat.S_IFREG, stat.S_IFDIR) or entry.flag_bits & 1):
                    raise BootstrapError('Archive contains an unsafe path or entry type.')
                key = '/'.join(components).casefold()
                if key in seen:
                    raise BootstrapError('Archive contains duplicate paths.')
                seen.add(key)
                total += entry.file_size
                if total > max_total or entry.file_size > max_total:
                    raise BootstrapError('Archive exceeds extraction size limit.')
                if not destination.joinpath(*components).resolve().is_relative_to(destination.resolve()):
                    raise BootstrapError('Archive path escapes destination.')
            destination.mkdir(mode=0o700, parents=False)
            written = 0
            for entry in entries:
                target = destination.joinpath(*entry.filename.rstrip('/').split('/'))
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(entry) as incoming, target.open('xb') as outgoing:
                    while chunk := incoming.read(64 * 1024):
                        written += len(chunk)
                        if written > max_total:
                            raise BootstrapError('Archive exceeds extraction size limit.')
                        outgoing.write(chunk)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, BootstrapError):
            raise
        raise BootstrapError('Archive is invalid or could not be safely extracted.') from None


def ask(message: str, default: str = '') -> str:
    try:
        with open('CONIN$' if os.name == 'nt' else '/dev/tty', 'r', encoding='utf-8') as terminal:
            print(message + (f' [{default}]' if default else '') + ': ', end='', file=sys.stderr, flush=True)
            value = terminal.readline()
            if not value:
                raise BootstrapError('Terminal input ended.')
            return value.strip() or default
    except OSError:
        raise BootstrapError('Remote bootstrap requires a terminal, or an explicit source URL and SHA256.') from None


def find_source(extracted: Path) -> Path:
    required = ('installer/bootstrap.py', 'installer/archive_bootstrap.py',
                'installer/credential_store.py', 'installer/launcher.py',
                'bug-bounty/SKILL.md', 'hackerone-mcp/pyproject.toml')
    candidates = [extracted] + [path for path in extracted.iterdir() if path.is_dir()]
    matches = [path for path in candidates if all((path / name).is_file() for name in required)]
    if len(matches) != 1:
        raise BootstrapError('Archive must contain exactly one complete toolkit root.')
    return matches[0]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-url', default='')
    parser.add_argument('--sha256', default='')
    args, remaining = parser.parse_known_args(argv)
    try:
        url = args.source_url or ask('HTTPS toolkit release ZIP URL')
        validate_url(url)
        expected = args.sha256
        if not expected:
            expected = ask('Expected source ZIP SHA256 (optional; blank trusts the HTTPS source)')
            if not expected and ask('No checksum supplied. Trust this HTTPS archive and execute its installer? (y/N)', 'no').lower() not in ('y', 'yes'):
                raise BootstrapError('Bootstrap cancelled; no source was downloaded.')
        with tempfile.TemporaryDirectory(prefix='bug-bounty-bootstrap-') as tmp:
            work = Path(tmp).resolve()
            archive = work / 'source.zip'
            print('Downloading toolkit archive (maximum 64 MiB).', file=sys.stderr)
            download(url, archive, expected=expected)
            extracted = work / 'extracted'
            safe_extract(archive, extracted)
            source = find_source(extracted)
            return subprocess.call([sys.executable, '-B', str(source / 'installer/bootstrap.py'),
                                    '--source', str(source), *remaining])
    except BootstrapError as error:
        print(f'Bootstrap stopped: {error}', file=sys.stderr)
        return 1
    except (OSError, ValueError, zipfile.BadZipFile):
        print('Bootstrap failed to download or validate the HTTPS source archive. Nothing was installed.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nBootstrap cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
'@
$embeddedBootstrap | & $pythonCommand @pythonPrefix -B - "--source-url=$SourceUrl" "--sha256=$ExpectedSha256" @InstallerArguments
if ($LASTEXITCODE -ne 0) { throw "Toolkit bootstrap failed (exit $LASTEXITCODE)." }
