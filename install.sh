#!/bin/sh
# Generated from installer/templates/install.sh.in + archive_bootstrap.py.
# Local: sh ./install.sh    Remote: curl -fsSL HTTPS_RELEASE/install.sh | sh
set -eu

DEFAULT_SOURCE_URL='__TOOLKIT_SOURCE_URL__'
DEFAULT_EXPECTED_SHA256='__TOOLKIT_SOURCE_SHA256__'
case "$DEFAULT_SOURCE_URL" in __TOOLKIT_*) DEFAULT_SOURCE_URL='' ;; esac
case "$DEFAULT_EXPECTED_SHA256" in __TOOLKIT_*) DEFAULT_EXPECTED_SHA256='' ;; esac
SOURCE_URL=${BBT_SOURCE_URL:-$DEFAULT_SOURCE_URL}
EXPECTED_SHA256=${BBT_SOURCE_SHA256:-$DEFAULT_EXPECTED_SHA256}
SOURCE_DIR=${BBT_SOURCE_DIR:-}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir) [ "$#" -ge 2 ] || exit 2; SOURCE_DIR=$2; shift 2 ;;
        --source-url) [ "$#" -ge 2 ] || exit 2; SOURCE_URL=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || exit 2; EXPECTED_SHA256=$2; shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done
NONINTERACTIVE=${BBT_NON_INTERACTIVE:-0}
if [ "$NONINTERACTIVE" = 1 ]; then set -- --non-interactive "$@"; fi
for installer_arg do
    case "$installer_arg" in --non-interactive|--plan) NONINTERACTIVE=1 ;; esac
done

ask_yes() {
    [ "$NONINTERACTIVE" -eq 0 ] || return 1
    printf '%s (y/N): ' "$1" >&2
    if ! IFS= read -r installer_answer </dev/tty; then
        printf '%s\n' 'Interactive setup requires a controlling terminal.' >&2
        return 1
    fi
    case "$installer_answer" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

PYTHON=''
for installer_candidate in python3 python; do
    if command -v "$installer_candidate" >/dev/null 2>&1 &&
       "$installer_candidate" -c 'import sys, sysconfig; raise SystemExit(sys.version_info < (3, 11) or sys.implementation.name != "cpython" or bool(sysconfig.get_config_var("Py_GIL_DISABLED")))' >/dev/null 2>&1; then
        PYTHON=$(command -v "$installer_candidate")
        break
    fi
done
if [ -z "$PYTHON" ]; then
    UV=''
    if command -v uv >/dev/null 2>&1; then UV=$(command -v uv)
    elif [ -x "$HOME/.local/bin/uv" ]; then UV=$HOME/.local/bin/uv
    elif [ -x "$HOME/.cargo/bin/uv" ]; then UV=$HOME/.cargo/bin/uv
    fi
    if [ -z "$UV" ]; then
        if ! ask_yes 'Standard GIL-enabled CPython 3.11+ was not found. Download and run the official https://astral.sh/uv/install.sh installer to install uv for your user (no sudo)?'; then
            printf '%s\n' 'Standard GIL-enabled CPython 3.11+ is required. Install from https://www.python.org/downloads/ or https://docs.astral.sh/uv/getting-started/installation/ and rerun.' >&2
            exit 1
        fi
        if ! command -v curl >/dev/null 2>&1; then
            printf '%s\n' 'curl is needed for the uv bootstrap. Install curl, or install Python 3.11+ yourself and rerun.' >&2
            exit 1
        fi
        installer_tmp=$(mktemp -d "${TMPDIR:-/tmp}/bug-bounty-uv.XXXXXXXX")
        trap 'rm -f "$installer_tmp/uv-install.sh"; rmdir "$installer_tmp" 2>/dev/null || true' EXIT HUP INT TERM
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --max-time 60 --max-filesize 2097152 https://astral.sh/uv/install.sh -o "$installer_tmp/uv-install.sh"
        UV_INSTALL_DIR="$HOME/.local/bin" UV_NO_MODIFY_PATH=1 sh "$installer_tmp/uv-install.sh"
        UV=$HOME/.local/bin/uv
        [ -x "$UV" ] || { printf '%s\n' 'uv setup did not produce the expected executable; setup stopped.' >&2; exit 1; }
        rm -f "$installer_tmp/uv-install.sh"
        rmdir "$installer_tmp"
        trap - EXIT HUP INT TERM
    fi
    if ! ask_yes 'Install a user-local Python 3.13 runtime with uv (download from the uv Python distribution)?'; then
        printf '%s\n' 'Python setup declined; toolkit setup stopped.' >&2
        exit 1
    fi
    "$UV" python install 3.13
    PYTHON=$("$UV" python find --managed-python 3.13)
    "$PYTHON" -c 'import sys, sysconfig; raise SystemExit(sys.version_info < (3, 11) or sys.implementation.name != "cpython" or bool(sysconfig.get_config_var("Py_GIL_DISABLED")))' || exit 1
fi

# Piped execution has no script path; BBT_SOURCE_DIR or a checkout cwd still works.
if [ -z "$SOURCE_DIR" ] && [ -z "$SOURCE_URL" ]; then
    installer_script_dir=$(CDPATH= cd -P "$(dirname "$0")" 2>/dev/null && pwd) || installer_script_dir=''
    if [ -n "$installer_script_dir" ] && [ -f "$installer_script_dir/installer/bootstrap.py" ]; then
        SOURCE_DIR=$installer_script_dir
    elif [ -f './installer/bootstrap.py' ] && [ -f './bug-bounty/SKILL.md' ]; then
        SOURCE_DIR=$(pwd -P)
    fi
fi
if [ -n "$SOURCE_DIR" ]; then
    [ -f "$SOURCE_DIR/installer/bootstrap.py" ] || { printf '%s\n' 'Source directory is not a complete toolkit checkout.' >&2; exit 1; }
    exec "$PYTHON" -B "$SOURCE_DIR/installer/bootstrap.py" --source "$SOURCE_DIR" "$@"
fi

# This Python is embedded in the reviewed wrapper; downloaded code runs only after validation.
exec "$PYTHON" -B - --source-url "$SOURCE_URL" --sha256 "$EXPECTED_SHA256" "$@" <<'BBT_PYTHON_BOOTSTRAP'
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
BBT_PYTHON_BOOTSTRAP
