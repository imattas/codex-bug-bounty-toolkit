"""Consented, user-local Node/npm bootstrap for missing agent CLIs.

Node archives and their SHA256 manifest come from HTTPS nodejs.org. The manifest
is authenticated by HTTPS, not by an independently verified signing key.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

from archive_bootstrap import BootstrapError, download, safe_extract, is_redirect
from credential_store import private_directory, private_write, validate_private_path


class RuntimeInstallError(RuntimeError):
    pass


def extract_node_tar(archive: Path, destination: Path) -> None:
    """Extract only directories/regular files. npm's optional bin symlinks are skipped."""
    validate_private_path(destination)
    if destination.exists():
        raise RuntimeInstallError('Node extraction destination already exists.')
    with tarfile.open(archive, 'r:*') as source:
        entries = []
        total = 0
        seen = set()
        for entry in source:
            entries.append(entry)
            if len(entries) > 30000:
                raise RuntimeInstallError('Node archive has too many entries.')
            parts = PurePosixPath(entry.name).parts
            if (not parts or PurePosixPath(entry.name).is_absolute() or '\\' in entry.name or
                any(part in ('', '.', '..') or ':' in part or part.rstrip(' .') != part for part in parts) or
                any(ord(char) < 32 for char in entry.name) or
                not (entry.isfile() or entry.isdir() or entry.issym() or entry.islnk())):
                raise RuntimeInstallError('Node archive contains an unsafe path/type.')
            key = '/'.join(parts).casefold()
            if key in seen:
                raise RuntimeInstallError('Node archive contains duplicate paths.')
            seen.add(key)
            total += entry.size
            if total > 512 * 1024 * 1024:
                raise RuntimeInstallError('Node archive exceeds extraction size limit.')
        destination.mkdir(mode=0o700)
        written = 0
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.name).parts)
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif entry.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                incoming = source.extractfile(entry)
                if incoming is None:
                    raise RuntimeInstallError('Node archive file could not be read.')
                with incoming, target.open('xb') as outgoing:
                    while chunk := incoming.read(64 * 1024):
                        written += len(chunk)
                        if written > 512 * 1024 * 1024:
                            raise RuntimeInstallError('Node archive exceeds extraction size limit.')
                        outgoing.write(chunk)
                target.chmod(0o700 if entry.mode & 0o111 else 0o600)


def _target() -> tuple[str, str]:
    system = {'Windows': 'win', 'Darwin': 'darwin', 'Linux': 'linux'}.get(platform.system())
    arch = {'amd64': 'x64', 'x86_64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if not system or not arch:
        raise RuntimeInstallError('Automatic Node setup supports Windows, macOS and Linux on x64/arm64. Install Node LTS from https://nodejs.org/en/download and rerun.')
    if system == 'linux' and platform.libc_ver()[0].lower() != 'glibc':
        raise RuntimeInstallError('Automatic Node setup requires glibc Linux. Install Node/npm with your distribution package manager and rerun.')
    return system, arch


def install_node(home: Path) -> tuple[Path, Path]:
    system, arch = _target()
    base = home / '.local' / 'share' / 'bug-bounty-runtimes'
    private_directory(base)
    with tempfile.TemporaryDirectory(prefix='.node-bootstrap-', dir=base) as tmp:
        work = Path(tmp).resolve()
        index = work / 'index.json'
        download('https://nodejs.org/dist/index.json', index, max_bytes=4 * 1024 * 1024)
        releases = json.loads(index.read_text())
        release = next((row for row in releases if row.get('lts') and
                        re.fullmatch(r'v\d+\.\d+\.\d+', row.get('version', '')) and
                        f'{system}-{arch}' + ('-zip' if system == 'win' else '') in row.get('files', [])), None)
        if not release:
            # Node index uses osx-*-tar for macOS, so select by a platform-aware key below.
            key = f'osx-{arch}-tar' if system == 'darwin' else f'{system}-{arch}' + ('-zip' if system == 'win' else '')
            release = next((row for row in releases if row.get('lts') and
                            re.fullmatch(r'v\d+\.\d+\.\d+', row.get('version', '')) and key in row.get('files', [])), None)
        if not release:
            raise RuntimeInstallError('No supported official Node LTS archive was found.')
        version = release['version']
        extension = 'zip' if system == 'win' else 'tar.gz'
        filename = f'node-{version}-{system}-{arch}.{extension}'
        final = base / f'node-{version}-{system}-{arch}'
        node = final / ('node.exe' if system == 'win' else 'bin/node')
        npm = final / ('node_modules/npm/bin/npm-cli.js' if system == 'win' else 'lib/node_modules/npm/bin/npm-cli.js')
        validate_private_path(final)
        if node.is_file() and npm.is_file():
            return node, npm
        if final.exists():
            raise RuntimeInstallError('A partial Node runtime already exists. Rename it and rerun setup: ' + str(final))
        print(f'Downloading official Node {version} LTS for {system}/{arch}; verifying the HTTPS SHASUMS manifest.', file=sys.stderr)
        manifest = work / 'SHASUMS256.txt'
        download(f'https://nodejs.org/dist/{version}/SHASUMS256.txt', manifest, max_bytes=1024 * 1024)
        digest = None
        for line in manifest.read_text().splitlines():
            pieces = line.split()
            if len(pieces) == 2 and pieces[1].lstrip('*') == filename and re.fullmatch(r'[0-9a-fA-F]{64}', pieces[0]):
                digest = pieces[0]
                break
        if not digest:
            raise RuntimeInstallError('Official Node SHA256 manifest does not list the expected archive.')
        archive = work / filename
        download(f'https://nodejs.org/dist/{version}/{filename}', archive, expected=digest, max_bytes=128 * 1024 * 1024)
        extracted = work / 'extracted'
        if system == 'win':
            safe_extract(archive, extracted, max_total=512 * 1024 * 1024)
        else:
            extract_node_tar(archive, extracted)
        top = extracted / final.name
        if not (top / node.relative_to(final)).is_file() or not (top / npm.relative_to(final)).is_file():
            raise RuntimeInstallError('Official Node archive did not contain node and npm as expected.')
        top.rename(final)
        return node, npm


def existing_node() -> tuple[Path, Path] | None:
    node, npm = shutil.which('node'), shutil.which('npm')
    if not node or not npm:
        return None
    try:
        result = subprocess.run([node, '--version'], capture_output=True, text=True, timeout=15)
        if result.returncode or int(result.stdout.strip().lstrip('v').split('.')[0]) < 20:
            return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    npm_path = Path(npm)
    candidates = [npm_path.resolve(), npm_path.parent / 'node_modules/npm/bin/npm-cli.js']
    cli = next((path for path in candidates if path.name == 'npm-cli.js' and path.is_file()), None)
    return (Path(node), cli) if cli else None


def _persist_path(paths: list[Path], home: Path, console) -> None:
    directories = [str(path) for path in paths]
    if not console.yes('Add ' + os.pathsep.join(directories) + ' to your user PATH for future terminals?'):
        print('User PATH was left unchanged. Add these directories before starting the agent: ' + os.pathsep.join(directories), file=sys.stderr)
        return
    if os.name == 'nt':
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
            try:
                value, kind = winreg.QueryValueEx(key, 'Path')
            except FileNotFoundError:
                value, kind = '', winreg.REG_EXPAND_SZ
            existing = value.split(';')
            additions = [path for path in directories if path.casefold() not in {item.casefold() for item in existing}]
            winreg.SetValueEx(key, 'Path', 0, kind, ';'.join(additions + ([value] if value else [])))
        print('User PATH updated. Open a new terminal (or restart the desktop app) before using the agent.', file=sys.stderr)
    else:
        shell = Path(os.environ.get('SHELL', '/bin/sh')).name
        target = home / ('.zprofile' if shell == 'zsh' else '.profile')
        if shell == 'fish':
            target = home / '.config/fish/conf.d/bug-bounty-toolkit.fish'
            line = 'fish_add_path -- ' + ' '.join(shlex.quote(path) for path in directories)
        else:
            line = 'export PATH=' + shlex.quote(':'.join(directories)) + ':"$PATH"'
        validate_private_path(target)
        original = target.read_text() if target.exists() else ''
        if line not in original.splitlines():
            if target.exists():
                from bootstrap import backup
                backup(target)
            private_write(target, (original.rstrip() + '\n\n# Bug bounty toolkit agent runtimes\n' + line + '\n').encode())
        print(f'PATH configured in {target}. Start a new login shell before using the agent.', file=sys.stderr)


def offer_agents(selected: list[str], console, home: Path, run) -> None:
    packages = {'codex': '@openai/codex', 'claude': '@anthropic-ai/claude-code'}
    missing = []
    for agent in selected:
        if shutil.which(agent):
            print(f'Found {agent}.', file=sys.stderr)
        elif console.yes(f'{agent} is absent. Install {packages[agent]} into a private user directory (including Node/npm if needed)?'):
            missing.append(agent)
        else:
            print(f'{agent} installation skipped. Its skill/config can still be prepared; install the CLI before use.', file=sys.stderr)
    if not missing:
        return
    pair = existing_node()
    if pair is None:
        if not console.yes('A usable Node 20+ and npm were not found. Download official Node LTS and npm into your user directory, verified against its HTTPS SHA256 manifest?', default=True):
            print('Agent CLI installation skipped because Node/npm setup was declined.', file=sys.stderr)
            return
        try:
            pair = install_node(home)
        except BootstrapError as error:
            raise RuntimeInstallError(str(error)) from None
    node, npm = pair
    prefix = home / '.local' / 'share' / 'bug-bounty-agent-cli'
    private_directory(prefix)
    node_bin = node.parent
    command_bin = prefix if os.name == 'nt' else prefix / 'bin'
    os.environ['PATH'] = os.pathsep.join([str(node_bin), str(command_bin), os.environ.get('PATH', '')])
    for agent in missing:
        package = packages[agent]
        run([str(node), str(npm), 'install', '--global', '--prefix', str(prefix), package])
        package_dir = prefix / ('node_modules' if os.name == 'nt' else 'lib/node_modules') / package
        metadata = json.loads((package_dir / 'package.json').read_text())
        binary = metadata.get('bin', {})
        relative = binary.get(agent) if isinstance(binary, dict) else binary
        if not relative or not isinstance(relative, str):
            raise RuntimeInstallError(f'Installed {agent} package has no expected executable.')
        executable = (package_dir / relative).resolve()
        if not executable.is_relative_to(package_dir.resolve()) or not executable.is_file():
            raise RuntimeInstallError(f'Installed {agent} executable is outside its package or missing.')
        run([str(node), str(executable), '--version'])
        print(f'Installed and verified {agent}. Agent account sign-in remains a separate local CLI step.', file=sys.stderr)
    _persist_path([node_bin, command_bin], home, console)
