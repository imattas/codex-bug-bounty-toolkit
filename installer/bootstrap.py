"""Interactive, dependency-free installer. --non-interactive emits a plan only.

Network/package installs happen only after local interactive consent. Credentials
are read from the controlling terminal and never command-line/config values.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zipfile

from credential_store import (CredentialError, load_credentials, preferred_backend,
                              private_directory, private_write, save_credentials,
                              is_redirect, validate_private_path, ensure_directory)


class InstallError(RuntimeError):
    pass


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 20000


def safe_extract(archive, destination: Path, *, max_total: int = MAX_EXTRACTED_BYTES) -> None:
    # The wrappers embed this exact archive validator; keep one source of truth.
    from archive_bootstrap import safe_extract as extract, BootstrapError
    try:
        extract(archive, destination, max_total=max_total)
    except BootstrapError as error:
        raise InstallError(str(error)) from None


def backup(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    target = path.with_name(f'{path.name}.backup-{stamp}-{uuid.uuid4().hex[:8]}')
    validate_private_path(path)
    if is_redirect(path):
        raise InstallError('Refusing to back up a symbolic link.')
    private_write(target, path.read_bytes())
    return target


def _write_config(path: Path, content: str, *, encoding: str = 'utf-8') -> None:
    if path.exists():
        backup(path)
    private_write(path, content.encode(encoding))


def _table_keys(line: str):
    """Parse quoted/dotted TOML table names with the stdlib parser itself."""
    stripped = line.strip()
    if not stripped.startswith('['):
        return None
    try:
        value = tomllib.loads(stripped + '\n__installer_probe = true\n')
        keys = []
        while isinstance(value, dict) and '__installer_probe' not in value:
            if len(value) != 1:
                return None
            key, value = next(iter(value.items()))
            keys.append(key)
        return keys if isinstance(value, dict) else None
    except tomllib.TOMLDecodeError:
        return None


def _codex_block(entry: dict) -> str:
    lines = ['[mcp_servers.hackerone]']
    for key, value in entry.items():
        if key != 'env':
            lines.append(f'{key} = {json.dumps(value, ensure_ascii=True)}')
    if entry.get('env'):
        lines.extend(['', '[mcp_servers.hackerone.env]'])
        for key, value in entry['env'].items():
            lines.append(f'{key} = {json.dumps(value, ensure_ascii=True)}')
    return '\n'.join(lines) + '\n'


def configure_codex(path: Path, entry: dict, *, replace: bool = False) -> None:
    path = Path(path)
    validate_private_path(path)
    original = path.read_text(encoding='utf-8-sig') if path.exists() else ''
    parsed = tomllib.loads(original)
    servers = parsed.get('mcp_servers', {})
    if not isinstance(servers, dict):
        raise InstallError('Existing Codex mcp_servers value is not a table; edit it manually.')
    if 'hackerone' in servers and not replace:
        raise InstallError('A HackerOne MCP registration already exists; replacement requires consent.')
    lines = []
    skip = False
    for line in original.splitlines(keepends=True):
        keys = _table_keys(line)
        if keys is not None:
            skip = keys[:2] == ['mcp_servers', 'hackerone']
        if not skip:
            lines.append(line)
    content = ''.join(lines).rstrip() + '\n\n' + _codex_block(entry)
    try:
        after = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        raise InstallError('This Codex TOML layout needs manual editing; the original was left intact.') from None
    expected = dict(parsed)
    expected['mcp_servers'] = {**servers, 'hackerone': entry}
    if after != expected:
        raise InstallError('Cannot preserve unrelated Codex settings in this layout; original left intact.')
    _write_config(path, content)


def configure_claude(path: Path, entry: dict, *, replace: bool = False) -> None:
    path = Path(path)
    validate_private_path(path)
    document = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    if not isinstance(document, dict) or not isinstance(document.get('mcpServers', {}), dict):
        raise InstallError('Existing Claude configuration has an unsupported layout.')
    servers = document.setdefault('mcpServers', {})
    if 'hackerone' in servers and not replace:
        raise InstallError('A HackerOne MCP registration already exists; replacement requires consent.')
    servers['hackerone'] = entry
    _write_config(path, json.dumps(document, indent=2, ensure_ascii=True) + '\n')


def default_runtime(home: Path) -> Path:
    if os.name == 'nt' and home == Path.home() and os.environ.get('LOCALAPPDATA'):
        return Path(os.environ['LOCALAPPDATA']) / 'bug-bounty-toolkit'
    return home / '.local' / 'share' / 'bug-bounty-toolkit'


def agent_list(choice: str) -> list[str]:
    return ['codex', 'claude'] if choice == 'both' else ([] if choice == 'skip' else [choice])


def plan_install(source: Path, home: Path, agents: str, mcp: bool, *, runtime: Path | None = None,
                 dashboard: bool = False):
    runtime = runtime or default_runtime(home)
    selected = agent_list(agents)
    operations = ['copy_private_runtime'] if mcp or dashboard else []
    if selected:
        operations += ['optional_agent_cli_and_runtimes', 'install_skills']
    if mcp or dashboard:
        operations.append('create_virtual_environment')
    if mcp:
        operations += ['install_python_dependencies',
                       'optional_private_credentials', 'configure_mcp', 'verify_local_imports']
    if dashboard:
        operations += ['create_dashboard_launchers', 'verify_dashboard_cli']
    codex_home = (Path(os.environ['CODEX_HOME']).expanduser() if home == Path.home() and os.environ.get('CODEX_HOME')
                  else home / '.codex')
    return {'mode': 'plan-only', 'source': str(source), 'home': str(home), 'agents': selected,
            'mcp': mcp, 'dashboard': dashboard, 'runtime': str(runtime),
            'skills': {agent: str((codex_home if agent == 'codex' else home / '.claude') / 'skills' / 'bug-bounty')
                       for agent in selected},
            'configs': {agent: str(codex_home / 'config.toml' if agent == 'codex' else home / '.claude.json')
                        for agent in selected if mcp},
            'external_writes_enabled': False, 'operations': operations}


class Console:
    """Open the controlling terminal, independently of piped installer stdin."""
    def __init__(self):
        try:
            self.input = open('CONIN$' if os.name == 'nt' else '/dev/tty', 'r', encoding='utf-8')
        except OSError:
            raise InstallError('Interactive setup requires a terminal. Use --non-interactive to print a plan.') from None

    def ask(self, message: str, default: str = '') -> str:
        suffix = f' [{default}]' if default else ''
        print(f'{message}{suffix}: ', end='', file=sys.stderr, flush=True)
        value = self.input.readline()
        if not value:
            raise InstallError('Terminal input ended; setup stopped.')
        return value.strip() or default

    def yes(self, message: str, *, default: bool = False) -> bool:
        while True:
            answer = self.ask(message + (' (Y/n)' if default else ' (y/N)'), 'yes' if default else 'no').lower()
            if answer in ('y', 'yes'):
                return True
            if answer in ('n', 'no'):
                return False

    def secret(self, message: str) -> str:
        # Never allow getpass's echoing fallback. It is unsafe for a token prompt.
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            try:
                return getpass.getpass(message + ': ')
            except (getpass.GetPassWarning, EOFError, OSError):
                raise InstallError('A hidden terminal token prompt is unavailable; no token was read.') from None

    def directory(self, message: str, default: Path) -> Path:
        while True:
            path = Path(self.ask(message, str(default))).expanduser().absolute()
            if path == Path(path.anchor) or path == Path.home():
                print('Choose a dedicated directory below your home or another explicit project directory.', file=sys.stderr)
                continue
            if any(is_redirect(item) for item in (path, *path.parents)):
                print('Choose a directory whose path does not traverse symbolic links or junctions.', file=sys.stderr)
                continue
            if path.exists() and not path.is_dir():
                print('That path is not a directory.', file=sys.stderr)
                continue
            return path.resolve()


def checked_run(command: list[str], **kwargs) -> None:
    # All commands are argument arrays; credential values must never enter them.
    clean_env = dict(os.environ)
    clean_env.pop('H1_USERNAME', None)
    clean_env.pop('H1_API_TOKEN', None)
    result = subprocess.run(command, env=clean_env, **kwargs)
    if result.returncode:
        raise InstallError('A setup command failed. Review its output; setup has stopped.')


def _check_source(source: Path) -> None:
    for required in ('bug-bounty/SKILL.md', 'hackerone-mcp/pyproject.toml',
                     'installer/launcher.py', 'installer/credential_store.py'):
        if not (source / required).is_file():
            raise InstallError(f'Toolkit source is incomplete: missing {required}.')


def _copy_tree(source: Path, target: Path) -> None:
    # No local checkout links may import arbitrary files into the private runtime.
    ignored = {'.venv', '__pycache__', '.git', '.pytest_cache', '.mypy_cache', '.ruff_cache',
               '.DS_Store', 'build', 'dist'}
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = [name for name in dirs if name not in ignored and not name.endswith('.egg-info')]
        for name in dirs + files:
            if is_redirect(Path(root) / name):
                raise InstallError('Toolkit source must not contain symbolic links or junctions.')
    shutil.copytree(source, target,
                    ignore=shutil.ignore_patterns(*ignored, '*.egg-info', '*.pyc', '*.pyo'))


def _replace_tree(source: Path, target: Path, console: Console, *, consent: bool = False) -> bool:
    validate_private_path(target)
    if is_redirect(target):
        raise InstallError('Refusing to replace a symbolic link.')
    if target.exists() and not consent and not console.yes(f'{target} already exists. Back it up and replace it?'):
        return False
    ensure_directory(target.parent)
    staging = Path(tempfile.mkdtemp(prefix=f'.{target.name}-staging-', dir=target.parent))
    private_directory(staging)
    # copytree requires an absent target; all later cleanup stays in this known staging path.
    incoming = staging / 'content'
    try:
        _copy_tree(source, incoming)
        private_directory(incoming)
        if target.exists():
            saved = target.with_name(target.name + '.backup-' + uuid.uuid4().hex[:12])
            target.rename(saved)
            print(f'Backup retained: {saved}', file=sys.stderr)
        incoming.rename(target)
    finally:
        if staging.resolve().parent == target.parent.resolve() and staging.name.startswith(f'.{target.name}-staging-'):
            shutil.rmtree(staging)
    return True


def _install_runtime_source(source: Path, runtime: Path, console: Console) -> bool:
    """Replace source subtrees only; leave credentials, settings, venv and journals in place."""
    validate_private_path(runtime)
    if runtime.exists() and not console.yes(f'{runtime} already exists. Back up and replace toolkit source files while retaining local credentials, settings and journals?'):
        return False
    private_directory(runtime)
    for component in ('bug-bounty', 'hackerone-mcp', 'installer'):
        _replace_tree(source / component, runtime / component, console, consent=True)
    return True


def dashboard_launchers(runtime: Path, python: Path, project: Path, console: Console) -> list[Path]:
    """Write launchers with literal path arguments; opening the dashboard stays a user action."""
    script = runtime / 'bug-bounty/scripts/webui.py'
    if os.name == 'nt':
        ps1 = runtime / 'Open Bug Bounty Dashboard.ps1'
        cmd = runtime / 'Open Bug Bounty Dashboard.cmd'
        paths = [ps1, cmd]
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        ps = "$ErrorActionPreference = 'Stop'\n& " + ' '.join(quote(value) for value in
                    (python, '-B', script, '--root', project, '--port', '8765', '--open')) + '\nexit $LASTEXITCODE\n'
        # Windows paths cannot contain a quote. Disable delayed expansion and double
        # percent characters to preserve literal paths in batch file interpretation.
        batch_quote = lambda value: '"' + str(value).replace('%', '%%') + '"'
        batch = '@echo off\r\nsetlocal DisableDelayedExpansion\r\nchcp 65001 >nul\r\n' + ' '.join(batch_quote(value) for value in
                    (python, '-B', script, '--root', project, '--port', '8765', '--open')) + '\r\n'
        contents = [ps, batch]
    else:
        paths = [runtime / 'Open Bug Bounty Dashboard.sh']
        contents = ['#!/bin/sh\nexec ' + ' '.join(shlex.quote(str(value)) for value in
                    (python, '-B', script, '--root', project, '--port', '8765', '--open')) + '\n']
    if any(path.exists() for path in paths) and not console.yes('Dashboard launchers already exist. Back them up and replace their configured root?'):
        print('Existing dashboard launchers retained with their previous root.', file=sys.stderr)
        return paths
    for path, content in zip(paths, contents):
        # Windows PowerShell 5.1 treats a BOM-less script as the ANSI codepage.
        _write_config(path, content, encoding='utf-8-sig' if path.suffix == '.ps1' else 'utf-8')
        if os.name != 'nt':
            path.chmod(0o700)
    return paths


def _offer_agents(selected: list[str], console: Console, home: Path):
    from runtimes import offer_agents, RuntimeInstallError
    try:
        offer_agents(selected, console, home, checked_run)
    except RuntimeInstallError as error:
        raise InstallError(str(error)) from None


def _existing_registration(path: Path, agent: str) -> bool:
    if not path.exists():
        return False
    if agent == 'codex':
        document = tomllib.loads(path.read_text(encoding='utf-8-sig'))
        return 'hackerone' in document.get('mcp_servers', {})
    document = json.loads(path.read_text(encoding='utf-8-sig'))
    return 'hackerone' in document.get('mcpServers', {})


def _credentials(runtime: Path, console: Console) -> None:
    directory = runtime / 'private'
    if not console.yes('Connect a HackerOne account now? Credentials stay local; local tools also work without an account'):
        return
    if (directory / 'credentials.json').exists() and not console.yes('Replace the existing stored credentials?'):
        return
    backend = preferred_backend()
    allow_plaintext = False
    if backend == 'file':
        print('No usable system keyring was found. The fallback is a PLAINTEXT credential file, restricted to your user (0600 inside 0700). It is not encrypted.', file=sys.stderr)
        if not console.yes('Use this plaintext credential file?'):
            print('Account connection skipped. Install Python keyring with an available system backend and rerun to use the system keyring.', file=sys.stderr)
            return
        allow_plaintext = True
    else:
        print('Credential storage: ' + ('Windows DPAPI, encrypted for your Windows user.' if backend == 'dpapi'
                                       else 'system keyring; unlocking may require your desktop prompt.'), file=sys.stderr)
    identifier = console.ask('HackerOne API identifier (username)')
    token = console.secret('HackerOne API token (hidden)')
    save_credentials(directory, identifier, token, allow_plaintext=allow_plaintext, backend=backend)
    # Verify locally only; never make an API request from setup.
    stored = load_credentials(directory)
    if stored != (identifier, token):
        raise InstallError('Local credential storage verification failed.')
    del token, stored
    print('Credentials saved and locally verified. No HackerOne API request was made.', file=sys.stderr)


def interactive(source: Path, home: Path) -> None:
    _check_source(source)
    console = Console()
    print('Bug bounty toolkit setup. Network installs and file replacements require your choices below.', file=sys.stderr)
    while True:
        choice = console.ask('Agents: codex, claude, both, or skip', 'codex').lower()
        if choice in ('codex', 'claude', 'both', 'skip'):
            break
    selected = agent_list(choice)
    mcp = console.yes('Install the optional HackerOne MCP and local execution tools?', default=True)
    dashboard = console.yes('Install the local bug bounty dashboard?', default=True)
    needs_runtime = mcp or dashboard
    if not selected and not needs_runtime:
        print('No components selected. No changes made.', file=sys.stderr)
        return
    plan = plan_install(source, home, choice, mcp, dashboard=dashboard)
    runtime = None
    data_dir = None
    project = None
    browser = False
    if needs_runtime:
        runtime = console.directory('Private toolkit installation directory', Path(plan['runtime']))
        if source.is_relative_to(runtime) or runtime == source:
            raise InstallError('The installation directory cannot contain or replace the source checkout.')
        if mcp:
            data_dir = console.directory('Private HackerOne data/cache directory', home / '.local' / 'share' / 'bug-bounty-data')
        project = console.directory('Engagement/project root (local tools are confined to this directory)', home / 'bug-bounty-engagements')
        if (data_dir and data_dir.is_relative_to(runtime)) or project.is_relative_to(runtime):
            raise InstallError('Data and engagements must be outside the replaceable toolkit installation directory.')
        if mcp:
            browser = console.yes('Install optional Chromium browser support? This downloads a large browser separately')
    print('Selected agents: ' + (', '.join(selected) or 'none'), file=sys.stderr)
    for agent, target in plan['skills'].items():
        print(f'{agent} skill: {target}', file=sys.stderr)
    if runtime:
        print(f'Runtime: {runtime}\nEngagement root: {project}', file=sys.stderr)
        if data_dir:
            print(f'Data: {data_dir}', file=sys.stderr)
    if not console.yes('Proceed with these directories and selected components?'):
        print('Setup cancelled. No changes made.', file=sys.stderr)
        return
    _offer_agents(selected, console, home)
    skill_paths = {}
    for agent, target_text in plan['skills'].items():
        target = Path(target_text)
        if _replace_tree(source / 'bug-bounty', target, console):
            skill_paths[agent] = target
            print(f'Installed {agent} skill: {target}', file=sys.stderr)
        else:
            print(f'Skipped {agent} skill; existing directory retained.', file=sys.stderr)
    if not needs_runtime:
        print('Skill setup finished. Open a new agent session to load the skill.', file=sys.stderr)
        return
    assert runtime and project
    if not _install_runtime_source(source, runtime, console):
        print('Runtime setup skipped; existing installation retained.', file=sys.stderr)
        return
    if data_dir:
        private_directory(data_dir)
    project.mkdir(parents=True, exist_ok=True)
    checked_run([sys.executable, '-m', 'venv', str(runtime / '.venv')])
    python = runtime / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if dashboard:
        checked_run([str(python), '-B', str(runtime / 'bug-bounty/scripts/webui.py'), '--help'])
        for path in dashboard_launchers(runtime, python, project, console):
            print(f'Open the local dashboard with: {path}', file=sys.stderr)
    if not mcp:
        print('Dashboard setup finished. Use the launcher above to open it locally.', file=sys.stderr)
        return
    assert data_dir
    dependencies = [str(python), '-m', 'pip', 'install', str(runtime / 'hackerone-mcp'),
                    '-r', str(runtime / 'bug-bounty/scripts/requirements-cvss.txt')]
    if os.name != 'nt':
        dependencies.append('keyring>=25,<26')
    checked_run(dependencies)
    if browser:
        checked_run([str(python), '-m', 'pip', 'install', '-r', str(runtime / 'bug-bounty/scripts/requirements-browser.txt')])
        checked_run([str(python), '-m', 'playwright', 'install', 'chromium'])
    checked_run([str(python), '-B', '-c', 'import hackerone_mcp.server; import cvss; print("Local package imports verified.")'])
    # Probe/store under the launcher's interpreter so the same keyring backend is available.
    checked_run([str(python), '-B', str(runtime / 'installer/bootstrap.py'),
                 '--connect-account', '--source', str(runtime)])
    for agent in selected:
        config = Path(plan['configs'][agent])
        existing = _existing_registration(config, agent)
        if existing and not console.yes(f'{config} already registers hackerone. Back it up and replace that registration?'):
            print(f'Skipped {agent} MCP registration.', file=sys.stderr)
            continue
        entry = {'command': str(python), 'args': ['-B', str(runtime / 'installer/launcher.py')],
                 'env': {'H1_DATA_DIR': str(data_dir), 'H1_ENABLE_WRITES': 'false',
                         'BUG_BOUNTY_SKILL_DIR': str(runtime / 'bug-bounty'),
                         'BUG_BOUNTY_PROJECT_ROOT': str(project)}}
        if agent == 'codex':
            entry['tool_timeout_sec'] = 300
            configure_codex(config, entry, replace=existing)
        else:
            configure_claude(config, {'type': 'stdio', **entry}, replace=existing)
        # Reopen and parse the actual written config before claiming registration.
        if not _existing_registration(config, agent):
            raise InstallError('MCP registration could not be verified.')
        print(f'Configured {agent} MCP: {config}', file=sys.stderr)
    if not selected:
        print(f'No agent selected. MCP runtime is ready at {runtime}; rerun setup to register an agent.', file=sys.stderr)
    print('Setup finished. Open a new agent session. HackerOne writes remain disabled; account validity has not been checked.', file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--home', type=Path, default=Path.home(), help='target home (useful for isolated plans/tests)')
    parser.add_argument('--non-interactive', '--plan', action='store_true', help='print a JSON plan; perform no writes/downloads/prompts')
    parser.add_argument('--agents', choices=('codex', 'claude', 'both', 'skip'), default='codex', help='plan mode only')
    parser.add_argument('--mcp', action='store_true', help='include optional MCP in plan mode')
    parser.add_argument('--dashboard', action='store_true', help='include local dashboard in plan mode')
    parser.add_argument('--connect-account', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        print('Python 3.11+ is required. Install Python from https://www.python.org/downloads/ and rerun.', file=sys.stderr)
        return 1
    try:
        if args.non_interactive:
            print(json.dumps(plan_install(args.source.resolve(), args.home.absolute(), args.agents, args.mcp,
                                          dashboard=args.dashboard), indent=2))
        elif args.connect_account:
            _credentials(args.source.resolve(), Console())
        else:
            interactive(args.source.resolve(), args.home.absolute())
        return 0
    except (InstallError, CredentialError) as error:
        print(f'Setup stopped: {error}', file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        # Tracebacks may contain locals; never print one in a credential-handling installer.
        print('Setup stopped. No live account action was performed. Check the preceding command output and selected file permissions; existing backups are retained.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nSetup cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
