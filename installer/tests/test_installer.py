"""Offline installer regression checks; no account or package manager calls."""
import io
import hashlib
import contextlib
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import sqlite3
import tomllib
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap
import credential_store
import launcher
import archive_bootstrap


def permissions(path):
    """Compare real directory security without changing it."""
    if os.name != 'nt':
        return path.stat().st_mode & 0o7777
    get_security = ctypes.WinDLL('advapi32', use_last_error=True).GetFileSecurityW
    get_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    get_security.restype = wintypes.BOOL
    needed = wintypes.DWORD()
    get_security(str(path), 7, None, 0, ctypes.byref(needed))
    data = ctypes.create_string_buffer(needed.value)
    if not get_security(str(path), 7, data, needed.value, ctypes.byref(needed)):
        raise OSError('Could not capture directory permissions for the regression test.')
    return data.raw


class InstallerTests(unittest.TestCase):
    def test_config_writes_keep_existing_home_and_config_parent_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            codex = home / '.codex'
            codex.mkdir(mode=0o755)
            if os.name != 'nt':
                home.chmod(0o755)
                codex.chmod(0o755)
            before = {path: permissions(path) for path in (home, codex)}
            bootstrap.configure_claude(home / '.claude.json', {'command': 'python'})
            bootstrap.configure_codex(codex / 'config.toml', {'command': 'python'})
            self.assertEqual({path: permissions(path) for path in before}, before)
            if os.name != 'nt':
                self.assertEqual((home / '.claude.json').stat().st_mode & 0o777, 0o600)
            else:
                # SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PROTECTED: final private
                # files do not inherit a broad parent's permissions.
                for path in (home / '.claude.json', codex / 'config.toml'):
                    self.assertTrue(int.from_bytes(permissions(path)[2:4], 'little') & 0x1000)

    def test_codex_preserves_settings_and_requires_explicit_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.toml'
            original = 'model = "custom"\n[mcp_servers.other]\ncommand = "existing"\n'
            path.write_text(original)
            entry = {'command': 'C:/private path/python.exe', 'args': ['-B', 'launcher.py'],
                     'env': {'H1_ENABLE_WRITES': 'false'}}
            bootstrap.configure_codex(path, entry)
            parsed = tomllib.loads(path.read_text())
            self.assertEqual(parsed['model'], 'custom')
            self.assertEqual(parsed['mcp_servers']['other']['command'], 'existing')
            self.assertEqual(parsed['mcp_servers']['hackerone'], entry)
            before = path.read_bytes()
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.configure_codex(path, {'command': 'replacement'})
            self.assertEqual(path.read_bytes(), before)
            bootstrap.configure_codex(path, {'command': 'replacement'}, replace=True)
            self.assertEqual(tomllib.loads(path.read_text())['mcp_servers']['other']['command'], 'existing')
            self.assertTrue(list(Path(tmp).glob('config.toml.backup-*')))

    def test_claude_preserves_unrelated_values_and_contains_no_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.claude.json'
            path.write_text(json.dumps({'theme': 'dark', 'mcpServers': {'existing': {'command': 'other'}}}))
            bootstrap.configure_claude(path, {'command': 'python', 'args': ['private/launcher.py']})
            result = json.loads(path.read_text())
            self.assertEqual(result['theme'], 'dark')
            self.assertEqual(result['mcpServers']['existing'], {'command': 'other'})
            self.assertNotIn('H1_API_TOKEN', path.read_text())

    def test_archive_rejects_traversal_absolute_symlink_and_oversize(self):
        for name in ['../escape', '/absolute', 'C:/escape', 'root/../../escape', 'root\\..\\escape', 'root/NUL.txt']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w') as archive:
                    archive.writestr(name, 'bad')
                buf.seek(0)
                with self.assertRaises(bootstrap.InstallError):
                    bootstrap.safe_extract(buf, Path(tmp) / 'out')
                self.assertFalse((Path(tmp) / 'escape').exists())
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as archive:
                entry = zipfile.ZipInfo('root/link')
                entry.create_system = 3
                entry.external_attr = 0o120777 << 16
                archive.writestr(entry, '../outside')
            buf.seek(0)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.safe_extract(buf, Path(tmp) / 'out')
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as archive:
                archive.writestr('large', '12345')
            buf.seek(0)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.safe_extract(buf, Path(tmp) / 'out', max_total=4)

    def test_archive_accepts_single_root_and_never_overwrites_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as archive:
                archive.writestr('release/installer/bootstrap.py', '# fixture')
                archive.writestr('release/README.md', 'readme')
            buf.seek(0)
            target = Path(tmp) / 'out'
            bootstrap.safe_extract(buf, target)
            self.assertEqual((target / 'release/README.md').read_text(), 'readme')
            buf.seek(0)
            with self.assertRaises(bootstrap.InstallError):
                bootstrap.safe_extract(buf, target)

    def test_credential_roundtrip_and_launcher_environment_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'private'
            credential_store.save_credentials(directory, 'test-id', 'fixture-secret', allow_plaintext=True,
                                              backend='file')
            self.assertEqual(credential_store.load_credentials(directory), ('test-id', 'fixture-secret'))
            if os.name != 'nt':
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual((directory / 'credentials.json').stat().st_mode & 0o777, 0o600)
            command, env = launcher.prepare_launch(directory, python='private/python', environ={'PATH': 'test'})
            self.assertEqual(command, ['private/python', '-B', '-m', 'hackerone_mcp'])
            self.assertEqual(env['H1_API_TOKEN'], 'fixture-secret')
            self.assertNotIn('fixture-secret', json.dumps(command))
            self.assertEqual(env['H1_ENABLE_WRITES'], 'false')

    def test_plaintext_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(credential_store.CredentialError):
                credential_store.save_credentials(Path(tmp) / 'private', 'id', 'secret', backend='file')

    def test_launcher_requires_explicit_flag_to_enable_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, env = launcher.prepare_launch(Path(tmp), environ={'H1_ENABLE_WRITES': 'true',
                                                                'H1_API_TOKEN': 'inherited-secret'})
            self.assertEqual(env['H1_ENABLE_WRITES'], 'false')
            self.assertNotIn('H1_API_TOKEN', env)
            _, enabled = launcher.prepare_launch(Path(tmp), environ={}, enable_writes=True)
            self.assertEqual(enabled['H1_ENABLE_WRITES'], 'true')

    @unittest.skipUnless(os.name == 'nt', 'Windows DPAPI')
    def test_dpapi_roundtrip_has_no_plaintext_token_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'private'
            credential_store.save_credentials(directory, 'fixture-id', 'fixture-token-only', backend='dpapi')
            self.assertEqual(credential_store.load_credentials(directory), ('fixture-id', 'fixture-token-only'))
            self.assertNotIn('fixture-token-only', (directory / 'credentials.json').read_text())

    @unittest.skipUnless(os.name == 'nt', 'Windows junction boundary')
    def test_private_paths_reject_windows_junction_before_read_or_acl_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / 'outside'
            outside.mkdir()
            junction = Path(tmp) / 'junction'
            created = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(outside)],
                                     capture_output=True, text=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            try:
                with self.assertRaises(credential_store.CredentialError):
                    credential_store.save_credentials(junction / 'private', 'fixture', 'fixture',
                                                      backend='file', allow_plaintext=True)
                with self.assertRaises(credential_store.CredentialError):
                    bootstrap.configure_claude(junction / '.claude.json', {'command': 'python'})
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                junction.rmdir()

    def test_noninteractive_plan_does_not_create_home_or_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'absent-home'
            result = subprocess.run([sys.executable, '-B', str(Path(bootstrap.__file__)),
                                     '--non-interactive', '--home', str(home), '--agents', 'both', '--mcp'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads(result.stdout)
            self.assertEqual(plan['agents'], ['codex', 'claude'])
            self.assertIn('create_virtual_environment', plan['operations'])
            self.assertIn('configure_mcp', plan['operations'])
            self.assertFalse(home.exists())
            self.assertNotIn('H1_API_TOKEN', result.stdout)

    def test_archive_download_requires_https_and_enforces_response_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'source.zip'
            for url in ['http://example.test/source.zip', 'file:///source.zip', 'https://user:pass@example.test/source.zip']:
                with self.subTest(url=url), self.assertRaises(archive_bootstrap.BootstrapError):
                    archive_bootstrap.download(url, destination)
            class Response(io.BytesIO):
                headers = {'Content-Length': '5'}
                def geturl(self):
                    return 'https://example.test/source.zip'
            with patch.object(archive_bootstrap, 'open_https', return_value=Response(b'12345')):
                with self.assertRaises(archive_bootstrap.BootstrapError):
                    archive_bootstrap.download('https://example.test/source.zip', destination, max_bytes=4)
            self.assertFalse(destination.exists())

    def test_archive_hash_mismatch_never_executes_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Response(io.BytesIO):
                headers = {}
                def geturl(self):
                    return 'https://example.test/source.zip'
            with patch.object(archive_bootstrap, 'open_https', return_value=Response(b'fixture')):
                with self.assertRaises(archive_bootstrap.BootstrapError):
                    archive_bootstrap.download('https://example.test/source.zip', Path(tmp) / 'source.zip', expected='0' * 64)

    def test_https_redirect_rejects_downgrade_before_request(self):
        handler = archive_bootstrap.HTTPSRedirects()
        with self.assertRaises(archive_bootstrap.BootstrapError):
            handler.redirect_request(archive_bootstrap.urllib.request.Request('https://example.test/'),
                                     None, 302, 'redirect', {}, 'http://example.test/unsafe')

    def test_remote_verified_archive_runs_only_plan_in_temporary_home(self):
        root = Path(__file__).resolve().parents[2]
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as target:
            for path in (root / 'installer').glob('*.py'):
                target.write(path, 'release/installer/' + path.name)
            target.writestr('release/bug-bounty/SKILL.md', '# fixture')
            target.writestr('release/hackerone-mcp/pyproject.toml', '# fixture')
        payload = archive.getvalue()
        digest = hashlib.sha256(payload).hexdigest()
        class Response(io.BytesIO):
            headers = {}
            def geturl(self):
                return 'https://cdn.example.test/source.zip'
        results = []
        def execute(command):
            results.append(subprocess.run(command, capture_output=True, text=True, timeout=10))
            return results[-1].returncode
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(archive_bootstrap, 'open_https', return_value=Response(payload)), \
             patch.object(archive_bootstrap.subprocess, 'call', side_effect=execute):
            home = Path(tmp) / 'home'
            code = archive_bootstrap.main(['--source-url', 'https://example.test/source.zip',
                                           '--sha256', digest, '--non-interactive', '--home', str(home),
                                           '--agents', 'both', '--mcp'])
            self.assertEqual(code, 0, results[0].stderr)
            self.assertEqual(json.loads(results[0].stdout)['agents'], ['codex', 'claude'])
            self.assertFalse(home.exists())

    def test_mocked_interactive_install_writes_real_configs_in_temporary_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broad_parent = home / '.local/share'
            broad_parent.mkdir(parents=True)
            if os.name != 'nt':
                home.chmod(0o755)
                broad_parent.chmod(0o755)
            before = {path: permissions(path) for path in (home, broad_parent)}
            class Answers:
                def ask(self, message, default=''):
                    return 'both' if message.startswith('Agents:') else default
                def yes(self, message, **kwargs):
                    return not message.startswith('Install optional Chromium')
                def directory(self, message, default):
                    return default
            source = Path(__file__).resolve().parents[2]
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[1:3] == ['-m', 'venv']:
                    python = Path(argv[3]) / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                    python.parent.mkdir(parents=True)
                    python.touch()
            with patch.object(bootstrap, 'Console', return_value=Answers()), \
                 patch.object(bootstrap, 'checked_run', side_effect=command), \
                 patch.object(bootstrap, '_offer_agents'):
                bootstrap.interactive(source, home)
            codex = tomllib.loads((home / '.codex/config.toml').read_text())['mcp_servers']['hackerone']
            claude = json.loads((home / '.claude.json').read_text())['mcpServers']['hackerone']
            self.assertEqual(codex['env']['H1_ENABLE_WRITES'], 'false')
            self.assertEqual(claude['type'], 'stdio')
            self.assertTrue((home / '.claude/skills/bug-bounty/SKILL.md').exists())
            self.assertTrue((home / '.codex/skills/bug-bounty/SKILL.md').exists())
            self.assertIn('launcher.py', codex['args'][-1])
            self.assertFalse(any('playwright' in ' '.join(call) for call in calls))
            self.assertNotIn('H1_API_TOKEN', json.dumps(codex) + json.dumps(claude))
            self.assertEqual({path: permissions(path) for path in before}, before)

    def test_reinstall_preserves_credential_settings_and_send_claim_without_moving_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            source = Path(__file__).resolve().parents[2]
            runtime = bootstrap.default_runtime(home)
            runtime.mkdir(parents=True)
            backend = 'dpapi' if os.name == 'nt' else 'file'
            credential_store.save_credentials(runtime / 'private', 'fixture-identifier', 'reinstall-fixture-token',
                                              backend=backend, allow_plaintext=True)
            credentials = runtime / 'private/credentials.json'
            original_blob = credentials.read_bytes()
            original_inode = credentials.stat().st_ino
            settings = runtime / 'settings.json'
            settings.write_text('{"operator_setting":"retain"}')
            old_source = runtime / 'installer'
            old_source.mkdir()
            (old_source / 'stale.txt').write_text('obsolete source')
            data = home / '.local/share/bug-bounty-data'
            data.mkdir()
            journal = data / 'journal.sqlite3'
            with contextlib.closing(sqlite3.connect(journal)) as database, database:
                database.execute('CREATE TABLE claims (id TEXT PRIMARY KEY, state TEXT)')
                database.execute("INSERT INTO claims VALUES ('reviewed-id', 'sending')")
            journal_inode = journal.stat().st_ino
            class Answers:
                def ask(self, message, default=''):
                    return 'codex' if message.startswith('Agents:') else default
                def yes(self, message, **kwargs):
                    return not (message.startswith('Install optional Chromium') or message.startswith('Connect a HackerOne'))
                def directory(self, message, default):
                    return default
            def command(argv, **kwargs):
                if argv[1:3] == ['-m', 'venv']:
                    python = Path(argv[3]) / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                    python.parent.mkdir(parents=True, exist_ok=True)
                    python.touch()
                elif '--connect-account' in argv:
                    bootstrap._credentials(runtime, Answers())
            output = io.StringIO()
            with patch.object(bootstrap, 'Console', return_value=Answers()), \
                 patch.object(bootstrap, 'checked_run', side_effect=command), \
                 patch.object(bootstrap, '_offer_agents'), \
                 patch.object(bootstrap, 'load_credentials', side_effect=AssertionError('reinstall must not decrypt state')), \
                 contextlib.redirect_stderr(output):
                bootstrap.interactive(source, home)
            self.assertTrue(credentials.exists(), 'stored credentials disappeared on reinstall')
            self.assertEqual(credentials.read_bytes(), original_blob)
            self.assertEqual(credentials.stat().st_ino, original_inode)
            self.assertEqual(settings.read_text(), '{"operator_setting":"retain"}')
            self.assertEqual(journal.stat().st_ino, journal_inode)
            with contextlib.closing(sqlite3.connect(journal)) as database:
                self.assertEqual(database.execute('SELECT state FROM claims WHERE id=?', ('reviewed-id',)).fetchone(), ('sending',))
            self.assertFalse((runtime / 'installer/stale.txt').exists())
            self.assertTrue((runtime / 'installer/launcher.py').exists())
            self.assertEqual(credential_store.load_credentials(runtime / 'private'), ('fixture-identifier', 'reinstall-fixture-token'))
            _, launch_environment = launcher.prepare_launch(runtime / 'private', environ={})
            self.assertEqual(launch_environment['H1_USERNAME'], 'fixture-identifier')
            self.assertEqual(launch_environment['H1_API_TOKEN'], 'reinstall-fixture-token')
            self.assertNotIn('reinstall-fixture-token', output.getvalue())

    def test_dashboard_without_mcp_installs_runtime_without_h1_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            source = Path(__file__).resolve().parents[2]
            calls = []
            class Answers:
                def ask(self, message, default=''):
                    return 'skip' if message.startswith('Agents:') else default
                def yes(self, message, **kwargs):
                    return not message.startswith('Install the optional HackerOne')
                def directory(self, message, default):
                    return default
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[1:3] == ['-m', 'venv']:
                    python = Path(argv[3]) / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                    python.parent.mkdir(parents=True, exist_ok=True)
                    python.touch()
            with patch.object(bootstrap, 'Console', return_value=Answers()), \
                 patch.object(bootstrap, 'checked_run', side_effect=command), patch.object(bootstrap, '_offer_agents'):
                bootstrap.interactive(source, home)
            runtime = bootstrap.default_runtime(home)
            launcher_name = 'Open Bug Bounty Dashboard.ps1' if os.name == 'nt' else 'Open Bug Bounty Dashboard.sh'
            self.assertTrue((runtime / launcher_name).is_file())
            self.assertTrue(any('webui.py' in ' '.join(argv) and '--help' in argv for argv in calls))
            self.assertFalse(any('pip' in argv or '--connect-account' in argv for argv in calls))
            self.assertFalse((home / '.codex/config.toml').exists())

    def test_dashboard_launchers_pass_literal_paths_without_starting_a_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime-é ' & %BBT_UNSET% ! path"
            scripts = runtime / 'bug-bounty/scripts'
            scripts.mkdir(parents=True)
            (scripts / 'webui.py').write_text('import json, os, sys\nfrom pathlib import Path\nPath(os.environ["BBT_TEST_ARGS"]).write_text(json.dumps(sys.argv[1:]))\n')
            root = Path(tmp) / "engagements-é-研究 ' & %BBT_UNSET% ! literal"
            class Answers:
                def yes(self, *args, **kwargs):
                    return True
            paths = bootstrap.dashboard_launchers(runtime, Path(sys.executable), root, Answers())
            for launcher_path in paths:
                args_file = Path(tmp) / (launcher_path.suffix[1:] + '-args.json')
                env = dict(os.environ, BBT_TEST_ARGS=str(args_file))
                if launcher_path.suffix == '.ps1':
                    command = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(launcher_path)]
                elif launcher_path.suffix == '.cmd':
                    command = ['cmd', '/d', '/c', launcher_path.name]
                else:
                    command = ['sh', str(launcher_path)]
                result = subprocess.run(command, cwd=launcher_path.parent, env=env,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(args_file.read_text()), ['--root', str(root), '--port', '8765', '--open'])


if __name__ == '__main__':
    unittest.main()
