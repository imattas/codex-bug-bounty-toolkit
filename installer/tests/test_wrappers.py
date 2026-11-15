"""Execute native entry points in plan mode; no packages or credentials are installed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import shlex
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WrapperTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'native Windows PowerShell')
    def test_powershell_skips_free_threaded_candidate_for_standard_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source = work / 'source/installer'
            source.mkdir(parents=True)
            (source / 'bootstrap.py').write_text('import json,sysconfig\nprint(json.dumps({"free_threaded": bool(sysconfig.get_config_var("Py_GIL_DISABLED"))}))\n')
            fake = work / 'free-threaded.py'
            fake.write_text('import json,sys,sysconfig\nargs=sys.argv[1:]\n'
                            'if args and args[0]=="-3": args.pop(0)\n'
                            'if "-c" in args:\n'
                            ' original=sysconfig.get_config_var\n'
                            ' sysconfig.get_config_var=lambda name: 1 if name=="Py_GIL_DISABLED" else original(name)\n'
                            ' exec(args[args.index("-c")+1])\n'
                            'else: print(json.dumps({"free_threaded": True}))\n')
            fake_launcher = work / 'free-threaded.ps1'
            fake_launcher.write_text('param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Invocation)\n'
                                     '& $env:BBT_REAL_PYTHON $env:BBT_FAKE_INTERPRETER @Invocation\n')
            script = '''function Get-Command {
param($Name, $CommandType, $ErrorAction)
if ($Name -eq 'py') { [pscustomobject]@{Source=$env:BBT_FAKE_LAUNCHER} }
elseif ($Name -eq 'python') { [pscustomobject]@{Source=$env:BBT_REAL_PYTHON} }
}
& $env:BBT_WRAPPER -NonInteractive -SourceDir $env:BBT_TEST_SOURCE
'''
            env = dict(os.environ, BBT_REAL_PYTHON=sys.executable, BBT_FAKE_INTERPRETER=str(fake),
                       BBT_FAKE_LAUNCHER=str(fake_launcher), BBT_TEST_SOURCE=str(source.parent),
                       BBT_WRAPPER=str(ROOT / 'install.ps1'))
            result = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['free_threaded'])

    @unittest.skipUnless(os.name != 'nt' and shutil.which('sh'), 'POSIX /bin/sh')
    def test_posix_skips_free_threaded_candidate_for_standard_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source = work / 'source/installer'
            source.mkdir(parents=True)
            (source / 'bootstrap.py').write_text('import json,sysconfig\nprint(json.dumps({"free_threaded": bool(sysconfig.get_config_var("Py_GIL_DISABLED"))}))\n')
            fake = work / 'free-threaded.py'
            fake.write_text('import json,sys,sysconfig\nargs=sys.argv[1:]\n'
                            'if "-c" in args:\n'
                            ' original=sysconfig.get_config_var\n'
                            ' sysconfig.get_config_var=lambda name: 1 if name=="Py_GIL_DISABLED" else original(name)\n'
                            ' exec(args[args.index("-c")+1])\n'
                            'else: print(json.dumps({"free_threaded": True}))\n')
            bins = work / 'bin'
            bins.mkdir()
            candidates = {'python3': [sys.executable, str(fake)], 'python': [sys.executable]}
            for name, command in candidates.items():
                path = bins / name
                path.write_text('#!/bin/sh\nexec ' + ' '.join(shlex.quote(part) for part in command) + ' "$@"\n')
                path.chmod(0o700)
            env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ.get('PATH', ''),
                       BBT_SOURCE_DIR=str(source.parent))
            result = subprocess.run(['sh', str(ROOT / 'install.sh'), '--non-interactive'],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['free_threaded'])

    @unittest.skipUnless(os.name == 'nt', 'native Windows PowerShell')
    def test_powershell_local_plan_with_space_in_home_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home with spaces'
            result = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                     '-File', str(ROOT / 'install.ps1'), '-NonInteractive',
                                     '-Agents', 'both', '-Mcp', '-HomeDir', str(home)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['agents'], ['codex', 'claude'])
            self.assertFalse(home.exists())

    @unittest.skipUnless(os.name == 'nt', 'native Windows PowerShell')
    def test_powershell_iex_mode_finds_checkout_without_script_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, BBT_NON_INTERACTIVE='1', BBT_SOURCE_DIR=str(ROOT))
            script = "Get-Content -LiteralPath $env:BBT_WRAPPER -Raw | Invoke-Expression"
            env['BBT_WRAPPER'] = str(ROOT / 'install.ps1')
            result = subprocess.run(['powershell', '-NoProfile', '-Command', script],
                                    env=env, cwd=tmp, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['mode'], 'plan-only')

    @unittest.skipUnless(os.name != 'nt' and shutil.which('sh'), 'POSIX /bin/sh')
    def test_posix_shell_local_and_pipe_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home with spaces'
            env = dict(os.environ, BBT_SOURCE_DIR=str(ROOT), BBT_NON_INTERACTIVE='1')
            for command, stdin in [(['sh', str(ROOT / 'install.sh'), '--home', str(home), '--agents', 'both', '--mcp'], None),
                                   (['sh'], (ROOT / 'install.sh').read_text())]:
                with self.subTest(command=command):
                    result = subprocess.run(command, input=stdin, cwd=tmp, env=env,
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout)['mode'], 'plan-only')
                    self.assertFalse(home.exists())


if __name__ == '__main__':
    unittest.main()
