import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CheckRunnerTests(unittest.TestCase):
    def test_earlier_failure_stops_and_cannot_be_masked_by_later_success(self):
        path=Path(__file__).with_name("check_all.py")
        spec=importlib.util.spec_from_file_location("check_all",path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp:
            sentinel=Path(temp)/"must-not-run"
            commands=[[sys.executable,"-c","raise SystemExit(7)"], [sys.executable,"-c","from pathlib import Path; Path('must-not-run').write_text('ran')"]]
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                module.run_commands(commands,cwd=temp)
            self.assertEqual(caught.exception.returncode,7)
            self.assertFalse(sentinel.exists())
