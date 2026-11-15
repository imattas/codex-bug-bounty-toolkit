"""Runtime bootstrap checks with package/network commands replaced at the boundary."""
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtimes


class RuntimeTests(unittest.TestCase):
    def test_node_tar_copies_regular_executables_but_never_follows_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'node.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                info = tarfile.TarInfo('node-v1/bin/node')
                info.size = 7
                info.mode = 0o755
                stream.addfile(info, io.BytesIO(b'fixture'))
                link = tarfile.TarInfo('node-v1/bin/npm')
                link.type = tarfile.SYMTYPE
                link.linkname = '../lib/npm.js'
                stream.addfile(link)
            target = Path(tmp) / 'out'
            runtimes.extract_node_tar(archive, target)
            self.assertEqual((target / 'node-v1/bin/node').read_text(), 'fixture')
            self.assertFalse((target / 'node-v1/bin/npm').exists())
            bad = Path(tmp) / 'bad.tar.gz'
            with tarfile.open(bad, 'w:gz') as stream:
                info = tarfile.TarInfo('../escape')
                info.size = 1
                stream.addfile(info, io.BytesIO(b'x'))
            with self.assertRaises(runtimes.RuntimeInstallError):
                runtimes.extract_node_tar(bad, Path(tmp) / 'bad-out')
            self.assertFalse((Path(tmp) / 'escape').exists())

    def test_missing_agent_can_install_node_and_npm_into_user_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            commands = []
            node = home / 'portable-node' / ('node.exe' if os.name == 'nt' else 'bin/node')
            npm = home / 'portable-node/npm-cli.js'
            class Console:
                def yes(self, message, **kwargs):
                    return not message.startswith('Add ')
            def run(command, **kwargs):
                commands.append(command)
                if 'install' in command:
                    prefix = Path(command[command.index('--prefix') + 1])
                    package = prefix / ('node_modules' if os.name == 'nt' else 'lib/node_modules') / '@openai/codex'
                    package.mkdir(parents=True)
                    (package / 'package.json').write_text(json.dumps({'bin': {'codex': 'bin/codex.js'}}))
                    (package / 'bin').mkdir()
                    (package / 'bin/codex.js').write_text('fixture')
            with patch.object(runtimes.shutil, 'which', return_value=None), \
                 patch.object(runtimes, 'install_node', return_value=(node, npm)), patch.dict(os.environ):
                runtimes.offer_agents(['codex'], Console(), home, run)
            self.assertEqual(len(commands), 2)
            self.assertIn('--prefix', commands[0])
            self.assertEqual(commands[0][-1], '@openai/codex')
            self.assertEqual(commands[1][-1], '--version')
            self.assertNotIn('-g @openai', ' '.join(commands[0]))


if __name__ == '__main__':
    unittest.main()
