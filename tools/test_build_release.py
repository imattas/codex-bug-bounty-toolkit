import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


class ReleaseTests(unittest.TestCase):
    def module(self):
        path=Path(__file__).with_name("build_release.py")
        spec=importlib.util.spec_from_file_location("release_builder",path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_release_is_source_only_and_bootstraps_bind_archive_hash(self):
        builder=self.module()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"source"; output=Path(temp)/"dist"; root.mkdir()
            for rel in ("README.md","bug-bounty/SKILL.md","hackerone-mcp/pyproject.toml","installer/bootstrap.py"):
                p=root/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text("fixture\n")
            (root/"install.ps1").write_text("url=__TOOLKIT_SOURCE_URL__\nhash=__TOOLKIT_SOURCE_SHA256__\n")
            (root/"install.sh").write_text("url=__TOOLKIT_SOURCE_URL__\nhash=__TOOLKIT_SOURCE_SHA256__\n")
            for rel in ("hackerone-mcp/.venv/secret.txt","bug-bounty/__pycache__/bad.pyc","hackerone-mcp/.env","installer/.env","installer/credentials.json"):
                p=root/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text("PRIVATE_SENTINEL")
            info=builder.build_release(root,output,repository="https://github.com/example/toolkit",tag="v1.0.0")
            with zipfile.ZipFile(info["archive"]) as archive:
                names=archive.namelist()
                self.assertIn("bug-bounty/SKILL.md",names)
                self.assertFalse(any(".venv" in n or "__pycache__" in n or n.endswith(".env") or "credentials.json" in n for n in names))
            for name in ("install.ps1","install.sh"):
                content=(output/name).read_text()
                self.assertIn("/releases/download/v1.0.0/",content)
                self.assertIn(info["sha256"],content)
                self.assertNotIn("__TOOLKIT_SOURCE_",content)

    def test_invalid_repository_or_tag_does_not_create_output(self):
        builder=self.module()
        with tempfile.TemporaryDirectory() as temp:
            for repo,tag in (("http://evil.invalid/repo","v1"),("https://github.com/a/b","../escape")):
                output=Path(temp)/"dist"
                with self.assertRaises(ValueError): builder.build_release(Path(temp),output,repository=repo,tag=tag)
                self.assertFalse(output.exists())
