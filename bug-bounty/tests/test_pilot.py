"""End-to-end loopback pilot; never contacts a public target."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))


class PilotTests(unittest.TestCase):
    def test_controlled_engagement_produces_one_real_lab_bundle_and_rejects_noise(self):
        from pilot_engagement import run_pilot
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"engagement"
            summary=run_pilot(root)
            self.assertEqual(summary["accepted_findings"],1)
            self.assertEqual(set(summary["rejected_candidates"]),{"informational","duplicate","out_of_scope","unpersisted_write"})
            bundle=root/"findings/cross-workspace-export"
            self.assertTrue((bundle/"report.md").is_file())
            self.assertTrue(any((bundle/"poc").iterdir()))
            self.assertTrue(any((bundle/"evidence").iterdir()))
            self.assertEqual(len(list((root/"findings").glob("*/report.md"))),1)
            self.assertIn("LOCAL LAB",(bundle/"report.md").read_text(encoding="utf-8"))
            self.assertTrue(summary["controlled_checks"]["cross_workspace_marker_observed"])
            self.assertTrue(summary["controlled_checks"]["protected_route_denied"])
            self.assertTrue(summary["controlled_checks"]["write_echo_not_persisted"])
            for f in root.rglob("*"):
                if f.is_file() and f.suffix in (".json",".txt",".http",".md"):
                    content=f.read_text(encoding="utf-8")
                    self.assertNotIn("pilot-owned-token-a-742",content)
                    self.assertNotIn("pilot-owned-token-b-742",content)

    def test_existing_output_not_overwritten(self):
        from pilot_engagement import run_pilot
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError): run_pilot(Path(temp))
