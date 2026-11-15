"""Optional extended/version-4 calculator tests. Require cvss==3.6."""
import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
try:
    from cvss import CVSS4
    HAS_REFERENCE = True
except ImportError:
    HAS_REFERENCE = False


@unittest.skipUnless(HAS_REFERENCE, "optional cvss==3.6 dependency not installed")
class ExtendedScoringTests(unittest.TestCase):
    def test_v4_documented_reference_example(self):
        from cvss_score import assess
        r = assess("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N")
        self.assertEqual(r["scores"], [9.9])
        self.assertEqual(r["assessment"], "CVSS-B")

    def test_v4_threat_environment_nomenclature(self):
        from cvss_score import assess
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"
        self.assertEqual(assess(v+"/E:P")["assessment"], "CVSS-BT")
        self.assertEqual(assess(v+"/CR:H")["assessment"], "CVSS-BE")
        self.assertEqual(assess(v+"/E:P/CR:H")["assessment"], "CVSS-BTE")
        self.assertEqual(assess(v+"/E:X/CR:X")["assessment"], "CVSS-B")

    def test_v3_extended_metrics_preserved(self):
        from cvss_score import assess
        r = assess("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C")
        self.assertEqual(r["scores"][0], 9.8)
        self.assertLess(r["scores"][1], r["scores"][0])
        self.assertEqual(r["score_labels"], ["Base", "Temporal", "Environmental"])

    def test_reject_unsupported_and_invalid_vector(self):
        from cvss_score import assess
        for v in ["CVSS:3.0/AV:N", "CVSS:4.0/AV:N", "CVSS:4.0/AV:Z"]:
            with self.subTest(v=v), self.assertRaises(ValueError): assess(v)
