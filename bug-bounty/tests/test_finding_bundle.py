"""Offline report-gate and bundle tests; no exploits or network requests."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
try:
    import cvss
    HAS_CVSS = True
except ImportError:
    HAS_CVSS = False


def candidate():
    return {
        "schema_version": 1, "slug": "cross-workspace-export", "program": "training", "artifacts_reviewed": True,
        "root_cause_key": "export-download-missing-object-access",
        "gates": {
            "scope": {"status": "in_scope", "source": "policy.txt section Eligible assets", "checked_at": "2026-11-15T18:00:00Z", "rationale": "Exact API host and read technique covered; exclusions checked."},
            "validation": {"status": "confirmed", "rationale": "B's unique export marker returned to isolated A; positive controls passed."},
            "actionability": {"status": "actionable", "rationale": "Unauthorized private export disclosure, not a header-only best practice."},
            "duplicate": {"status": "no_known_duplicate", "checked_at": "2026-11-15T18:00:00Z", "sources": ["local findings", "supplied known-issues list"], "rationale": "No same-root-cause issue identified in accessible records; private submissions unavailable."}
        },
        "report": {
            "title": "Members can read another workspace's export", "asset": "https://api.example.test/exports/{id}",
            "weakness": "CWE-639: Authorization Bypass Through User-Controlled Key",
            "severity": {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "score": 5.3},
            "summary": "The export download operation returns B's file to A without a sharing relationship.",
            "setup": "Use two owned isolated workspaces A/B and a completed export owned by B.",
            "steps": ["As B, retrieve the export and confirm its unique marker.", "As A, request B's export ID and observe B's marker; A's own-object control succeeds."],
            "expected": "A is denied access to B's private export.", "actual": "A receives B's export content.",
            "impact": "A member with another workspace's export ID can read that export.",
            "references": ["policy.txt"]
        },
        "poc_files": ["candidate/reproduce.http"], "evidence_files": ["candidate/control.txt"]
    }


class GateTests(unittest.TestCase):
    def setUp(self):
        import finding_bundle
        self.module = finding_bundle

    def test_excluded_informational_duplicate_and_unresolved_make_no_report(self):
        cases = [("scope", "out_of_scope"), ("scope", "unresolved"), ("actionability", "informational"), ("duplicate", "duplicate"), ("duplicate", "not_checked"), ("validation", "inconclusive")]
        for gate,status in cases:
            with self.subTest(gate=gate,status=status), tempfile.TemporaryDirectory() as temp:
                d=candidate(); d["gates"][gate]["status"]=status
                with self.assertRaises(ValueError): self.module.create_bundle(d,Path(temp))
                self.assertFalse((Path(temp)/"findings").exists())

    def test_assertion_without_scope_and_duplicate_sources_is_insufficient(self):
        d=candidate(); d["gates"]["scope"]["source"]=""; d["gates"]["duplicate"]["sources"]=[]
        self.assertTrue(self.module.gate_reasons(d))


@unittest.skipUnless(HAS_CVSS, "optional cvss dependency required for CVSS 4.0 report validation")
class BundleTests(unittest.TestCase):
    setUp = GateTests.setUp
    def prepare(self, root, data):
        (root/"candidate").mkdir()
        (root/"candidate/reproduce.http").write_text("GET /exports/b1 HTTP/1.1\nHost: api.example.test\n",encoding="utf-8")
        (root/"candidate/control.txt").write_text("Fictional control evidence",encoding="utf-8")
        from cvss_score import assess
        data["report"]["severity"]["score"]=assess(data["report"]["severity"]["vector"])["scores"][0]

    def test_accepted_bundle_has_exact_frame_and_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); d=candidate(); self.prepare(root,d)
            result=self.module.create_bundle(d,root)
            report=(result/"report.md").read_text(encoding="utf-8")
            self.assertTrue((result/"poc/reproduce.http").is_file())
            self.assertTrue((result/"evidence/control.txt").is_file())
            headers=["Asset:","Weakness:","Severity:","## Description","### Summary:","### Steps To Reproduce:","### Expected vs. Actual Behavior:","### Supporting Material / References:","## Impact"]
            self.assertEqual([report.index(h) for h in headers], sorted(report.index(h) for h in headers))
            self.assertIn("poc/reproduce.http",report); self.assertIn("evidence/control.txt",report)
            self.assertNotIn("REPORT FRAME",report)
            self.assertEqual(json.loads((result/"evidence/assessment.json").read_text())["gates"]["scope"]["status"],"in_scope")

    def test_same_root_cause_blocks_second_report_and_existing_report_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); d=candidate(); self.prepare(root,d)
            first=self.module.create_bundle(d,root); original=(first/"report.md").read_bytes()
            d["slug"]="different-title-same-cause"
            with self.assertRaises(ValueError): self.module.create_bundle(d,root)
            self.assertFalse((root/"findings/different-title-same-cause").exists())
            self.assertEqual((first/"report.md").read_bytes(),original)

    def test_bad_score_missing_artifact_and_unsafe_path_block_before_creation(self):
        for failure in ("score","missing","traversal","slug"):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temp:
                root=Path(temp); d=candidate(); self.prepare(root,d)
                if failure=="score": d["report"]["severity"]["score"]=9.8
                if failure=="missing": d["evidence_files"]=["candidate/missing.log"]
                if failure=="traversal": d["poc_files"]=["../outside.py"]
                if failure=="slug": d["slug"]="../escape"
                with self.assertRaises(ValueError): self.module.create_bundle(d,root)
                self.assertFalse((root/"findings").exists())

    def test_empty_or_whitespace_artifacts_do_not_become_proof(self):
        for relative in ("candidate/reproduce.http", "candidate/control.txt"):
            for content in (b"",b" \n\t\r"):
                with self.subTest(relative=relative,content=content),tempfile.TemporaryDirectory() as temp:
                    root=Path(temp); d=candidate(); self.prepare(root,d)
                    (root/relative).write_bytes(content)
                    with self.assertRaises(ValueError): self.module.create_bundle(d,root)
                    self.assertFalse((root/"findings").exists())

    def test_unindexed_existing_reports_require_actual_legacy_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); d=candidate(); self.prepare(root,d)
            legacy=root/"findings/legacy/report.md"; legacy.parent.mkdir(parents=True)
            legacy.write_text("Existing report",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"Unreviewed legacy"):
                self.module.create_bundle(d,root)
            self.assertEqual(legacy.read_text(),"Existing report")
            self.assertFalse((root/"findings"/d["slug"]).exists())
            d["gates"]["duplicate"]["reviewed_legacy_reports"]=["findings/legacy/report.md"]
            result=self.module.create_bundle(d,root)
            self.assertTrue((result/"report.md").exists())
            self.assertEqual(legacy.read_text(),"Existing report")

    def test_postpublication_lock_cleanup_failure_does_not_claim_creation_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); d=candidate(); self.prepare(root,d)
            original_unlink=Path.unlink
            def fail_lock(path,*args,**kwargs):
                if path.name==".bundle-create.lock": raise PermissionError("simulated lock cleanup denial")
                return original_unlink(path,*args,**kwargs)
            error=io.StringIO()
            with mock.patch.object(Path,"unlink",new=fail_lock),contextlib.redirect_stderr(error):
                result=self.module.create_bundle(d,root)
            self.assertTrue((result/"report.md").is_file())
            self.assertTrue((root/"findings/.bundle-create.lock").exists())
            self.assertIn("lock",error.getvalue())
