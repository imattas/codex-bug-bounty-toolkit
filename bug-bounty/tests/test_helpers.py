"""Offline behavioral tests: python -m unittest discover -s tests -v."""
import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class CVSSBaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cvss = load("cvss31")

    def test_network_full_impact(self):
        self.assertEqual(self.cvss.assess("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["score"], 9.8)

    def test_authenticated_limited_read(self):
        r = self.cvss.assess("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual((r["score"], r["rating"]), (4.3, "Medium"))

    def test_scope_changed_privileges_weight(self):
        self.assertEqual(self.cvss.assess("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N")["score"], 6.4)

    def test_no_impact_is_zero_even_scope_changed(self):
        self.assertEqual(self.cvss.assess("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N")["score"], 0)

    def test_scope_changed_caps_at_ten(self):
        self.assertEqual(self.cvss.assess("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")["score"], 10)

    def test_roundup_decimal_boundary(self):
        self.assertEqual(self.cvss.round_up(4.0), 4.0)
        self.assertEqual(self.cvss.round_up(4.00001), 4.1)

    def test_reject_invalid_incomplete_duplicate_and_extended_metrics(self):
        good = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        for vector in [good.replace("3.1", "4.0"), good+"/E:F", good+"/AV:L", good.replace("/A:H", ""), good.replace("AV:N", "AV:Z")]:
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                self.cvss.assess(vector)


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load("openapi_inventory")

    def base(self):
        return {"openapi": "3.1.0", "security": [{"bearer": []}], "paths": {}}

    def test_inherited_auth_and_explicit_anonymous_are_different(self):
        d = self.base(); d["paths"] = {"/a": {"get": {}}, "/b": {"get": {"security": []}}, "/c": {"get": {"security": [{}, {"bearer": []}]}}}
        rows = self.api.inventory(d)["operations"]
        self.assertEqual([r["security_declaration"] for r in rows], ["credentials_declared", "anonymous_allowed", "anonymous_allowed"])
        self.assertEqual(rows[0]["security_source"], "root")
        self.assertEqual(rows[1]["security_source"], "operation")

    def test_parameter_override_and_local_ref(self):
        d = self.base(); d["components"] = {"parameters": {"ID": {"in": "path", "name": "id", "required": True}}}
        d["paths"] = {"/items/{id}": {"parameters": [{"$ref": "#/components/parameters/ID"}, {"in": "query", "name": "q", "required": False}], "get": {"parameters": [{"in": "query", "name": "q", "required": True}]}}}
        params = self.api.inventory(d)["operations"][0]["parameters"]
        self.assertEqual([(p["in"],p["name"],p["required"]) for p in params], [("path","id",True),("query","q",True)])

    def test_unresolved_remote_ref_is_explicit(self):
        d = self.base(); d["paths"] = {"/remote": {"$ref": "https://outside.invalid/path.json"}}
        r = self.api.inventory(d)
        self.assertEqual(r["operations"], [])
        self.assertTrue(any("external" in s for s in r["warnings"]))

    def test_cyclic_reference_does_not_recurse_forever(self):
        d = self.base(); d["paths"] = {"/loop": {"$ref": "#/paths/~1loop"}}
        self.assertTrue(self.api.inventory(d)["warnings"])

    def test_server_override_and_no_spec_authorization_claim(self):
        d = self.base(); d["servers"]=[{"url":"https://root.invalid"}]
        d["paths"] = {"/x": {"servers":[{"url":"https://path.invalid"}],"get":{"servers":[{"url":"https://op.invalid"}]}}}
        r = self.api.inventory(d)
        self.assertEqual(r["operations"][0]["server_candidates"], [{"url":"https://op.invalid"}])
        self.assertFalse(r["authorizes_testing"])

    def test_empty_root_servers_uses_spec_default(self):
        d = self.base(); d["paths"] = {"/x": {"get": {}}}
        absent = self.api.inventory(d)["operations"][0]["server_candidates"]
        d["servers"] = []
        self.assertEqual(self.api.inventory(d)["operations"][0]["server_candidates"], absent)
        self.assertEqual(absent, [{"url": "/"}])

    def test_unsupported_version_and_bad_paths_are_errors(self):
        for doc in [{"swagger":"2.0","paths":{}},{"openapi":"3.2.0","paths":{}},{"openapi":"3.1.0","paths":[]}]:
            with self.subTest(doc=doc), self.assertRaises(ValueError): self.api.inventory(doc)


if __name__ == "__main__":
    unittest.main()
