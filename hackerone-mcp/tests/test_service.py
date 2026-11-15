import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from hackerone_mcp.client import HackerOneClient, HackerOneError
from hackerone_mcp.service import ResearchService
from hackerone_mcp.store import Store


def make_bundle(root):
    bundle = root / 'finding'
    (bundle / 'evidence').mkdir(parents=True)
    (bundle / 'poc').mkdir()
    (bundle / 'poc/repro.txt').write_text('reproduce locally', encoding='utf-8')
    (bundle / 'evidence/proof.txt').write_text('verified behavior', encoding='utf-8')
    metadata = {'schema_version': 1, 'program': 'acme', 'root_cause_key': 'object-owner-check', 'artifacts_reviewed': True,
        'gates': {name: {'status': status, 'rationale': 'reviewed', 'checked_at': '2026-11-15T00:00:00+00:00', 'source': 'https://hackerone.com/acme', 'sources': ['own reports and local bundles']} for name, status in {'scope': 'in_scope', 'validation': 'confirmed', 'actionability': 'actionable', 'duplicate': 'no_known_duplicate'}.items()},
        'report': {'title': 'Owner check missing', 'asset': 'https://acme.test', 'weakness': 'Improper Access Control', 'impact': 'Other account data is exposed', 'severity': {'score': 5.3, 'vector': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'}, 'summary': 'Verified missing owner check', 'setup': 'Create isolated accounts A and B', 'steps': ['Create private object as B', 'Retrieve B object as A'], 'expected': 'Deny the request', 'actual': 'B data is returned'},
        'calculation': {'vector': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', 'scores': [5.3], 'score_labels': ['CVSS-B']},
        'artifact_sha256': {name: hashlib.sha256((bundle / name).read_bytes()).hexdigest() for name in ('poc/repro.txt', 'evidence/proof.txt')}}
    (bundle / 'evidence/assessment.json').write_text(json.dumps(metadata), encoding='utf-8')
    (bundle / 'report.md').write_text('# Owner check missing\n\nAsset: https://acme.test\n\nWeakness: Improper Access Control\n\nSeverity: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N / 5.3 (CVSS-B)\n\n## Description\n\n### Summary:\n\nVerified missing owner check\n\n### Steps To Reproduce:\n\n1. Create isolated accounts A and B\n2. Create private object as B\n3. Retrieve B object as A\n\n### Expected vs. Actual Behavior:\n\nExpected: Deny the request\n\nActual: B data is returned\n\n### Supporting Material / References:\n\n- [poc/repro.txt](poc/repro.txt)\n- [evidence/proof.txt](evidence/proof.txt)\n\n## Impact\n\nOther account data is exposed\n', encoding='utf-8')
    return bundle


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = make_bundle(self.root)
        self.posts = []
        self.scope_asset = 'https://acme.test'
        self.eligible = True
        self.program_open = True
        self.timeout = False
        self.policy = 'Only allowed assets'
        self.asset_type = 'URL'
        self.extra_scopes = []
        self.weakness_external_id = 'cwe-639'

    def tearDown(self): self.temp.cleanup()

    def respond(self, request):
        path = request.url.path
        if request.method == 'POST':
            self.posts.append(json.loads(request.content))
            if self.timeout: raise httpx.ReadTimeout('private-token')
            return httpx.Response(201, json={'data': {'id': '91', 'type': 'report'}})
        if path.endswith('/structured_scopes'):
            data = [{'id': '42', 'type': 'structured-scope', 'attributes': {'asset_identifier': self.scope_asset, 'asset_type': self.asset_type, 'eligible_for_submission': self.eligible}}, *self.extra_scopes]
        elif path.endswith('/weaknesses'):
            data = [{'id': '17', 'type': 'weakness', 'attributes': {'name': 'Improper Access Control', 'external_id': self.weakness_external_id}}]
        elif path.endswith('/scope_exclusions'): data = []
        else:
            data = {'id': '7', 'type': 'program', 'attributes': {'handle': 'acme', 'submission_state': 'open' if self.program_open else 'closed', 'policy': self.policy}}
        return httpx.Response(200, json={'data': data})

    def service(self, writes=True):
        return ResearchService(HackerOneClient('alice', 'private-token', transport=httpx.MockTransport(self.respond)), Store(self.root / 'data', 'alice'), enable_writes=writes)

    async def prepare(self, service):
        return await service.prepare_bundle(str(self.bundle), 'acme', 42, 17, 'medium')

    async def test_prepare_exact_payload_and_one_send_across_restart(self):
        service = self.service()
        first = await self.prepare(service)
        second = await self.prepare(service)
        self.assertEqual(first['prepared_hash'], second['prepared_hash'])
        self.assertEqual(first['payload']['data']['attributes']['structured_scope_id'], 42)
        receipt = await service.commit(first['prepared_hash'], confirm=True)
        self.assertEqual(receipt['state'], 'succeeded')
        self.assertEqual(receipt['receipt']['data']['id'], '91')
        with self.assertRaises(HackerOneError):
            await self.service().commit(first['prepared_hash'], confirm=True)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0], first['payload'])

    async def test_disabled_writes_and_confirmation_refuse_before_post(self):
        service = self.service(False)
        prepared = await self.prepare(service)
        for current, confirm in ((service, True), (self.service(), False)):
            with self.assertRaises(HackerOneError): await current.commit(prepared['prepared_hash'], confirm=confirm)
        self.assertEqual(self.posts, [])

    async def test_modified_report_assessment_or_artifact_refuses(self):
        for rel in ('report.md', 'evidence/assessment.json', 'poc/repro.txt'):
            with self.subTest(rel=rel):
                service = self.service()
                prepared = await self.prepare(service)
                path = self.bundle / rel
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                with self.assertRaises(HackerOneError): await service.commit(prepared['prepared_hash'], confirm=True)
                path.write_bytes(original)
        self.assertEqual(self.posts, [])

    async def test_scope_asset_change_eligibility_and_program_closure_refuse(self):
        service = self.service()
        prepared = await self.prepare(service)
        for field, changed, original in (('scope_asset', 'https://other.test', 'https://acme.test'), ('eligible', False, True), ('program_open', False, True)):
            setattr(self, field, changed)
            with self.assertRaises(HackerOneError): await service.commit(prepared['prepared_hash'], confirm=True)
            setattr(self, field, original)
        self.assertEqual(self.posts, [])

    async def test_uncertain_write_cannot_be_sent_again_after_restart(self):
        service = self.service()
        prepared = await self.prepare(service)
        self.timeout = True
        result = await service.commit(prepared['prepared_hash'], confirm=True)
        self.assertEqual(result['state'], 'uncertain')
        self.assertNotIn('private-token', json.dumps(result))
        with self.assertRaises(HackerOneError): await self.service().commit(prepared['prepared_hash'], confirm=True)
        self.assertEqual(len(self.posts), 1)

    async def test_artifact_traversal_and_missing_proof_are_refused(self):
        path = self.bundle / 'evidence/assessment.json'
        metadata = json.loads(path.read_text())
        metadata['artifact_sha256']['../outside.txt'] = '0' * 64
        path.write_text(json.dumps(metadata))
        with self.assertRaises(HackerOneError): await self.prepare(self.service())

    async def test_report_policy_and_scopes_are_returned_with_explicit_cache_limits(self):
        service = self.service()
        result = await service.briefing('acme', 'missing')
        self.assertEqual(result['program']['data']['attributes']['policy'], 'Only allowed assets')
        self.assertTrue(result['scopes']['complete'])
        self.assertEqual(result['cached_related_reports']['matches'], [])
        self.assertIn('undisclosed', result['limits'])

    async def test_bundle_gate_and_exact_asset_mapping_are_required(self):
        self.scope_asset = '*.acme.test'
        with self.assertRaises(HackerOneError): await self.prepare(self.service())
        self.scope_asset = 'https://acme.test'
        path = self.bundle / 'evidence/assessment.json'
        metadata = json.loads(path.read_text())
        metadata['gates']['duplicate']['status'] = 'unknown'
        path.write_text(json.dumps(metadata))
        with self.assertRaises(HackerOneError): await self.prepare(self.service())

    async def test_changed_terms_can_be_prepared_for_review_but_payload_is_never_resent(self):
        service = self.service()
        original = await self.prepare(service)
        self.policy = 'Updated policy requiring extra review'
        with self.assertRaises(HackerOneError): await service.commit(original['prepared_hash'], confirm=True)
        updated = await self.prepare(service)
        self.assertNotEqual(original['prepared_hash'], updated['prepared_hash'])
        self.assertEqual(updated['mapping']['program']['attributes']['policy'], self.policy)
        await service.commit(updated['prepared_hash'], confirm=True)
        self.policy = 'Third policy'
        third = await self.prepare(service)
        with self.assertRaises(HackerOneError): await service.commit(third['prepared_hash'], confirm=True)
        self.assertEqual(len(self.posts), 1)

    async def test_severity_must_match_bundle_score(self):
        with self.assertRaises(HackerOneError):
            await self.service().prepare_bundle(str(self.bundle), 'acme', 42, 17, 'critical')

    def change_report_field(self, field, value):
        path = self.bundle / 'evidence/assessment.json'
        metadata = json.loads(path.read_text())
        old = metadata['report'][field]
        metadata['report'][field] = value
        path.write_text(json.dumps(metadata))
        report = self.bundle / 'report.md'
        report.write_text(report.read_text().replace(old, value))

    async def test_url_endpoint_maps_to_selected_origin_and_boundary_prefix(self):
        self.change_report_field('asset', 'https://acme.test/api/accounts/1?view=details')
        await self.prepare(self.service())
        self.scope_asset = 'https://acme.test/api'
        await self.prepare(self.service())
        for identifier in ('https://acme.test/ap', 'http://acme.test/api', 'https://acme.test:8443/api', 'https://evilacme.test/api'):
            self.scope_asset = identifier
            with self.assertRaises(HackerOneError): await self.prepare(self.service())

    async def test_domain_and_wildcard_use_label_boundaries_and_excluded_rows_win(self):
        self.change_report_field('asset', 'https://api.acme.test/v1')
        self.asset_type, self.scope_asset = 'WILDCARD', '*.acme.test'
        await self.prepare(self.service())
        self.extra_scopes = [{'id': '43', 'type': 'structured-scope', 'attributes': {'asset_identifier': 'https://api.acme.test/v1', 'asset_type': 'URL', 'eligible_for_submission': False}}]
        with self.assertRaises(HackerOneError): await self.prepare(self.service())
        self.extra_scopes = []
        self.asset_type, self.scope_asset = 'DOMAIN', 'api.acme.test'
        await self.prepare(self.service())
        self.scope_asset = 'acme.test'
        with self.assertRaises(HackerOneError): await self.prepare(self.service())

    async def test_weakness_primary_cwe_maps_case_insensitively_and_rejects_ambiguity(self):
        self.change_report_field('weakness', 'CWE-639: Authorization bypass through user-controlled key')
        await self.prepare(self.service())
        self.weakness_external_id = 'cwe-79'
        with self.assertRaises(HackerOneError): await self.prepare(self.service())
        self.weakness_external_id = 'cwe-639'
        self.change_report_field('weakness', 'CWE-639 and CWE-79')
        with self.assertRaises(HackerOneError): await self.prepare(self.service())

    async def test_deleted_report_sections_and_wrong_calculation_are_refused(self):
        report = self.bundle / 'report.md'
        original = report.read_text()
        report.write_text(original.replace('### Steps To Reproduce:', 'Steps:'))
        with self.assertRaises(HackerOneError): await self.prepare(self.service())
        report.write_text(original)
        assessment = self.bundle / 'evidence/assessment.json'
        metadata = json.loads(assessment.read_text())
        metadata['report']['severity']['score'] = 9.9
        assessment.write_text(json.dumps(metadata))
        with self.assertRaises(HackerOneError): await self.prepare(self.service())


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_sdk_lists_tools_and_local_status_without_credentials(self):
        from hackerone_mcp.server import create_server
        server = create_server(environ={})
        tools = await server.list_tools()
        names = {tool.name for tool in tools}
        self.assertIn('hackerone_prepare_submission', names)
        self.assertIn('hackerone_commit_submission', names)
        self.assertNotIn('hackerone_api_request', names)
        content = await server.call_tool('hackerone_status', {})
        self.assertIn('credentials_configured', str(content))

    async def test_bundle_tools_require_configured_project_root_and_reject_escape(self):
        from hackerone_mcp.server import create_server
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = make_bundle(root)
            server = create_server(environ={})
            with self.assertRaisesRegex(Exception, 'BUG_BOUNTY_PROJECT_ROOT'):
                await server.call_tool('hackerone_validate_bundle', {'bundle_path': str(bundle)})
            server = create_server(environ={'BUG_BOUNTY_PROJECT_ROOT': str(root / 'allowed')})
            with self.assertRaisesRegex(Exception, 'outside'):
                await server.call_tool('hackerone_validate_bundle', {'bundle_path': str(bundle)})
            server = create_server(environ={'BUG_BOUNTY_PROJECT_ROOT': str(root)})
            result = await server.call_tool('hackerone_validate_bundle', {'bundle_path': str(bundle)})
            self.assertIn('valid', str(result))
