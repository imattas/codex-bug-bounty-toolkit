"""Loopback UI contract and filesystem/security boundaries; no external requests."""
import hashlib
from contextlib import redirect_stdout
import io
import http.client
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import webui


class WebUITest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        finding = self.root / 'acme/findings/read-export'
        (finding / 'evidence').mkdir(parents=True)
        (finding / 'poc').mkdir()
        (finding / 'report.md').write_text('# Export <img src=x onerror=alert(1)>\n\nPrivate export disclosure.\n\n## Description\n\n### Steps To Reproduce:\n\n1. Read another workspace export.\n\n```html\n<script>alert(1)</script>\n```', encoding='utf-8')
        artifact = b'<script>alert(1)</script>'
        (finding / 'poc/proof.html').write_bytes(artifact)
        self.assessment = finding / 'evidence/assessment.json'
        self.meta = {'schema_version': 1, 'slug': 'read-export', 'program': 'Acme', 'artifacts_reviewed': True,
                     'report': {'title': 'Export <img src=x onerror=alert(1)>', 'severity': {'score': 6.5}},
                     'gates': {k: {'status': v, 'rationale': 'Recorded evidence', 'source': 'policy',
                                   'checked_at': '2026-11-15T00:00:00Z', 'sources': ['local']}
                               for k, v in {'scope': 'in_scope', 'validation': 'confirmed', 'actionability': 'actionable', 'duplicate': 'no_known_duplicate'}.items()},
                     'artifact_sha256': {'poc/proof.html': hashlib.sha256(artifact).hexdigest()},
                     'secret_token': 'NEVER-EXPOSE-ASSESSMENT'}
        self.assessment.write_text(json.dumps(self.meta), encoding='utf-8')
        notes = self.root / 'acme/.bug-bounty/candidates'
        notes.mkdir(parents=True)
        (notes / 'rejected.json').write_text(json.dumps({'informational': 'No security consequence', 'duplicate': 'Known root cause'}))
        self.server = webui.create_server(self.root, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.origin = f'http://127.0.0.1:{self.port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, method='GET', data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request(method, path, body=json.dumps(data) if data is not None else None, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def listing(self):
        status, _, body = self.request('/api/findings')
        self.assertEqual(status, 200)
        return json.loads(body)

    def test_discovery_and_detail_use_recorded_data(self):
        listing = self.listing()
        self.assertEqual(len(listing['findings']), 3)
        finding = next(x for x in listing['findings'] if x['kind'] == 'report')
        self.assertEqual(finding['program'], 'Acme')
        self.assertEqual(finding['decision'], 'actionable')
        self.assertEqual(sum(x['decision'] == 'held' for x in listing['findings']), 2)
        detail = self.request('/api/findings/' + finding['id'])
        self.assertNotIn(b'NEVER-EXPOSE-ASSESSMENT', detail[2])
        self.assertNotIn(b'assessment.json', detail[2])
        self.assertIn(b'Private export disclosure', detail[2])
        self.assertEqual(finding['id'], next(x for x in self.listing()['findings'] if x['kind'] == 'report')['id'])

    def test_manual_state_separate_and_requires_csrf(self):
        listing = self.listing()
        identifier = listing['findings'][0]['id']
        original = self.assessment.read_bytes()
        path = '/api/findings/' + identifier + '/state'
        body = {'status': 'submitted', 'notes': 'Manually sent by reviewer'}
        self.assertEqual(self.request(path, 'POST', body)[0], 403)
        headers = {'Content-Type': 'application/json', 'Origin': self.origin, 'X-CSRF-Token': listing['csrf_token']}
        self.assertEqual(self.request(path, 'POST', body, headers)[0], 200)
        self.assertEqual(self.assessment.read_bytes(), original)
        self.assertEqual(next(x for x in self.listing()['findings'] if x['id'] == identifier)['workflow']['status'], 'submitted')
        self.assertEqual(self.request(path, 'POST', {'status': 'confirmed'}, headers)[0], 400)

    def test_host_origin_and_traversal_rejected(self):
        self.assertEqual(self.request('/api/findings', headers={'Host': 'evil.example'})[0], 403)
        for origin in ('https://evil.example', 'null', 'http://localhost:' + str(self.port)):
            self.assertEqual(self.request('/api/findings', headers={'Origin': origin})[0], 403)
        for path in ('/../../secret', '/api/artifacts/../../secret', '/%2e%2e/secret'):
            self.assertNotEqual(self.request(path)[0], 200)

    def test_artifacts_are_manifest_only_attachment_and_hash_checked(self):
        finding = next(x for x in self.listing()['findings'] if x['kind'] == 'report')
        detail = json.loads(self.request('/api/findings/' + finding['id'])[2])
        artifact = detail['artifacts'][0]
        status, headers, body = self.request(artifact['url'])
        self.assertEqual(status, 200)
        self.assertIn('attachment;', headers['Content-Disposition'])
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(body, b'<script>alert(1)</script>')
        (self.assessment.parent.parent / 'poc/proof.html').write_text('changed')
        self.assertNotEqual(self.request(artifact['url'])[0], 200)

    def test_linked_paths_are_omitted_and_internal_metadata_not_downloadable(self):
        outside = self.root / 'outside.txt'
        outside.write_text('private')
        target = self.assessment.parent.parent / 'poc/linked.txt'
        os.link(outside, target)
        self.meta['artifact_sha256']['poc/linked.txt'] = hashlib.sha256(b'private').hexdigest()
        self.meta['artifact_sha256']['evidence/assessment.json'] = '0' * 64
        self.meta['artifact_sha256']['../../outside.txt'] = hashlib.sha256(b'private').hexdigest()
        self.assessment.write_text(json.dumps(self.meta))
        finding = next(x for x in self.listing()['findings'] if x['kind'] == 'report')
        detail = json.loads(self.request('/api/findings/' + finding['id'])[2])
        self.assertEqual([a['name'] for a in detail['artifacts']], ['proof.html'])

    def test_shell_is_local_and_csp_blocks_html_execution(self):
        status, headers, body = self.request('/')
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers['Content-Security-Policy'])
        self.assertNotIn(b'https://', body)
        self.assertIn(b'/app.js', body)

    def test_legacy_reports_and_unconfirmed_candidates_remain_held(self):
        legacy = self.root / 'acme/findings/legacy'
        legacy.mkdir()
        (legacy / 'report.md').write_text('# Old report\nNo assessment available.')
        candidate = dict(self.meta)
        candidate['slug'] = 'unconfirmed'
        candidate['gates'] = {'validation': {'status': 'unconfirmed'}}
        (self.root / 'acme/.bug-bounty/candidates/unconfirmed.json').write_text(json.dumps(candidate))
        records = self.listing()['findings']
        self.assertEqual(len(records), 5)
        self.assertEqual(sum(x['decision'] == 'held' for x in records), 4)
        self.assertFalse((self.root / 'acme/findings/unconfirmed/report.md').exists())

    def test_outside_directory_link_is_not_discovered_or_served(self):
        with tempfile.TemporaryDirectory() as outside_temp:
            outside = Path(outside_temp)
            (outside / 'report.md').write_text('# PRIVATE OUTSIDE REPORT')
            link = self.root / 'acme/findings/outside'
            if os.name == 'nt':
                result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(outside)], capture_output=True)
                if result.returncode:
                    self.skipTest('Junction creation unavailable')
            else:
                link.symlink_to(outside, target_is_directory=True)
            try:
                records = self.listing()['findings']
                self.assertEqual(len(records), 3)
                self.assertNotIn('PRIVATE OUTSIDE REPORT', json.dumps(records))
            finally:
                # Removing the junction itself never touches its target.
                if os.name == 'nt':
                    link.rmdir()
                else:
                    link.unlink()

    def test_single_engagement_root_and_empty_states(self):
        catalog = webui.Catalog(self.root / 'acme')
        self.assertEqual(len(catalog.items), 3)
        empty = self.root / 'empty'
        empty.mkdir()
        self.assertEqual(webui.Catalog(empty).items, {})

    def test_candidate_json_never_dumps_arbitrary_fields_or_credentials(self):
        notes = self.root / 'acme/.bug-bounty/candidates/private.json'
        notes.write_text(json.dumps({'secret_token': 'PRIVATE-CANDIDATE-TOKEN', 'configuration': 'PRIVATE-CONFIG',
                                     'title': 'Needs triage', 'reason': 'Awaiting reproduction'}))
        listing = self.listing()
        self.assertEqual(len(listing['findings']), 4)
        self.assertNotIn('PRIVATE-CANDIDATE-TOKEN', json.dumps(listing))
        self.assertNotIn('PRIVATE-CONFIG', json.dumps(listing))

    def test_rejection_note_groups_cannot_exceed_discovery_limit(self):
        project = self.root / 'limited'
        notes = project / '.bug-bounty/candidates'
        notes.mkdir(parents=True)
        (notes / 'notes.json').write_text(json.dumps({'informational': 'No impact', 'duplicate': 'Known', 'out_of_scope': 'Excluded'}))
        with patch.object(webui, 'MAX_FINDINGS', 2):
            catalog = webui.Catalog(project)
        self.assertEqual(len(catalog.items), 2)
        self.assertTrue(catalog.truncated)

    def test_cli_occupied_port_uses_new_server_and_actual_browser_url(self):
        with patch.object(sys, 'argv', ['webui.py', '--root', str(self.root), '--port', str(self.port), '--open']), \
                patch.object(webui.LocalServer, 'serve_forever', side_effect=KeyboardInterrupt), \
                patch.object(webui.webbrowser, 'open') as launch, redirect_stdout(io.StringIO()) as output:
            webui.main()
        actual = launch.call_args.args[0]
        self.assertNotEqual(actual, self.origin)
        self.assertTrue(actual.startswith('http://127.0.0.1:'))
        self.assertIn(actual, output.getvalue())
        self.assertIn('in use', output.getvalue())

    def test_supporting_source_files_are_not_counted_as_candidate_notes(self):
        support = self.root / 'acme/.bug-bounty/candidates/reproduction.txt'
        support.write_text('Supporting reproduction instructions')
        self.meta['poc_files'] = ['.bug-bounty/candidates/reproduction.txt']
        self.assessment.write_text(json.dumps(self.meta))
        self.assertEqual(len(self.listing()['findings']), 3)


@unittest.skipUnless(os.getenv('BUG_BOUNTY_REAL_BROWSER') == '1', 'Opt-in real browser UI verification')
class RealBrowserTest(WebUITest):
    def test_browser_safe_rendering_state_and_preview(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, device_scale_factor=1)
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(self.origin)
            page.get_by_role('button', name='Export <img src=x onerror=alert(1)>').click()
            page.get_by_label('Workflow status', exact=True).select_option('reviewed')
            page.get_by_label('Review notes').fill('Ready for owner review')
            page.get_by_role('button', name='Save tracking').click()
            page.get_by_text('Tracking saved.').wait_for()
            self.assertEqual(next(x for x in self.listing()['findings'] if x['kind'] == 'report')['workflow']['status'], 'reviewed')
            self.assertEqual(page.locator('img').count(), 0)
            page.get_by_role('heading', name='Steps To Reproduce:').wait_for()
            self.assertEqual(page.locator('.report-body li').count(), 1)
            self.assertIn('<script>alert(1)</script>', page.locator('.report-body pre').inner_text())
            page.get_by_label('Search findings').fill('NoSuchFinding')
            page.get_by_text('No matching findings').wait_for()
            page.get_by_label('Search findings').fill('')
            page.get_by_role('button', name='Export <img src=x onerror=alert(1)>').wait_for()
            page.evaluate('document.activeElement.blur(); window.scrollTo(0, 0)')
            screenshot = Path(__file__).resolve().parents[2] / 'artifacts/webui-preview.png'
            screenshot.parent.mkdir(exist_ok=True)
            page.screenshot(path=str(screenshot), full_page=True)
            self.assertFalse(errors)
            page.set_viewport_size({'width': 390, 'height': 844})
            self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), 390)
            browser.close()


if __name__ == '__main__':
    unittest.main()
