import concurrent.futures
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import socket
from unittest.mock import patch
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import engagement_runtime as runtime


class Handler(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.__class__.calls.append((self.path, dict(self.headers)))
        if self.path == '/two-cookies':
            self.send_response(200)
            self.send_header('Set-Cookie', 'identity=SESSION-SECRET-ONE; Path=/; HttpOnly')
            self.send_header('Set-Cookie', 'second=SESSION-SECRET-TWO; Path=/')
            self.end_headers()
            self.wfile.write(b'SESSION-SECRET-ONE and SESSION-SECRET-TWO')
            return
        if self.path == '/slow-headers':
            try:
                for byte in b'HTTP/1.1 200 OK\r\nX-Slow: abcdefghijklmnop\r\n\r\n':
                    self.connection.sendall(bytes([byte]))
                    time.sleep(.04)
            except OSError:
                pass
            return
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/ok')
            self.end_headers()
            return
        if self.path == '/cross':
            self.send_response(302)
            self.send_header('Location', self.__class__.cross_url)
            self.end_headers()
            return
        self.send_response(429 if self.path == '/throttle' else 200)
        self.send_header('Set-Cookie', 'session=random-server-secret' if self.path == '/seed-cookie' else 'identity=' + self.headers.get('Authorization', 'anonymous'))
        self.end_headers()
        if self.path == '/raw-cookie':
            self.wfile.write(self.headers.get('Cookie', '').encode())
            return
        self.wfile.write(json.dumps({'path': self.path, 'auth': self.headers.get('Authorization'), 'cookie': self.headers.get('Cookie'), 'proof': 'owned-marker', 'padding': 'x' * 500}).encode())

    def log_message(self, *args):
        pass


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        runtime.init_budget(self.project, max_requests=20, rate_per_second=10000, concurrency=2, duration_seconds=30)
        Handler.calls.clear()

    def tearDown(self):
        self.tmp.cleanup()

    def test_capture_redacts_credentials_and_records_proof(self):
        os.environ['RUNTIME_TEST_AUTH'] = 'Bearer private-secret'
        result = runtime.replay(self.project, 'alice', self.origin + '/ok', allowlist=[self.origin], credential_env={'Authorization': 'RUNTIME_TEST_AUTH'})
        self.assertEqual(result['status'], 200)
        self.assertIn('owned-marker', result['body'])
        self.assertEqual(result['body_source'], 'http-response')
        self.assertFalse(result['truncated'])
        self.assertNotIn('private-secret', ''.join(p.read_text() for p in Path(result['evidence_dir']).iterdir()))
        self.assertEqual(Handler.calls[0][1]['Authorization'], 'Bearer private-secret')

    def test_scope_rejects_userinfo_suffix_encoded_traversal_and_path_bypass(self):
        scope = runtime.Scope(['https://example.test/api'])
        for url in ['https://example.test.evil/api', 'https://x@example.test/api', 'https://example.test/apix', 'https://example.test/api/%2e%2e/admin', 'https://example.test/api/../admin', 'https://example.test:444/api']:
            with self.subTest(url=url), self.assertRaises(runtime.ScopeError):
                scope.check(url)
        self.assertEqual(scope.check('https://EXAMPLE.test:443/api/a'), 'https://example.test/api/a')

    def test_write_requires_opt_in_and_does_not_consume_budget(self):
        with self.assertRaises(runtime.RuntimePolicyError):
            runtime.replay(self.project, 'alice', self.origin, allowlist=[self.origin], method='POST')
        self.assertEqual(runtime.budget_status(self.project)['used'], 0)

    def test_redirect_default_and_byte_cap(self):
        result = runtime.replay(self.project, 'alice', self.origin + '/redirect', allowlist=[self.origin])
        self.assertEqual(result['status'], 302)
        self.assertEqual(len(Handler.calls), 1)
        result = runtime.replay(self.project, 'alice', self.origin + '/ok', allowlist=[self.origin], max_response_bytes=32)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['captured_bytes'], 32)

    def test_explicit_redirect_rechecks_scope(self):
        with self.assertRaises(runtime.ScopeError):
            runtime.replay(self.project, 'alice', self.origin + '/redirect', allowlist=[self.origin + '/redirect'], follow_redirects=True)
        self.assertEqual(len(Handler.calls), 1)

    def test_throttle_persistently_stops_other_clients(self):
        result = runtime.replay(self.project, 'alice', self.origin + '/throttle', allowlist=[self.origin])
        self.assertEqual(result['status'], 429)
        with self.assertRaises(runtime.BudgetExceeded):
            runtime.replay(self.project, 'bob', self.origin + '/ok', allowlist=[self.origin])

    def test_budget_atomic_total_and_concurrency_across_instances(self):
        other = self.project / 'atomic'
        runtime.init_budget(other, max_requests=3, rate_per_second=10000, concurrency=3, duration_seconds=30)
        def attempt(i):
            try:
                return runtime.reserve(other, timeout=1)
            except runtime.BudgetExceeded:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            leases = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(x is not None for x in leases), 3)
        self.assertEqual(runtime.budget_status(other)['used'], 3)
        for lease in leases:
            if lease:
                runtime.release(other, lease)

    def test_budget_cannot_reset_and_rate_deadline_and_concurrency_hold(self):
        other = self.project / 'limited'
        runtime.init_budget(other, max_requests=2, rate_per_second=1, concurrency=1, duration_seconds=.2)
        lease = runtime.reserve(other, timeout=1)
        with self.assertRaises(runtime.BudgetExceeded):
            runtime.reserve(other, timeout=1)
        runtime.release(other, lease)
        with self.assertRaises(runtime.BudgetExceeded):
            runtime.reserve(other, timeout=1)
        with self.assertRaises(runtime.RuntimePolicyError):
            runtime.init_budget(other, max_requests=100)
        time.sleep(.22)
        with self.assertRaises(runtime.BudgetExceeded):
            runtime.reserve(other, timeout=1)

    def test_cookie_jars_are_per_identity(self):
        client = runtime.ReplayClient(self.project, allowlist=[self.origin])
        client.replay('alice', self.origin + '/first')
        client.replay('bob', self.origin + '/second')
        client.replay('alice', self.origin + '/third')
        self.assertNotIn('Cookie', Handler.calls[1][1])
        self.assertIn('Cookie', Handler.calls[2][1])

    def test_independent_processes_share_total(self):
        other = self.project / 'processes'
        runtime.init_budget(other, max_requests=2, rate_per_second=10000, concurrency=2)
        script = "import sys;sys.path.insert(0,sys.argv[1]);from engagement_runtime import reserve;reserve(sys.argv[2],timeout=1)"
        args = [sys.executable, '-c', script, str(Path(runtime.__file__).parent), str(other)]
        first = subprocess.run(args, capture_output=True, text=True)
        second = subprocess.run(args, capture_output=True, text=True)
        third = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(third.returncode, 0)
        self.assertEqual(runtime.budget_status(other)['used'], 2)

    def test_redirect_never_forwards_auth_or_cookies_to_other_origin(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        destination = f'http://127.0.0.1:{server.server_port}'
        Handler.cross_url = destination + '/destination'
        os.environ['RUNTIME_TEST_AUTH'] = 'Bearer secret-cross'
        try:
            client = runtime.ReplayClient(self.project, allowlist=[self.origin, destination])
            client.replay('alice', self.origin + '/first', credential_env={'Authorization': 'RUNTIME_TEST_AUTH'})
            result = client.replay('alice', self.origin + '/cross', credential_env={'Authorization': 'RUNTIME_TEST_AUTH'}, follow_redirects=True)
            self.assertEqual(result['status'], 200)
            self.assertNotIn('Authorization', Handler.calls[-1][1])
            self.assertNotIn('Cookie', Handler.calls[-1][1])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_retry_consumes_budget_and_transport_error_does_not_echo_credentials(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        unused = f'http://127.0.0.1:{server.server_port}'
        server.server_close()
        os.environ['RUNTIME_TEST_AUTH'] = 'Bearer never-log-me'
        result = runtime.replay(self.project, 'alice', unused, allowlist=[unused], credential_env={'Authorization': 'RUNTIME_TEST_AUTH'}, timeout=.2, retries=1)
        self.assertEqual(runtime.budget_status(self.project)['used'], 2)
        self.assertEqual(result['body_source'], 'transport-error')
        self.assertEqual(len(result['attempt_paths']), 2)
        self.assertNotIn('never-log-me', json.dumps(result))

    def test_redaction_handles_json_escaping_and_prior_session_credentials(self):
        secret = 'secret"quoted'
        self.assertNotIn('secret', runtime.redact(json.dumps({'echo': secret}), [secret]))
        os.environ['RUNTIME_TEST_AUTH'] = 'Bearer remembered-private'
        client = runtime.ReplayClient(self.project, allowlist=[self.origin])
        client.replay('alice', self.origin + '/first', credential_env={'Authorization': 'RUNTIME_TEST_AUTH'})
        result = client.replay('alice', self.origin + '/second')
        self.assertNotIn('remembered-private', json.dumps(result))

    def test_total_timeout_includes_slow_response_headers(self):
        started = time.monotonic()
        result = runtime.replay(self.project, 'alice', self.origin + '/slow-headers', allowlist=[self.origin], timeout=.15)
        self.assertLess(time.monotonic() - started, .65)
        self.assertIsNotNone(result['error'])

    def test_dns_resolution_is_bounded_without_late_request(self):
        original = socket.getaddrinfo
        def slow_resolver(*args, **kwargs):
            time.sleep(.5)
            return original(*args, **kwargs)
        url = self.origin.replace('127.0.0.1', 'localhost') + '/late-dns'
        started = time.monotonic()
        with patch('socket.getaddrinfo', slow_resolver):
            result = runtime.replay(self.project, 'alice', url, allowlist=[url], timeout=.08)
        self.assertLess(time.monotonic() - started, .35)
        self.assertIsNotNone(result['error'])
        time.sleep(.52)
        self.assertFalse(any(p == '/late-dns' for p, _ in Handler.calls))

    def test_server_cookie_is_redacted_even_when_echoed_as_plain_text(self):
        client = runtime.ReplayClient(self.project, allowlist=[self.origin])
        client.replay('alice', self.origin + '/seed-cookie')
        result = client.replay('alice', self.origin + '/raw-cookie')
        self.assertNotIn('random-server-secret', json.dumps(result))

    def test_all_repeated_set_cookie_values_redacted_in_same_response(self):
        result = runtime.replay(self.project, 'alice', self.origin + '/two-cookies', allowlist=[self.origin])
        captured = json.dumps(result) + ''.join(p.read_text() for p in Path(result['evidence_dir']).glob('*.json'))
        self.assertNotIn('SESSION-SECRET-ONE', captured)
        self.assertNotIn('SESSION-SECRET-TWO', captured)

    def test_reserved_environment_headers_rejected_before_budget_or_network(self):
        os.environ['RUNTIME_RESERVED_HEADER'] = 'outside-vhost.test'
        for header in ('Host', 'hOsT', 'Content-Length', 'Transfer-Encoding', 'Connection', 'Proxy-Authorization'):
            with self.subTest(header=header), self.assertRaises(runtime.RuntimePolicyError):
                runtime.replay(self.project, 'alice', self.origin, allowlist=[self.origin], credential_env={header: 'RUNTIME_RESERVED_HEADER'})
        self.assertFalse(Handler.calls)
        self.assertEqual(runtime.budget_status(self.project)['used'], 0)

    def test_linked_budget_and_evidence_children_cannot_escape_project(self):
        def link_directory(link, target):
            if os.name == 'nt':
                env = dict(os.environ, BB_TEST_LINK=str(link), BB_TEST_TARGET=str(target))
                result = subprocess.run(['powershell', '-NoProfile', '-Command', 'New-Item -ItemType Junction -Path $env:BB_TEST_LINK -Target $env:BB_TEST_TARGET | Out-Null'], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                link.symlink_to(target, target_is_directory=True)
        for child in ('.engagement', 'evidence'):
            with self.subTest(child=child):
                project = self.project / ('linked-' + child.strip('.'))
                outside = self.project / ('outside-' + child.strip('.'))
                project.mkdir()
                outside.mkdir()
                link = project / child
                link_directory(link, outside)
                try:
                    with self.assertRaises(runtime.RuntimePolicyError):
                        if child == '.engagement':
                            runtime.init_budget(project)
                        else:
                            runtime.evidence_directory(project, 'alice')
                    self.assertFalse(list(outside.iterdir()))
                finally:
                    os.rmdir(link) if os.name == 'nt' else link.unlink()

    def test_database_file_hardlink_cannot_modify_an_outside_file(self):
        project = self.project / 'file-link'
        (project / '.engagement').mkdir(parents=True)
        outside = self.project / 'outside-database'
        outside.write_bytes(b'')
        os.link(outside, project / '.engagement' / 'budget.sqlite3')
        with self.assertRaises(runtime.RuntimePolicyError):
            runtime.init_budget(project)
        self.assertEqual(outside.read_bytes(), b'')

    def test_missing_python311_is_junction_method_preserves_path_checks(self):
        # Simulate the advertised Python 3.11 API on the available interpreter.
        with patch.object(Path, 'is_junction', None, create=True):
            self.assertEqual(runtime.confined_path(self.project, 'evidence'), (self.project / 'evidence').resolve())
            self.assertEqual(runtime.budget_status(self.project)['used'], 0)
            with self.assertRaises(runtime.RuntimePolicyError):
                runtime.confined_path(self.project, '..', 'outside')

    def test_authorization_cookie_and_custom_environment_headers_remain_supported(self):
        os.environ['RUNTIME_AUTH_CONTROL'] = 'Bearer credential-control'
        os.environ['RUNTIME_COOKIE_CONTROL'] = 'owned=session-control'
        os.environ['RUNTIME_CUSTOM_CONTROL'] = 'custom-control'
        result = runtime.replay(self.project, 'alice', self.origin, allowlist=[self.origin], credential_env={
            'Authorization': 'RUNTIME_AUTH_CONTROL', 'Cookie': 'RUNTIME_COOKIE_CONTROL', 'X-Owned-Credential': 'RUNTIME_CUSTOM_CONTROL'})
        sent = Handler.calls[-1][1]
        self.assertEqual(sent['Authorization'], 'Bearer credential-control')
        self.assertEqual(sent['Cookie'], 'owned=session-control')
        self.assertEqual(sent['X-Owned-Credential'], 'custom-control')
        self.assertNotIn('session-control', result['body'])


if __name__ == '__main__':
    unittest.main()
