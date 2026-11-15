from pathlib import Path
import os
import sys
import tempfile
import threading
import socket
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import browser_sessions
from engagement_runtime import init_budget, ScopeError, budget_status


class FakePage:
    def goto(self, url, **kwargs):
        self.url = url
        return type('Response', (), {'status': 200})()

    def screenshot(self, *, path, **kwargs):
        Path(path).write_bytes(b'fake-png')


class FakeContext:
    def __init__(self):
        self.page = FakePage()
        self.closed = False

    def new_page(self):
        return self.page

    def route(self, pattern, callback):
        self.handler = callback

    def on(self, *args):
        pass

    def route_web_socket(self, *args):
        pass

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self):
        self.contexts = []

    def new_context(self, **kwargs):
        context = FakeContext()
        self.contexts.append(context)
        return context

    def close(self):
        pass


class BrowserTests(unittest.TestCase):
    def test_caller_managed_browser_is_rejected_without_confined_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            init_budget(temp)
            with self.assertRaises(browser_sessions.BrowserUnavailable):
                browser_sessions.BrowserSessionManager(temp, allowlist=['http://127.0.0.1:8000'], browser=FakeBrowser()).start()

    def test_contexts_isolated_navigation_scoped_and_capture_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            init_budget(temp)
            fake = FakeBrowser()
            with patch.object(browser_sessions.BrowserSessionManager, '_launch_browser', lambda manager: setattr(manager, 'browser', fake)), browser_sessions.BrowserSessionManager(temp, allowlist=['http://127.0.0.1:8000']) as manager:
                manager.new_session('alice')
                manager.new_session('bob')
                self.assertIsNot(fake.contexts[0], fake.contexts[1])
                self.assertEqual(manager.navigate('alice', 'http://127.0.0.1:8000/')['status'], 200)
                with self.assertRaises(ScopeError):
                    manager.navigate('alice', 'http://evil.test/')
                self.assertTrue(Path(manager.screenshot('alice')['screenshot_path']).exists())
            self.assertTrue(all(c.closed for c in fake.contexts))

    def test_route_blocks_outside_scope_and_writes(self):
        class Request:
            url = 'http://evil.test/'
            method = 'GET'
            headers = {}
        class Route:
            request = Request()
            def abort(self, *args):
                self.blocked = True
            def continue_(self, **kwargs):
                self.continued = True
        with tempfile.TemporaryDirectory() as temp:
            init_budget(temp)
            fake = FakeBrowser()
            with patch.object(browser_sessions.BrowserSessionManager, '_launch_browser', lambda manager: setattr(manager, 'browser', fake)), browser_sessions.BrowserSessionManager(temp, allowlist=['http://127.0.0.1:8000']) as manager:
                manager.new_session('alice')
                route = Route()
                fake.contexts[0].handler(route)
                self.assertTrue(route.blocked)
                route.request.url = 'http://127.0.0.1:8000/'
                route.request.method = 'POST'
                fake.contexts[0].handler(route)
                self.assertFalse(hasattr(route, 'continued'))


@unittest.skipUnless(os.environ.get('BUG_BOUNTY_REAL_BROWSER') == '1', 'Set BUG_BOUNTY_REAL_BROWSER=1 with local Playwright/browser installed')
class RealBrowserTests(unittest.TestCase):
    def test_webrtc_udp_and_turn_tcp_cannot_bypass_exhausted_budget(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<html><body>owned-webrtc-lab</body></html>')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        http_thread = threading.Thread(target=server.serve_forever, daemon=True)
        http_thread.start()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        udp.settimeout(.1)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(('127.0.0.1', 0))
        tcp.listen()
        tcp.settimeout(.1)
        stopped = threading.Event()
        udp_packets, tcp_connections = [], []
        def receive_udp():
            while not stopped.is_set():
                try:
                    udp_packets.append(udp.recvfrom(65535)[0])
                except socket.timeout:
                    continue
        def receive_tcp():
            while not stopped.is_set():
                try:
                    connection, address = tcp.accept()
                    tcp_connections.append(address)
                    connection.close()
                except socket.timeout:
                    continue
        udp_thread = threading.Thread(target=receive_udp, daemon=True)
        tcp_thread = threading.Thread(target=receive_tcp, daemon=True)
        udp_thread.start()
        tcp_thread.start()
        try:
            # Positive fixture controls establish live receivers before launch.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
                control.sendto(b'fixture-control', udp.getsockname())
            with socket.create_connection(tcp.getsockname()):
                pass
            until = time.monotonic() + 2
            while (not udp_packets or not tcp_connections) and time.monotonic() < until:
                time.sleep(.01)
            self.assertEqual(udp_packets, [b'fixture-control'])
            self.assertEqual(len(tcp_connections), 1)
            udp_packets.clear()
            tcp_connections.clear()
            with tempfile.TemporaryDirectory() as temp:
                allowed = f'http://127.0.0.1:{server.server_port}'
                init_budget(temp, max_requests=1, rate_per_second=10000)
                with browser_sessions.BrowserSessionManager(temp, allowlist=[allowed]) as manager:
                    manager.new_session('alice')
                    manager.navigate('alice', allowed)
                    page = manager.sessions['alice']['page']
                    self.assertEqual(budget_status(temp)['used'], 1)
                    self.assertIn('[native code]', page.evaluate('RTCPeerConnection.toString()'))
                    # Use both native top-level and native srcdoc frame APIs.
                    page.evaluate('''async ({udpPort, tcpPort}) => {
                        const frame = document.createElement('iframe');
                        document.body.appendChild(frame);
                        window.peers = [];
                        for (const target of [window, frame.contentWindow]) {
                            const pc = new target.RTCPeerConnection({iceServers: [
                                {urls: 'stun:127.0.0.1:' + udpPort},
                                {urls: 'turn:127.0.0.1:' + udpPort + '?transport=udp', username:'owned', credential:'fixture'},
                                {urls: 'turn:127.0.0.1:' + tcpPort + '?transport=tcp', username:'owned', credential:'fixture'},
                                {urls: 'turns:127.0.0.1:' + tcpPort + '?transport=tcp', username:'owned', credential:'fixture'}
                            ]});
                            window.peers.push(pc);
                            pc.createDataChannel('owned-fixture');
                            await pc.setLocalDescription(await pc.createOffer());
                        }
                    }''', {'udpPort': udp.getsockname()[1], 'tcpPort': tcp.getsockname()[1]})
                    page.wait_for_timeout(1800)
                    self.assertEqual(udp_packets, [], 'WebRTC emitted unbudgeted UDP datagrams')
                    self.assertEqual(tcp_connections, [], 'WebRTC reached unlisted TURN TCP/TLS listener')
                    self.assertEqual(budget_status(temp)['used'], 1)
                    page.evaluate('window.peers.forEach(pc => pc.close())')
        finally:
            stopped.set()
            udp_thread.join(timeout=2)
            tcp_thread.join(timeout=2)
            udp.close()
            tcp.close()
            server.shutdown()
            server.server_close()
            http_thread.join()

    def test_actual_chromium_cookie_storage_isolation_scope_and_capture(self):
        class Handler(BaseHTTPRequestHandler):
            calls = []
            def do_GET(self):
                Handler.calls.append((self.path, dict(self.headers)))
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'x' * 2000 if self.path == '/large' else b'<html><body>owned-browser-proof</body></html>')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        allowed = f'http://127.0.0.1:{server.server_port}'
        os.environ['BROWSER_ALICE_AUTH'] = 'Bearer browser-alice-secret'
        try:
            with tempfile.TemporaryDirectory() as temp:
                init_budget(temp, max_requests=30, rate_per_second=10000, concurrency=4)
                with browser_sessions.BrowserSessionManager(temp, allowlist=[allowed], max_response_bytes=1024) as manager:
                    manager.new_session('alice', credential_env={'Authorization': 'BROWSER_ALICE_AUTH'})
                    manager.new_session('bob')
                    manager.navigate('alice', allowed + '/alice')
                    alice = manager.sessions['alice']['page']
                    alice.evaluate("document.cookie='identity=alice'; localStorage.setItem('identity','alice')")
                    manager.navigate('bob', allowed + '/bob')
                    bob = manager.sessions['bob']['page']
                    self.assertEqual(bob.evaluate('document.cookie'), '')
                    self.assertIsNone(bob.evaluate("localStorage.getItem('identity')"))
                    self.assertEqual(alice.evaluate("localStorage.getItem('identity')"), 'alice')
                    self.assertEqual([h for p, h in Handler.calls if p == '/alice'][0]['Authorization'], 'Bearer browser-alice-secret')
                    self.assertNotIn('Authorization', [h for p, h in Handler.calls if p == '/bob'][0])
                    # A forbidden subresource is intercepted before any server hit.
                    alice.evaluate("fetch('/forbidden', {method:'POST'}).catch(()=>{})")
                    alice.wait_for_timeout(100)
                    self.assertFalse(any(p == '/forbidden' for p, _ in Handler.calls))
                    with self.assertRaises(ScopeError):
                        manager.navigate('alice', 'http://localhost:1/outside')
                    capture = manager.screenshot('alice')
                    self.assertTrue(Path(capture['screenshot_path']).read_bytes().startswith(b'\x89PNG'))
                    alice.evaluate("fetch('/large').catch(()=>{})")
                    alice.wait_for_timeout(100)
                    self.assertTrue(any(o.get('blocked') == 'ResponseByteLimit' for o in manager.sessions['alice']['observations']))
                    for path in Path(temp).rglob('*.json'):
                        self.assertNotIn('browser-alice-secret', path.read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
