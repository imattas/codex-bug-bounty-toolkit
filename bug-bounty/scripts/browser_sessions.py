"""Optional Playwright browser identities using the shared engagement budget.

Importing does not require Playwright. Browser state stays in independent,
non-persistent contexts; no cookie/storage-state export is provided.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import re
import socketserver
import threading
import time
import urllib.parse

from engagement_runtime import (BudgetExceeded, RuntimePolicyError, Scope, ScopeError,
    _number, _deadline_connection, budget_status, collected_headers, confined_path, cookie_secrets, environment_headers, evidence_directory, origin,
    redact, release, reserve, stop_budget, utc_now, write_json)


class BrowserUnavailable(RuntimePolicyError):
    pass


class _DenyProxy:
    """No forwarding, DNS lookup, CONNECT tunnel or direct fallback exists."""
    def __init__(self):
        class Reject(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(.5)
                try:
                    self.request.recv(4096)
                    self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                except OSError:
                    pass
        self.server = socketserver.TCPServer(('127.0.0.1', 0), Reject)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class BrowserSessionManager:
    """Synchronous Playwright adapter; one actor is bound to one exact origin.

    Chromium must be owned by this manager so its deny-only proxy and WebRTC
    restrictions can be set at launch. Caller-managed browser injection fails
    closed. Every identity gets its own fresh, non-persistent context.
    """
    def __init__(self, project, *, allowlist, browser=None, headless=True,
                 timeout=10, allow_write=False, max_response_bytes=1048576):
        _number(timeout, 'timeout', maximum=120)
        _number(max_response_bytes, 'max_response_bytes', maximum=16 * 1024 * 1024)
        if int(max_response_bytes) != max_response_bytes:
            raise RuntimePolicyError('max_response_bytes must be an integer')
        self.project = Path(project).resolve()
        self.scope = Scope(allowlist)
        self.browser = browser
        self.headless = headless
        self.timeout = timeout
        self.allow_write = allow_write
        self.max_response_bytes = max_response_bytes
        self.sessions = {}
        self._playwright = None
        self._owns_browser = browser is None
        self._proxy = None

    def __enter__(self):
        self.start()
        return self

    def start(self):
        budget_status(self.project)
        if not self._owns_browser:
            raise BrowserUnavailable('Caller-managed browsers cannot prove network confinement; omit browser= so this manager launches restricted Chromium')
        if self.browser is not None:
            return self
        try:
            self._proxy = _DenyProxy()
            self._launch_browser()
        except Exception:
            if self._proxy:
                self._proxy.close()
                self._proxy = None
            raise
        return self

    def _launch_browser(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise BrowserUnavailable('Optional browser support requires Playwright in your chosen local Python environment: python -m pip install playwright; then explicitly install a browser with python -m playwright install chromium. No download was attempted.') from None
        try:
            self._playwright = sync_playwright().start()
            self.browser = self._playwright.chromium.launch(headless=self.headless, chromium_sandbox=True,
                proxy={'server': self._proxy.url, 'bypass': '<-loopback>'},
                args=['--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
        except Exception:
            if self._playwright:
                self._playwright.stop()
                self._playwright = None
            raise BrowserUnavailable('Chromium could not launch. Explicitly install its binary using the same Python environment: python -m playwright install chromium; verify local sandbox support. No automatic download or protection bypass was attempted.') from None
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        for session in self.sessions.values():
            try:
                session['context'].close()
            finally:
                for lease in list(session['leases'].values()):
                    release(self.project, lease)
                session['leases'].clear()
        self.sessions.clear()
        if self._owns_browser and self.browser:
            self.browser.close()
            self.browser = None
        if self._playwright:
            self._playwright.stop()
            self._playwright = None
        if self._proxy:
            self._proxy.close()
            self._proxy = None

    def new_session(self, actor, *, credential_env=None, secret_literals=()):
        if actor in self.sessions:
            raise RuntimePolicyError('Actor already has an isolated browser session')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', actor):
            raise RuntimePolicyError('Invalid actor label')
        self.start()
        headers, secrets = environment_headers(credential_env)
        context = self.browser.new_context(accept_downloads=False, ignore_https_errors=False,
            bypass_csp=False, service_workers='block')
        session = {'actor': actor, 'context': context, 'page': None, 'origin': None,
                   'headers': headers, 'secrets': secrets + list(secret_literals),
                   'leases': {}, 'observations': [], 'network_paths': []}
        self.sessions[actor] = session
        context.route('**/*', lambda route: self._route(session, route))
        context.on('response', lambda response: self._response(session, response))
        context.on('requestfinished', lambda request: self._finish(session, request))
        context.on('requestfailed', lambda request: self._finish(session, request))
        # WebSocket upgrades do not pass through HTTP routing. Block them all;
        # they cannot be charged as bounded replay requests by this adapter.
        if hasattr(context, 'route_web_socket'):
            context.route_web_socket('**/*', lambda websocket: websocket.close())
        else:
            context.close()
            del self.sessions[actor]
            raise BrowserUnavailable('This Playwright version lacks WebSocket interception; upgrade Playwright to version 1.48 or newer. No browser traffic was started.')
        session['page'] = context.new_page()
        return {'actor': actor, 'isolated_context': True, 'persistent_storage': False}

    def _observe(self, session, observation):
        session['observations'].append(redact(observation, session['secrets']))

    def _route(self, session, route):
        request = route.request
        try:
            url = self.scope.check(request.url)
            if session['origin'] is None or origin(url) != session['origin']:
                raise ScopeError('Browser identity is bound to its initial navigation origin')
            if request.method.upper() not in ('GET', 'HEAD') and not self.allow_write:
                raise RuntimePolicyError('Browser state changes require allow_write=True for owned state')
            # Fail closed when busy. Blocking this callback would prevent prior
            # response events from freeing leases on Playwright's sync event loop.
            lease = reserve(self.project, timeout=self.timeout, wait=False)
            session['leases'][id(request)] = lease
            headers = {k: v for k, v in request.headers.items() if not re.search(r'authorization|api[-_]?key', k, re.I)}
            headers.update(session['headers'])
            session['secrets'].extend(cookie_secrets(headers))
            # Fulfill browser requests through a bounded transport. Browser-side
            # routing still enforces CSP/CORS and context cookies; the transport
            # checks TLS, never follows redirects, caps bytes, and closes sockets
            # on the overall timeout. Background XHR cannot outlive its lease.
            deadline = min(time.time() + self.timeout, budget_status(self.project)['deadline'])
            status, response_headers, raw, truncated = self._fetch(url, request.method, headers, request.post_data_buffer, deadline)
            session['secrets'].extend(cookie_secrets(response_headers))
            if status in (429, 503) or any(k.lower() == 'retry-after' for k in response_headers):
                stop_budget(self.project)
            directory = evidence_directory(self.project, session['actor'], 'browser-response')
            observation = {'actor': session['actor'], 'utc': utc_now(), 'url': url,
                'status': status, 'body_source': 'bounded-browser-http-response',
                'body_captured': True, 'truncated': truncated, 'captured_bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(),
                'hash_source': 'captured-response-bytes-before-redaction',
                'observations': ['Status alone does not confirm a security finding.']}
            write_json(directory / 'request.json', redact({'actor': session['actor'], 'url': url, 'method': request.method, 'headers': headers, 'body': (request.post_data_buffer or b'').decode('utf-8', errors='replace')}, session['secrets']), project=self.project)
            encoded = any(k.lower() == 'content-encoding' and v.lower() not in ('', 'identity') for k, v in response_headers.items())
            captured_body = '[OMITTED: encoded response body]' if encoded else raw.decode('utf-8', errors='replace')
            write_json(directory / 'response.json', redact({'headers': response_headers, 'body': captured_body, **observation}, session['secrets']), project=self.project)
            write_json(directory / 'metadata.json', redact(observation, session['secrets']), project=self.project)
            session['network_paths'].append(str(directory / 'metadata.json'))
            self._finish(session, request)
            if truncated:
                self._observe(session, {'utc': utc_now(), 'url': url, 'blocked': 'ResponseByteLimit'})
                route.abort('blockedbyclient')
            else:
                # Transfer framing is regenerated by Playwright from the body.
                safe_headers = {k: v for k, v in response_headers.items() if k.lower() not in ('transfer-encoding', 'content-length', 'connection')}
                route.fulfill(status=status, headers=safe_headers, body=raw)
        except (RuntimePolicyError, OSError) as exc:
            self._finish(session, request)
            self._observe(session, {'utc': utc_now(), 'url': request.url, 'blocked': type(exc).__name__})
            route.abort('blockedbyclient')
        except Exception:
            self._finish(session, request)
            self._observe(session, {'utc': utc_now(), 'url': request.url, 'blocked': 'BrowserTransportError'})
            route.abort('blockedbyclient')

    def _fetch(self, url, method, headers, body, deadline):
        parsed = urllib.parse.urlsplit(url)
        remaining = deadline - time.time()
        if remaining <= 0:
            raise BudgetExceeded('Engagement time limit reached')
        cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
        timers = []
        monotonic_deadline = time.monotonic() + remaining
        connection = _deadline_connection(cls, monotonic_deadline, timers)(parsed.hostname, parsed.port, timeout=remaining)
        try:
            connection.connect()
            outgoing = {k: v for k, v in headers.items() if k.lower() not in ('host', 'content-length', 'transfer-encoding', 'connection')}
            outgoing['Accept-Encoding'] = 'identity'
            connection.request(method, urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, '')), body=body, headers=outgoing)
            response = connection.getresponse()
            raw = response.read(self.max_response_bytes + 1) if method != 'HEAD' else b''
            response_headers = collected_headers(response.getheaders())
            return response.status, response_headers, raw[:self.max_response_bytes], len(raw) > self.max_response_bytes
        finally:
            for timer in timers:
                timer.cancel()
            connection.close()

    def _finish(self, session, request):
        lease = session['leases'].pop(id(request), None)
        if lease:
            release(self.project, lease)

    def _response(self, session, response):
        if response.status in (429, 503):
            stop_budget(self.project)

    def navigate(self, actor, url):
        session = self.sessions[actor]
        url = self.scope.check(url)
        if session['origin'] and session['origin'] != origin(url):
            raise ScopeError('Use another browser identity for a different origin')
        session['origin'] = origin(url)
        remaining = min(self.timeout, budget_status(self.project)['deadline'] - time.time())
        if remaining <= 0:
            raise BudgetExceeded('Engagement time limit reached')
        try:
            response = session['page'].goto(url, wait_until='load', timeout=remaining * 1000)
        except Exception:
            # A timed-out navigation must not keep background requests alive.
            session['context'].close()
            for lease in session['leases'].values():
                release(self.project, lease)
            session['leases'].clear()
            raise RuntimePolicyError('Browser navigation failed or timed out; this identity was closed. Inspect redacted observations for blocked requests.') from None
        return {'actor': actor, 'utc': utc_now(), 'url': redact(url, session['secrets']),
            'status': response.status if response else None,
            'body_source': 'browser-navigation-status',
            'network_paths': session['network_paths'][:],
            'observations': session['observations'][:] + ['Rendered content and authorization require analyst review; navigation status is not proof.']}

    def screenshot(self, actor, *, mask_selectors=()):
        """Capture explicit evidence, masking passwords and known secret text.

        Supply mask_selectors for any additional sensitive page content. Cookie,
        localStorage and browser profiles are never exported.
        """
        session = self.sessions[actor]
        page = session['page']
        directory = evidence_directory(self.project, actor, 'browser-screenshot')
        path = confined_path(self.project, directory.relative_to(self.project), 'screenshot.png')
        masks = []
        if hasattr(page, 'locator'):
            masks.append(page.locator('input[type="password"]'))
            masks.extend(page.locator(selector) for selector in mask_selectors)
            for secret in session['secrets']:
                if secret:
                    masks.append(page.get_by_text(secret, exact=False))
                    # Values in form controls are not text nodes.
                    masks.append(page.locator('input,textarea').filter(visible=True))
        page.screenshot(path=str(path), full_page=True, mask=masks, timeout=self.timeout * 1000)
        result = {'actor': actor, 'utc': utc_now(), 'screenshot_path': str(path),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'body_source': 'rendered-browser-screenshot', 'metadata_path': str(directory / 'metadata.json')}
        write_json(result['metadata_path'], result, project=self.project)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project')
    parser.add_argument('actor')
    parser.add_argument('url')
    parser.add_argument('--allow', action='append', required=True)
    parser.add_argument('--credential-env', action='append', default=[], metavar='HEADER=ENV_NAME')
    parser.add_argument('--allow-write', action='store_true')
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--screenshot', action='store_true')
    args = parser.parse_args(argv)
    try:
        with BrowserSessionManager(args.project, allowlist=args.allow, timeout=args.timeout, allow_write=args.allow_write) as manager:
            manager.new_session(args.actor, credential_env=dict(item.split('=', 1) for item in args.credential_env))
            result = manager.navigate(args.actor, args.url)
            if args.screenshot:
                result['screenshot'] = manager.screenshot(args.actor)
            print(json.dumps(result, indent=2))
        return 0
    except (RuntimePolicyError, ValueError, OSError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'message': str(exc) if isinstance(exc, RuntimePolicyError) else 'Browser operation failed'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
