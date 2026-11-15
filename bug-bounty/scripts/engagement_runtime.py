"""Bounded, explicitly scoped HTTP replay with project-local shared budgets.

No target is implied by this module: callers supply an explicit allowlist and an
already authorized project. Credentials are supplied only by environment name.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import http.cookiejar
from http.cookies import SimpleCookie
import json
import math
import os
from pathlib import Path
import queue
import re
import sqlite3
import socket
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class RuntimePolicyError(ValueError):
    pass


class ScopeError(RuntimePolicyError):
    pass


class BudgetExceeded(RuntimePolicyError):
    pass


SENSITIVE = re.compile(r'authorization|cookie|password|passwd|secret|token|api[-_]?key', re.I)
RESERVED_HEADERS = frozenset(('host', 'content-length', 'transfer-encoding', 'connection', 'proxy-authorization', 'proxy-connection', 'trailer', 'upgrade', 'te'))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _number(value, name, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= minimum or (maximum is not None and value > maximum):
        raise RuntimePolicyError(f'{name} must be finite, greater than {minimum}' + (f' and at most {maximum}' if maximum else ''))
    return value


def confined_path(project, *parts):
    """Validate every child before any read/create, including NTFS junctions.

    The engagement root is caller-owned. Concurrent hostile replacement of its
    directories is outside this local helper's filesystem threat model.
    """
    root = Path(project).resolve()
    candidate = root.joinpath(*parts)
    if not candidate.is_relative_to(root):
        raise RuntimePolicyError('Internal artifact path is outside the engagement project')
    current = root
    for part in candidate.relative_to(root).parts:
        current = current / part
        junction_check = getattr(current, 'is_junction', None)
        if callable(junction_check):
            junction = junction_check()
        else:
            try:
                junction = getattr(current.lstat(), 'st_reparse_tag', None) == getattr(stat, 'IO_REPARSE_TAG_MOUNT_POINT', -1)
            except FileNotFoundError:
                junction = False
        if current.is_symlink() or junction or not current.resolve().is_relative_to(root):
            raise RuntimePolicyError('Internal engagement paths cannot contain symlinks or junctions')
        if current.is_file() and current.stat().st_nlink > 1:
            raise RuntimePolicyError('Internal engagement files cannot have multiple hard links')
    return candidate


def _db_path(project):
    path = confined_path(project, '.engagement', 'budget.sqlite3')
    # SQLite can create/open these companion files independently of its main DB.
    for suffix in ('-journal', '-wal', '-shm'):
        confined_path(project, '.engagement', 'budget.sqlite3' + suffix)
    return path


@contextmanager
def _connection(project):
    path = _db_path(project)
    if not path.exists():
        raise RuntimePolicyError('Budget is absent; call init_budget(project, ...) first')
    db = sqlite3.connect(path, timeout=5, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def init_budget(project, *, max_requests=30, rate_per_second=2.0, concurrency=1, duration_seconds=300):
    """Create a new budget. Never reset an existing engagement implicitly."""
    for value, name in [(max_requests, 'max_requests'), (rate_per_second, 'rate_per_second'), (concurrency, 'concurrency'), (duration_seconds, 'duration_seconds')]:
        _number(value, name)
    if int(max_requests) != max_requests or int(concurrency) != concurrency:
        raise RuntimePolicyError('max_requests and concurrency must be integers')
    path = _db_path(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    path = _db_path(project)
    db = sqlite3.connect(path, timeout=5, isolation_level=None)
    try:
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY CHECK(id=1), max_requests INTEGER, rate REAL, concurrency INTEGER, deadline REAL, used INTEGER, next_at REAL, stopped TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS leases (token TEXT PRIMARY KEY, expires REAL)')
        if db.execute('SELECT 1 FROM budget').fetchone():
            raise RuntimePolicyError('Budget already exists; use a new project for a new engagement')
        db.execute('INSERT INTO budget VALUES (1,?,?,?,?,0,0,NULL)', (int(max_requests), rate_per_second, int(concurrency), time.time() + duration_seconds))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return path


def budget_status(project):
    with _connection(project) as db:
        row = db.execute('SELECT * FROM budget WHERE id=1').fetchone()
        if row is None:
            raise RuntimePolicyError('Budget initialization is incomplete')
        result = dict(row)
        result['active'] = db.execute('SELECT COUNT(*) FROM leases WHERE expires>?', (time.time(),)).fetchone()[0]
        return result


def reserve(project, *, timeout=10, wait=False):
    """Atomically consume one attempt and return its concurrency lease token.

    A failed network attempt still consumes its reservation. Leases expire after
    timeout plus one second for recovery after a process exits unexpectedly.
    """
    _number(timeout, 'timeout', maximum=120)
    wait_until = time.monotonic() + timeout
    while True:
        with _connection(project) as db:
            db.execute('BEGIN IMMEDIATE')
            now = time.time()
            row = db.execute('SELECT * FROM budget WHERE id=1').fetchone()
            if row is None:
                raise RuntimePolicyError('Budget initialization is incomplete')
            if row['stopped'] or now >= row['deadline'] or row['used'] >= row['max_requests']:
                raise BudgetExceeded('Engagement stopped, expired, or request total exhausted')
            db.execute('DELETE FROM leases WHERE expires<=?', (now,))
            active = db.execute('SELECT COUNT(*) FROM leases').fetchone()[0]
            blocked = active >= row['concurrency'] or now < row['next_at']
            if not blocked:
                token = uuid.uuid4().hex
                db.execute('INSERT INTO leases VALUES (?,?)', (token, now + timeout + 1))
                db.execute('UPDATE budget SET used=used+1, next_at=? WHERE id=1', (now + 1 / row['rate'],))
                db.commit()
                return token
            db.rollback()
        if not wait or time.monotonic() >= wait_until:
            raise BudgetExceeded('Concurrency or request rate limit reached')
        time.sleep(min(.05, max(.001, wait_until - time.monotonic())))


def release(project, token):
    with _connection(project) as db:
        db.execute('DELETE FROM leases WHERE token=?', (token,))


def stop_budget(project, reason='target-distress'):
    with _connection(project) as db:
        db.execute('UPDATE budget SET stopped=? WHERE id=1', (reason,))


def normalize_url(url):
    try:
        if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url) or '\\' in url:
            raise ValueError()
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError()
        host = parsed.hostname.encode('idna').decode('ascii').lower()
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        # Reject ambiguous separators and dot segments, including nested encoding.
        path = parsed.path or '/'
        decoded = path
        for _ in range(5):
            next_path = urllib.parse.unquote(decoded, errors='strict')
            if '\\' in next_path or any(ord(c) < 32 for c in next_path):
                raise ValueError()
            if any(part in ('.', '..') for part in next_path.split('/')):
                raise ValueError()
            if next_path == decoded:
                break
            if next_path.count('/') != decoded.count('/'):
                raise ValueError()
            decoded = next_path
        if '%' in decoded or '//' in path:
            raise ValueError()
        authority = f'[{host}]' if ':' in host else host
        if port and port != (443 if parsed.scheme.lower() == 'https' else 80):
            authority += f':{port}'
        return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, parsed.query, ''))
    except (ValueError, UnicodeError):
        raise ScopeError('URL must be an unambiguous HTTP(S) URL without userinfo, fragment, or traversal') from None


def origin(url):
    p = urllib.parse.urlsplit(normalize_url(url))
    return f'{p.scheme}://{p.netloc}'


class Scope:
    def __init__(self, allowlist):
        if not allowlist:
            raise ScopeError('Provide an explicit origin/path allowlist')
        self.entries = []
        for entry in allowlist:
            p = urllib.parse.urlsplit(normalize_url(entry))
            if p.query:
                raise ScopeError('Allowlist entries cannot contain query strings')
            self.entries.append((f'{p.scheme}://{p.netloc}', p.path.rstrip('/') or '/'))

    def check(self, url):
        normalized = normalize_url(url)
        p = urllib.parse.urlsplit(normalized)
        current_origin = f'{p.scheme}://{p.netloc}'
        if not any(current_origin == allowed and (prefix == '/' or p.path == prefix or p.path.startswith(prefix + '/')) for allowed, prefix in self.entries):
            raise ScopeError('URL is outside the explicit origin/path allowlist')
        return normalized


def environment_headers(credential_env):
    result = {}
    secrets = []
    for header, variable in (credential_env or {}).items():
        if not isinstance(header, str) or header.lower() in RESERVED_HEADERS:
            raise RuntimePolicyError('Reserved routing/framing headers cannot be supplied as credentials')
        if not isinstance(variable, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', variable):
            raise RuntimePolicyError('Credentials must reference environment variable names')
        value = os.environ.get(variable)
        if not value:
            raise RuntimePolicyError(f'Required credential environment variable is absent: {variable}')
        if not re.fullmatch(r'[!#$%&\'*+.^_`|~0-9A-Za-z-]+', header) or '\r' in value or '\n' in value:
            raise RuntimePolicyError('Invalid credential header')
        result[header] = value
        secrets.extend([value, value.split(' ', 1)[-1]])
    return result, secrets


def redact(value, secrets=()):
    """Redact known literals, common structured secret fields, and headers."""
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SENSITIVE.search(str(k)) else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    # Match encoded representations before they reach an artifact as well as
    # plain literals. JSON decoding also catches structured cookie/token fields.
    try:
        structured = json.loads(value)
    except (ValueError, TypeError):
        structured = None
    if isinstance(structured, (dict, list)):
        return json.dumps(redact(structured, secrets), ensure_ascii=True)
    for secret in sorted(set(x for x in secrets if x), key=len, reverse=True):
        for variant in (secret, urllib.parse.quote(secret, safe=''), urllib.parse.quote_plus(secret), json.dumps(secret)[1:-1]):
            value = value.replace(variant, '[REDACTED]')
    value = re.sub(r'(?i)([?&](?:[^=&]*(?:token|secret|password|api[_-]?key)[^=&]*)=)[^&#]*', r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(["\'](?:password|passwd|secret|token|access_token|api_key)["\']\s*:\s*["\'])[^"\']*', r'\1[REDACTED]', value)
    return value


def cookie_secrets(headers):
    values = []
    for key, value in headers.items():
        if key.lower() in ('cookie', 'set-cookie'):
            for line in value.splitlines():
                cookies = SimpleCookie()
                try:
                    cookies.load(line)
                    values.extend(item.value for item in cookies.values() if item.value)
                except Exception:
                    pass
    return values


def evidence_directory(project, actor, kind='http'):
    if not isinstance(actor, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', actor):
        raise RuntimePolicyError('actor must be a short identity label using letters, digits, dot, dash, underscore')
    if not re.fullmatch(r'[A-Za-z0-9-]{1,40}', kind):
        raise RuntimePolicyError('Invalid evidence kind')
    name = f'{kind}-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")}-{actor}-{uuid.uuid4().hex[:12]}'
    directory = confined_path(project, 'evidence', name)
    directory.mkdir(parents=True, exist_ok=False)
    return confined_path(project, 'evidence', name)


def write_json(path, value, *, project):
    root = Path(project).resolve()
    path = confined_path(root, Path(path).relative_to(root))
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')


def collected_headers(pairs):
    """Preserve repeated cookie fields before redaction and browser fulfillment."""
    result = {}
    for key, value in pairs:
        previous = next((name for name in result if name.lower() == key.lower()), None)
        if previous:
            result[previous] += ('\n' if key.lower() == 'set-cookie' else ', ') + value
        else:
            result[key] = value
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def bounded_create_connection(address, timeout, source_address=None, *, deadline):
    """Bound DNS wait and TCP connection without a late background HTTP send."""
    host, port = address
    resolved = queue.Queue(maxsize=1)
    def lookup():
        try:
            resolved.put((socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM), None))
        except Exception as exc:
            resolved.put((None, exc))
    resolver = threading.Thread(target=lookup, daemon=True)
    resolver.start()
    try:
        addresses, error = resolved.get(timeout=max(.001, min(timeout, deadline - time.monotonic())))
    except queue.Empty:
        raise TimeoutError('DNS lookup exceeded request deadline') from None
    if error:
        raise error
    last_error = None
    for family, socktype, protocol, _, sockaddr in addresses:
        remaining = min(timeout, deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError('Connection deadline reached')
        candidate = socket.socket(family, socktype, protocol)
        try:
            candidate.settimeout(remaining)
            if source_address:
                candidate.bind(source_address)
            candidate.connect(sockaddr)
            return candidate
        except OSError as exc:
            last_error = exc
            candidate.close()
    raise last_error or OSError('No usable resolved address')


def _deadline_connection(cls, deadline, timers):
    class DeadlineConnection(cls):
        def connect(self):
            # Begin the watchdog after TCP connection, before TLS handshaking.
            http.client.HTTPConnection.connect(self)
            def interrupt():
                try:
                    if self.sock:
                        self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(max(.001, deadline - time.monotonic()), interrupt)
            timer.daemon = True
            timers.append(timer)
            timer.start()
            if cls is http.client.HTTPSConnection:
                self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host, do_handshake_on_connect=False)
                self.sock.do_handshake()

    def factory(*args, **kwargs):
        connection = DeadlineConnection(*args, **kwargs)
        connection._create_connection = lambda address, timeout, source_address=None: bounded_create_connection(address, timeout, source_address, deadline=deadline)
        return connection
    return factory


class _TimedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, deadline, timers):
        super().__init__()
        self.deadline, self.timers = deadline, timers

    def http_open(self, request):
        return self.do_open(_deadline_connection(http.client.HTTPConnection, self.deadline, self.timers), request)


class _TimedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, deadline, timers):
        super().__init__()
        self.deadline, self.timers = deadline, timers

    def https_open(self, request):
        return self.do_open(_deadline_connection(http.client.HTTPSConnection, self.deadline, self.timers), request, context=self._context)


class ReplayClient:
    def __init__(self, project, *, allowlist):
        self.project = Path(project).resolve()
        self.scope = Scope(allowlist)
        self.jars = {}
        self.actor_secrets = {}
        self.lock = threading.Lock()

    def replay(self, actor, url, *, method='GET', credential_env=None, headers=None, body=None, allow_write=False, timeout=10, retries=0, max_response_bytes=1048576, follow_redirects=False, max_redirects=3, secret_envs=(), secret_literals=()):
        method = method.upper()
        if method not in ('GET', 'HEAD') and not allow_write:
            raise RuntimePolicyError('State-changing methods require explicit allow_write=True for owned state')
        if method not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
            raise RuntimePolicyError('Unsupported HTTP method')
        if retries not in range(4) or max_redirects not in range(6):
            raise RuntimePolicyError('retries must be 0..3; max_redirects must be 0..5')
        if retries and method not in ('GET', 'HEAD'):
            raise RuntimePolicyError('Writes cannot be retried automatically')
        _number(timeout, 'timeout', maximum=120)
        _number(max_response_bytes, 'max_response_bytes', maximum=16 * 1024 * 1024)
        if int(max_response_bytes) != max_response_bytes:
            raise RuntimePolicyError('max_response_bytes must be an integer')
        url = self.scope.check(url)
        initial_origin = origin(url)
        auth_headers, secrets = environment_headers(credential_env)
        secrets += list(secret_literals)
        for variable in secret_envs:
            if variable not in os.environ:
                raise RuntimePolicyError('Redaction environment variable is absent')
            secrets.append(os.environ[variable])
        with self.lock:
            remembered = self.actor_secrets.setdefault(actor, set())
            remembered.update(secrets)
            secrets = list(remembered)
        outgoing = dict(headers or {})
        if any(SENSITIVE.search(k) for k in outgoing):
            raise RuntimePolicyError('Sensitive headers must use credential_env references')
        if any(k.lower() in RESERVED_HEADERS or '\r' in str(v) or '\n' in str(v) for k, v in outgoing.items()):
            raise RuntimePolicyError('Unsupported request header')
        outgoing.update(auth_headers)
        outgoing['Accept-Encoding'] = 'identity'
        if isinstance(body, str):
            body = body.encode('utf-8')
        if body is not None and not isinstance(body, bytes):
            raise RuntimePolicyError('body must be bytes or text')
        if body and method in ('GET', 'HEAD'):
            raise RuntimePolicyError('GET/HEAD bodies are disabled')
        attempts = []
        redirects = 0
        retry_count = 0
        while True:
            # Validate before each actual network operation, including redirects.
            url = self.scope.check(url)
            directory = evidence_directory(self.project, actor)
            lease = reserve(self.project, timeout=timeout, wait=True)
            deadline = min(time.monotonic() + timeout, time.monotonic() + max(0, budget_status(self.project)['deadline'] - time.time()))
            status = None
            response_headers = {}
            raw = b''
            error = None
            truncated = False
            timers = []
            try:
                current_headers = dict(outgoing)
                if origin(url) != initial_origin:
                    current_headers = {k: v for k, v in current_headers.items() if k not in auth_headers and not SENSITIVE.search(k)}
                key = (actor, origin(url))
                with self.lock:
                    jar = self.jars.setdefault(key, http.cookiejar.CookieJar())
                    secrets.extend(cookie.value for cookie in jar)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPCookieProcessor(jar), _TimedHTTPHandler(deadline, timers), _TimedHTTPSHandler(deadline, timers))
                request = urllib.request.Request(url, data=body, headers=current_headers, method=method)
                request_capture = {'actor': actor, 'utc': utc_now(), 'method': method, 'url': url, 'headers': current_headers, 'body': (body or b'').decode('utf-8', errors='replace')}
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                try:
                    response = opener.open(request, timeout=remaining)
                except urllib.error.HTTPError as response_error:
                    response = response_error
                with response:
                    status = response.status
                    response_headers = collected_headers(response.headers.items())
                    secrets.extend(cookie_secrets(response_headers))
                    secrets.extend(cookie.value for cookie in jar)
                    with self.lock:
                        self.actor_secrets[actor].update(secrets)
                    if status in (429, 503) or response.headers.get('Retry-After'):
                        stop_budget(self.project)
                    chunks = []
                    captured = 0
                    while method != 'HEAD' and captured <= max_response_bytes:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError()
                        # urllib's socket timeout covers each read; bound the entire
                        # attempt too, using read1 rather than a fill-until-size read.
                        socket = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
                        if socket is not None:
                            socket.settimeout(remaining)
                        chunk = response.read1(min(65536, max_response_bytes + 1 - captured))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        captured += len(chunk)
                    raw = b''.join(chunks)
                    truncated = len(raw) > max_response_bytes
                    raw = raw[:max_response_bytes]
            except (urllib.error.URLError, OSError, TimeoutError, ValueError, http.client.HTTPException) as exc:
                error = type(exc).__name__  # Exception text may contain credentials.
                request_capture = {'actor': actor, 'utc': utc_now(), 'method': method, 'url': url, 'headers': current_headers, 'body': (body or b'').decode('utf-8', errors='replace')}
            finally:
                for timer in timers:
                    timer.cancel()
                release(self.project, lease)
            encoded = any(k.lower() == 'content-encoding' and v.lower() not in ('', 'identity') for k, v in response_headers.items())
            decoded = '[OMITTED: encoded response body; inspect through an explicitly decoded, redacted workflow]' if encoded else raw.decode('utf-8', errors='replace')
            safe_body = redact(decoded, secrets)
            result = {'actor': actor, 'utc': utc_now(), 'url': redact(url, secrets), 'status': status, 'body': safe_body, 'body_source': 'http-response-encoded-omitted' if encoded else ('http-response' if status is not None else 'transport-error'), 'truncated': truncated, 'captured_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'hash_source': 'captured-response-bytes-before-redaction', 'error': error, 'observations': ['HTTP observations require content and authorization analysis; status alone does not confirm a security finding.'], 'evidence_dir': str(directory), 'request_path': str(directory / 'request.json'), 'response_path': str(directory / 'response.json'), 'metadata_path': str(directory / 'metadata.json')}
            write_json(result['request_path'], redact(request_capture, secrets), project=self.project)
            write_json(result['response_path'], {'status': status, 'headers': redact(response_headers, secrets), 'body': safe_body, 'body_source': result['body_source'], 'truncated': truncated}, project=self.project)
            write_json(result['metadata_path'], {k: v for k, v in result.items() if k != 'body'}, project=self.project)
            attempts.append(str(directory))
            result['attempt_paths'] = attempts[:]
            if error and retry_count < retries:
                retry_count += 1
                continue
            if follow_redirects and status in (301, 302, 303, 307, 308) and 'Location' in response_headers:
                if method not in ('GET', 'HEAD'):
                    raise RuntimePolicyError('Automatic redirects for state-changing methods are disabled')
                if redirects >= max_redirects:
                    raise RuntimePolicyError('Redirect limit reached')
                redirects += 1
                url = self.scope.check(urllib.parse.urljoin(url, response_headers['Location']))
                continue
            return result


_clients = {}
_clients_lock = threading.Lock()


def replay(project, actor, url, *, allowlist, **kwargs):
    key = (str(Path(project).resolve()), tuple(allowlist))
    with _clients_lock:
        client = _clients.setdefault(key, ReplayClient(project, allowlist=allowlist))
    return client.replay(actor, url, **kwargs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('project')
    init.add_argument('--max-requests', type=int, default=30)
    init.add_argument('--rate-per-second', type=float, default=2)
    init.add_argument('--concurrency', type=int, default=1)
    init.add_argument('--duration-seconds', type=float, default=300)
    status = sub.add_parser('status')
    status.add_argument('project')
    request = sub.add_parser('replay')
    request.add_argument('project')
    request.add_argument('actor')
    request.add_argument('url')
    request.add_argument('--allow', action='append', required=True)
    request.add_argument('--credential-env', action='append', default=[], metavar='HEADER=ENV_NAME')
    request.add_argument('--method', default='GET')
    request.add_argument('--allow-write', action='store_true')
    request.add_argument('--body-file')
    request.add_argument('--timeout', type=float, default=10)
    request.add_argument('--retries', type=int, default=0)
    request.add_argument('--max-response-bytes', type=int, default=1048576)
    request.add_argument('--follow-redirects', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            value = {'budget_path': str(init_budget(args.project, max_requests=args.max_requests, rate_per_second=args.rate_per_second, concurrency=args.concurrency, duration_seconds=args.duration_seconds))}
        elif args.command == 'status':
            value = budget_status(args.project)
        else:
            credentials = dict(item.split('=', 1) for item in args.credential_env)
            value = replay(args.project, args.actor, args.url, allowlist=args.allow, credential_env=credentials, method=args.method, allow_write=args.allow_write, body=Path(args.body_file).read_bytes() if args.body_file else None, timeout=args.timeout, retries=args.retries, max_response_bytes=args.max_response_bytes, follow_redirects=args.follow_redirects)
        print(json.dumps(value, indent=2))
        return 0
    except (RuntimePolicyError, OSError, ValueError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'message': str(exc) if isinstance(exc, RuntimePolicyError) else 'Local operation failed'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
