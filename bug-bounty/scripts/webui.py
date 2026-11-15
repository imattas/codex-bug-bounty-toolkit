"""A dependency-free, loopback-only viewer for local engagement reports.

python scripts/webui.py --root /path/to/engagements --port 8765 --open
The viewer reads recorded decisions; manual tracking never changes triage gates.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import threading
import webbrowser

from engagement_runtime import confined_path, RuntimePolicyError
from finding_bundle import gate_reasons

MAX_JSON = 256 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_FINDINGS = 1000
MAX_SCAN_ARTIFACT_BYTES = 32 * 1024 * 1024
STATUSES = ('unreviewed', 'reviewed', 'submitted', 'fixed', 'archived')
ASSETS = Path(__file__).resolve().parents[1] / 'assets/webui'
SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$')
NOTE_CATEGORIES = frozenset(('informational', 'info', 'duplicate', 'out_of_scope', 'unpersisted_write',
                             'blocked', 'rejected', 'held', 'unconfirmed', 'not_actionable'))


def bounded_text(value, limit=500):
    return value[:limit] if isinstance(value, str) else ''


def read_bytes(root, path, limit):
    safe = confined_path(root, path.relative_to(root))
    if not safe.is_file() or safe.stat().st_size > limit:
        raise ValueError('File unavailable or too large')
    with safe.open('rb') as handle:
        result = handle.read(limit + 1)
    if len(result) > limit:
        raise ValueError('File too large')
    return result


def read_json(root, path):
    value = json.loads(read_bytes(root, path, MAX_JSON).decode('utf-8-sig'))
    if not isinstance(value, dict):
        raise ValueError('Expected an object')
    return value


class Catalog:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError('Root must be an existing directory')
        self.lock = threading.RLock()
        self.items = {}
        self.artifacts = {}
        self.state = {}
        self.truncated = False
        self.scan()

    def children(self, folder, budget):
        """Bound enumeration before sorting, and reject junctions and links."""
        result = []
        try:
            confined_path(self.root, folder.relative_to(self.root))
            with os.scandir(folder) as entries:
                for entry in entries:
                    budget[0] += 1
                    if budget[0] > MAX_ENTRIES:
                        self.truncated = True
                        break
                    try:
                        path = confined_path(self.root, Path(entry.path).relative_to(self.root))
                        result.append(path)
                    except (OSError, ValueError, RuntimePolicyError):
                        continue
        except (OSError, ValueError, RuntimePolicyError):
            return []
        return sorted(result, key=lambda p: p.name.casefold())

    def item(self, path, metadata, *, kind, note='', suffix=''):
        relative = path.relative_to(self.root).as_posix()
        identifier = hashlib.sha256((relative + suffix).encode()).hexdigest()[:24]
        report = metadata.get('report', {})
        report = report if isinstance(report, dict) else {}
        gates = metadata.get('gates', {})
        gates = gates if isinstance(gates, dict) else {}
        public_gates = {name: bounded_text(gate.get('status'), 80)
                        for name in ('scope', 'validation', 'actionability', 'duplicate')
                        if isinstance((gate := gates.get(name)), dict)}
        reasons = gate_reasons(metadata)
        title = bounded_text(report.get('title')) or bounded_text(metadata.get('title')) or path.stem
        if kind == 'report' and not report.get('title'):
            try:
                safe = confined_path(self.root, path.relative_to(self.root))
                with safe.open('rb') as handle:
                    first = handle.read(1024).decode('utf-8', errors='replace').splitlines()[0]
                title = first.lstrip('# ').strip()[:500] or title
            except (ValueError, OSError, IndexError):
                pass
        severity = report.get('severity', {})
        severity = severity if isinstance(severity, dict) else {}
        score = severity.get('score')
        if type(score) not in (int, float) or not 0 <= score <= 10:
            score = None
        item = {'id': identifier, 'kind': kind, 'title': title,
                'program': bounded_text(metadata.get('program'), 120) or self.engagement_name(path),
                'reference': relative, 'decision': 'held' if reasons else 'actionable',
                'gate_statuses': public_gates, 'gate_reasons': reasons, 'score': score,
                'note': bounded_text(note, 2000), 'artifacts': [], '_path': path}
        self.items[identifier] = item
        return item

    def engagement_name(self, path):
        parts = path.relative_to(self.root).parts
        return parts[0] if parts and parts[0] not in ('findings', '.bug-bounty') else self.root.name

    def scan(self):
        with self.lock:
            self.items = {}
            self.artifacts = {}
            self.truncated = False
            budget = [0]
            artifact_bytes = 0
            projects = []
            queue = [(self.root, 0)]
            while queue and budget[0] <= MAX_ENTRIES:
                folder, depth = queue.pop(0)
                children = self.children(folder, budget)
                if any(p.name in ('findings', '.bug-bounty') and p.is_dir() for p in children):
                    projects.append(folder)
                if depth < 2:
                    queue.extend((p, depth + 1) for p in children if p.is_dir() and not p.name.startswith('.')
                                 and p.name not in ('findings', 'node_modules', 'poc', 'evidence', '__pycache__'))
            bundled = set()
            supporting_sources = set()
            for project in projects:
                for finding in self.children(project / 'findings', budget):
                    if len(self.items) >= MAX_FINDINGS:
                        self.truncated = True
                        break
                    try:
                        report = confined_path(self.root, (finding / 'report.md').relative_to(self.root))
                        if not finding.is_dir() or not report.is_file():
                            continue
                        if report.stat().st_size > MAX_FILE:
                            continue
                        try:
                            meta = read_json(self.root, finding / 'evidence/assessment.json')
                        except (OSError, ValueError, RuntimePolicyError):
                            meta = {}
                        item = self.item(report, meta, kind='report')
                        bundled.add((project, bounded_text(meta.get('slug')) or finding.name))
                        for field in ('poc_files', 'evidence_files'):
                            sources = meta.get(field, [])
                            if not isinstance(sources, list):
                                continue
                            for source in sources[:100]:
                                if not isinstance(source, str) or Path(source).is_absolute():
                                    continue
                                try:
                                    supporting_sources.add(confined_path(self.root, (project / source).relative_to(self.root)))
                                except (OSError, ValueError, RuntimePolicyError):
                                    continue
                        manifest = meta.get('artifact_sha256', {})
                        if meta.get('artifacts_reviewed') is True and isinstance(manifest, dict):
                            for rel, expected in list(manifest.items())[:100]:
                                if not isinstance(rel, str) or not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
                                    continue
                                parts = rel.split('/')
                                if len(parts) != 2 or parts[0] not in ('poc', 'evidence') or not SAFE_NAME.fullmatch(parts[1]) or parts[1].lower() == 'assessment.json':
                                    continue
                                try:
                                    path = confined_path(self.root, (finding / rel).relative_to(self.root))
                                    if path.stat().st_size + artifact_bytes > MAX_SCAN_ARTIFACT_BYTES:
                                        self.truncated = True
                                        continue
                                    payload = read_bytes(self.root, path, MAX_FILE)
                                    artifact_bytes += len(payload)
                                    if hashlib.sha256(payload).hexdigest() != expected:
                                        continue
                                except (OSError, ValueError, RuntimePolicyError):
                                    continue
                                key = hashlib.sha256((item['id'] + rel + expected).encode()).hexdigest()
                                self.artifacts[key] = (path, expected)
                                item['artifacts'].append({'name': parts[1], 'kind': parts[0], 'size': len(payload),
                                                          'url': '/api/artifacts/' + key,
                                                          'image': self.image_type(payload, path) is not None})
                    except (OSError, ValueError, RuntimePolicyError):
                        continue
            for project in projects:
                candidates = [(project / '.bug-bounty/candidates', 0)]
                while candidates and len(self.items) < MAX_FINDINGS:
                    folder, depth = candidates.pop(0)
                    for path in self.children(folder, budget):
                        if path in supporting_sources:
                            continue
                        if path.is_dir() and depth < 2:
                            candidates.append((path, depth + 1))
                        elif path.suffix.lower() == '.json':
                            try:
                                meta = read_json(self.root, path)
                                if meta.get('schema_version') == 1 or isinstance(meta.get('gates'), dict):
                                    if (project, bounded_text(meta.get('slug'))) not in bundled:
                                        self.item(path, meta, kind='candidate')
                                else:
                                    if isinstance(meta.get('title'), str):
                                        self.item(path, {'title': meta['title'], 'program': meta.get('program')}, kind='candidate',
                                                  note=bounded_text(meta.get('reason') or meta.get('summary'), 2000))
                                    for name, note in list(meta.items())[:100]:
                                        if len(self.items) >= MAX_FINDINGS:
                                            self.truncated = True
                                            break
                                        if name in NOTE_CATEGORIES and isinstance(note, str):
                                            self.item(path, {'title': bounded_text(name)}, kind='candidate', note=note, suffix=name)
                            except (OSError, ValueError, RuntimePolicyError):
                                continue
                        elif path.suffix.lower() in ('.md', '.txt'):
                            # Unstructured internal notes are never dumped through the API.
                            self.item(path, {}, kind='candidate', note='Unstructured candidate notes. Review the original locally before recording triage decisions.')
                        if len(self.items) >= MAX_FINDINGS:
                            self.truncated = True
                            break
            self.state = self.load_state()

    @staticmethod
    def image_type(payload, path):
        if path.suffix.lower() == '.png' and payload.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        if path.suffix.lower() in ('.jpg', '.jpeg') and payload.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        return None

    def load_state(self):
        try:
            state = read_json(self.root, self.root / '.bug-bounty-webui/state.json')
            return {k: {'status': v['status'], 'notes': bounded_text(v.get('notes'), 4000)}
                    for k, v in state.items() if isinstance(v, dict) and v.get('status') in STATUSES}
        except (OSError, ValueError, RuntimePolicyError):
            return {}

    def public(self, item, detail=False):
        result = {k: v for k, v in item.items() if not k.startswith('_') and (detail or k != 'artifacts')}
        result['workflow'] = self.state.get(item['id'], {'status': 'unreviewed', 'notes': ''})
        if detail:
            result['report'] = read_bytes(self.root, item['_path'], MAX_FILE).decode('utf-8', errors='replace') if item['kind'] == 'report' else ''
        return result

    def save(self, identifier, body):
        with self.lock:
            if identifier not in self.items:
                raise KeyError(identifier)
            if set(body) != {'status', 'notes'} or body['status'] not in STATUSES or not isinstance(body['notes'], str) or len(body['notes']) > 4000:
                raise ValueError('Use a valid workflow status and at most 4000 characters of notes')
            folder = confined_path(self.root, '.bug-bounty-webui')
            folder.mkdir(exist_ok=True)
            target = confined_path(self.root, '.bug-bounty-webui/state.json')
            state = self.load_state()
            state[identifier] = body
            payload = (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode()
            if len(payload) > MAX_JSON:
                raise ValueError('Local tracking storage is full')
            temp = confined_path(self.root, '.bug-bounty-webui', secrets.token_hex(16) + '.tmp')
            try:
                with temp.open('xb') as handle:
                    handle.write(payload)
                confined_path(self.root, '.bug-bounty-webui/state.json')
                os.replace(temp, target)
            finally:
                temp.unlink(missing_ok=True)
            self.state = state
            return body


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class Handler(BaseHTTPRequestHandler):
    server_version = 'LocalFindings/1'

    def log_message(self, *_):
        pass

    def send(self, code, payload=b'', mime='application/json; charset=utf-8', extra=None):
        self.send_response(code)
        for key, value in {'Content-Type': mime, 'Content-Length': str(len(payload)), 'Cache-Control': 'no-store',
                           'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                           'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", **(extra or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def json(self, code, value):
        self.send(code, json.dumps(value, ensure_ascii=False).encode())

    def guard(self):
        origin = self.server.origin
        if self.client_address[0] != '127.0.0.1' or self.headers.get_all('Host') != [origin.removeprefix('http://')]:
            self.json(403, {'error': 'Use the printed 127.0.0.1 URL'})
            return False
        origins = self.headers.get_all('Origin')
        if (origins is not None and origins != [origin]) or self.headers.get('Sec-Fetch-Site', '') not in ('', 'same-origin', 'none'):
            self.json(403, {'error': 'Cross-origin requests are blocked'})
            return False
        return True

    def do_GET(self):
        if not self.guard():
            return
        try:
            if self.path in ('/', '/index.html', '/app.js', '/styles.css'):
                name = 'index.html' if self.path == '/' else self.path[1:]
                self.send(200, (ASSETS / name).read_bytes(), {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'styles.css': 'text/css; charset=utf-8'}[name])
            elif self.path == '/api/findings':
                catalog = self.server.catalog
                with catalog.lock:
                    catalog.scan()
                    self.json(200, {'findings': [catalog.public(item) for item in catalog.items.values()],
                                    'csrf_token': self.server.csrf_token, 'truncated': catalog.truncated,
                                    'root_name': catalog.root.name})
            elif re.fullmatch(r'/api/findings/[0-9a-f]{24}', self.path):
                catalog = self.server.catalog
                with catalog.lock:
                    self.json(200, catalog.public(catalog.items[self.path.rsplit('/', 1)[1]], detail=True))
            elif re.fullmatch(r'/api/artifacts/[0-9a-f]{64}(?:\?preview=1)?', self.path):
                key = self.path.split('?', 1)[0].rsplit('/', 1)[1]
                catalog = self.server.catalog
                with catalog.lock:
                    path, expected = catalog.artifacts[key]
                    payload = read_bytes(catalog.root, path, MAX_FILE)
                    if hashlib.sha256(payload).hexdigest() != expected:
                        raise ValueError('Artifact changed; refresh findings')
                    image = catalog.image_type(payload, path) if self.path.endswith('?preview=1') else None
                    self.send(200, payload, image or 'application/octet-stream',
                              {'Content-Disposition': ('inline' if image else 'attachment') + '; filename="' + path.name + '"'})
            else:
                self.json(404, {'error': 'Not found'})
        except KeyError:
            self.json(404, {'error': 'Not found; refresh findings'})
        except (OSError, ValueError, RuntimePolicyError):
            self.json(409, {'error': 'File unavailable, changed, oversized, or outside the permitted local paths'})

    def do_POST(self):
        if not self.guard():
            return
        if self.headers.get('Origin') != self.server.origin or not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), self.server.csrf_token):
            self.json(403, {'error': 'Same-origin CSRF token required'})
            return
        if not re.fullmatch(r'/api/findings/[0-9a-f]{24}/state', self.path):
            self.json(404, {'error': 'Not found'})
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if self.headers.get('Transfer-Encoding') is not None or self.headers.get('Content-Type') != 'application/json' or not 0 < length <= 20000:
                raise ValueError('Expected bounded JSON body')
            body = json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(body, dict):
                raise ValueError('Expected JSON object')
            state = self.server.catalog.save(self.path.split('/')[3], body)
            self.json(200, {'workflow': state})
        except KeyError:
            self.json(404, {'error': 'Finding not found'})
        except (ValueError, TypeError, UnicodeError):
            self.json(400, {'error': 'Invalid workflow update; use an allowed status and notes up to 4000 characters'})
        except (OSError, RuntimePolicyError):
            self.json(409, {'error': 'Tracking storage is unavailable or unsafe'})


def create_server(root: Path, port=0):
    """Return an unstarted server bound exclusively to IPv4 loopback."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError('Port must be between 0 and 65535')
    catalog = Catalog(root)
    server = LocalServer(('127.0.0.1', port), Handler)
    server.catalog = catalog
    server.csrf_token = secrets.token_urlsafe(32)
    server.origin = f'http://127.0.0.1:{server.server_address[1]}'
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--open', action='store_true', help='Open the local dashboard in your browser')
    args = parser.parse_args()
    try:
        try:
            server = create_server(args.root, args.port)
        except OSError as error:
            if args.port == 0 or (error.errno != errno.EADDRINUSE and getattr(error, 'winerror', None) != 10048):
                raise
            server = create_server(args.root, 0)
            print(f'Port {args.port} is in use; selected an available local port.', flush=True)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Cannot start dashboard: {error}\n')
    print(f'Local findings dashboard: {server.origin}', flush=True)
    print('Press Ctrl+C to stop. Tracking stays on this computer.', flush=True)
    if args.open:
        webbrowser.open(server.origin)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
