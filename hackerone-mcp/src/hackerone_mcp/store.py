"""Account-separated SQLite cache and transactional submission journal."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .client import HackerOneError, utcnow


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


class Store:
    def __init__(self, data_dir: Path, account: str):
        directory = Path(data_dir).expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / ("h1-" + hashlib.sha256(account.encode("utf-8")).hexdigest()[:32] + ".sqlite3")
        with self.connection() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS items (cache_key TEXT NOT NULL, id TEXT NOT NULL, program TEXT NOT NULL, document TEXT NOT NULL, UNIQUE(cache_key,id));
            CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(cache_key UNINDEXED, id UNINDEXED, program UNINDEXED, text);
            CREATE TABLE IF NOT EXISTS submissions (hash TEXT PRIMARY KEY, state TEXT NOT NULL, record TEXT NOT NULL, receipt TEXT, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS payload_claims (payload_hash TEXT PRIMARY KEY, prepared_hash TEXT NOT NULL);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db: yield db
        finally:
            db.close()

    def cache(self, key, document):
        with self.connection() as db:
            db.execute("INSERT OR REPLACE INTO cache VALUES (?,?)", (key, canonical(document)))
            db.execute("DELETE FROM items WHERE cache_key=?", (key,))
            db.execute("DELETE FROM search WHERE cache_key=?", (key,))
            items = document.get("data", [])
            if isinstance(items, dict): items = [items]
            for item in items:
                item_id = str(item.get("id", ""))
                attrs = item.get("attributes", {})
                relationships = item.get("relationships", {})
                relation = relationships.get("program", relationships.get("team", {})).get("data", {}) or {}
                program = attrs.get("team_handle", attrs.get("handle", relation.get("attributes", {}).get("handle", "")))
                encoded = canonical(item)
                db.execute("INSERT OR REPLACE INTO items VALUES (?,?,?,?)", (key, item_id, program, encoded))
                db.execute("INSERT INTO search VALUES (?,?,?,?)", (key, item_id, program, encoded))

    def coverage(self):
        with self.connection() as db:
            rows = db.execute("SELECT key, document FROM cache ORDER BY key").fetchall()
        return [{"key": row["key"], **{field: json.loads(row["document"]).get(field) for field in ("source", "fetched_at", "complete", "pages", "query")}} for row in rows]

    def search(self, query: str, *, program: str = "", kind: str = "", limit=20):
        if not isinstance(query, str) or not 1 <= len(query) <= 500:
            raise HackerOneError("Search requires 1-500 characters")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HackerOneError("Search limit must be 1-100")
        words = re.findall(r"[^\W_]+", query, re.UNICODE)
        expression = " AND ".join('"' + word.replace('"', '""') + '"' for word in words)
        if not expression:
            return {"matches": [], "coverage": self.coverage(), "source": "local SQLite FTS5 cache"}
        sql = "SELECT items.document,items.cache_key FROM search JOIN items ON search.cache_key=items.cache_key AND search.id=items.id WHERE search MATCH ?"
        params = [expression]
        if program: sql += " AND items.program=?"; params.append(program)
        if kind: sql += " AND items.cache_key LIKE ? ESCAPE '\\'"; params.append(kind.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        sql += " ORDER BY rank LIMIT ?"; params.append(limit)
        with self.connection() as db:
            rows = db.execute(sql, params).fetchall()
        return {"matches": [{**json.loads(row["document"]), "cache_key": row["cache_key"]} for row in rows], "coverage": self.coverage(), "source": "local SQLite FTS5 cache", "limits": "Own reports and disclosed items fetched into this account cache only; no global private duplicate search"}

    def prepare(self, prepared_hash, record):
        with self.connection() as db:
            db.execute("INSERT OR IGNORE INTO submissions VALUES (?, 'prepared', ?, NULL, ?)", (prepared_hash, canonical(record), utcnow()))
        return self.prepared(prepared_hash)

    def prepared(self, prepared_hash):
        with self.connection() as db:
            row = db.execute("SELECT * FROM submissions WHERE hash=?", (prepared_hash,)).fetchone()
        if row is None: raise HackerOneError("Unknown prepared submission hash")
        return {**json.loads(row["record"]), "prepared_hash": row["hash"], "state": row["state"], "updated_at": row["updated_at"], "receipt": json.loads(row["receipt"]) if row["receipt"] else None}

    def claim(self, prepared_hash):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT record,state FROM submissions WHERE hash=?", (prepared_hash,)).fetchone()
            if row is None or row["state"] != "prepared": return False
            payload_hash = digest(json.loads(row["record"])["payload"])
            claimed = db.execute("INSERT OR IGNORE INTO payload_claims VALUES (?,?)", (payload_hash, prepared_hash))
            if claimed.rowcount != 1: return False
            cursor = db.execute("UPDATE submissions SET state='sending', updated_at=? WHERE hash=? AND state='prepared'", (utcnow(), prepared_hash))
        return cursor.rowcount == 1

    def finish(self, prepared_hash, state, receipt):
        if state not in ("succeeded", "uncertain"): raise HackerOneError("Invalid submission state")
        with self.connection() as db:
            db.execute("UPDATE submissions SET state=?,receipt=?,updated_at=? WHERE hash=? AND state='sending'", (state, canonical(receipt), utcnow(), prepared_hash))
        return self.prepared(prepared_hash)
