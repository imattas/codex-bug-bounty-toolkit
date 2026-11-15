"""Bounded authenticated transport; only the documented researcher API surface."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import re
from urllib.parse import unquote, urljoin, urlsplit

import httpx


BASE = "https://api.hackerone.com/v1"
_PATH = re.compile(r"/hackers/(?:programs(?:/[A-Za-z0-9_-]{1,100}(?:/(?:structured_scopes|scope_exclusions|weaknesses))?)?|me/reports|reports/[0-9]{1,20}|hacktivity)\Z")


class HackerOneError(ValueError):
    """A safe error message that never includes response bodies or credentials."""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def handle_path(handle: str) -> str:
    if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", handle):
        raise HackerOneError("Invalid program handle")
    return "/hackers/programs/" + handle


class HackerOneClient:
    def __init__(self, username: str, token: str, *, transport=None, sleep=asyncio.sleep, max_bytes=2_000_000):
        self._username, self._token = username, token
        self._transport, self._sleep = transport, sleep
        self.max_bytes = min(max(1024, int(max_bytes)), 2_000_000)

    @property
    def configured(self):
        return bool(self._username and self._token)

    def _initial_url(self, path):
        if not isinstance(path, str) or not _PATH.fullmatch(path):
            raise HackerOneError("Unsupported researcher endpoint")
        return BASE + path

    def _next_url(self, value, current, original):
        if not isinstance(value, str) or len(value) > 4096 or "\\" in value:
            raise HackerOneError("Unsafe pagination link")
        candidate = urljoin(current, value)
        parsed, wanted = urlsplit(candidate), urlsplit(original)
        raw_path = unquote(urlsplit(value).path)
        if (parsed.scheme != "https" or parsed.netloc != "api.hackerone.com" or parsed.username or parsed.password or parsed.fragment or parsed.path != wanted.path or any(part in (".", "..") for part in raw_path.split("/"))):
            raise HackerOneError("Unsafe pagination link")
        return candidate

    @staticmethod
    def _delay(value, attempt):
        try:
            seconds = float(value)
        except (TypeError, ValueError):
            try:
                seconds = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                seconds = 0.25 * (attempt + 1)
        if seconds != seconds: seconds = 0.25
        if seconds > 2:
            raise HackerOneError("HackerOne requested a longer Retry-After; retry later after the server's requested delay")
        return min(2.0, max(0.0, seconds))

    async def _request(self, method, url, *, params=None, payload=None):
        if not self.configured:
            raise HackerOneError("HackerOne credentials are not configured: set H1_USERNAME and H1_API_TOKEN in the server environment")
        attempts = 3 if method == "GET" else 1
        async with httpx.AsyncClient(transport=self._transport, timeout=httpx.Timeout(20.0, connect=5.0), follow_redirects=False, trust_env=False) as http:
            for attempt in range(attempts):
                try:
                    async with http.stream(method, url, params=params, json=payload, auth=(self._username, self._token), headers={"Accept": "application/json", "User-Agent": "hackerone-research-mcp/0.1"}) as response:
                        status = response.status_code
                        retry_after = response.headers.get("Retry-After")
                        if method == "GET" and status in (429, 502, 503, 504) and attempt + 1 < attempts:
                            retry = True
                        else:
                            retry = False
                            if status < 200 or status >= 300:
                                raise HackerOneError("HackerOne API returned HTTP " + str(status))
                            chunks, size = [], 0
                            async for chunk in response.aiter_bytes():
                                size += len(chunk)
                                if size > self.max_bytes:
                                    raise HackerOneError("HackerOne response exceeded the byte limit")
                                chunks.append(chunk)
                            try:
                                body = json.loads(b"".join(chunks))
                            except (ValueError, UnicodeError):
                                raise HackerOneError("HackerOne API returned invalid JSON") from None
                            if not isinstance(body, dict) or "data" not in body:
                                raise HackerOneError("HackerOne API returned an unexpected document")
                            return body
                    if retry:
                        await self._sleep(self._delay(retry_after, attempt))
                except httpx.RequestError:
                    if method == "GET" and attempt + 1 < attempts:
                        await self._sleep(0.25 * (attempt + 1))
                        continue
                    raise HackerOneError("HackerOne transport failed; write outcome may be unknown") from None

    async def get(self, path: str, params=None):
        url = self._initial_url(path)
        try:
            async with asyncio.timeout(60):
                body = await self._request("GET", url, params=params)
        except TimeoutError:
            raise HackerOneError("HackerOne read time budget exhausted") from None
        return {**body, "source": url, "fetched_at": utcnow(), "complete": True, "pages": 1}

    async def pages(self, path: str, params=None, *, max_pages=10):
        if type(max_pages) is not int or not 1 <= max_pages <= 50:
            raise HackerOneError("max_pages must be between 1 and 50")
        original = self._initial_url(path)
        url, data, seen = original, [], set()
        query = {"page[size]": 100, **(params or {})}
        try:
            async with asyncio.timeout(60):
                for page in range(1, max_pages + 1):
                    if url in seen: raise HackerOneError("Pagination cycle detected")
                    seen.add(url)
                    body = await self._request("GET", url, params=query)
                    if not isinstance(body["data"], list) or len(body["data"]) > 100:
                        raise HackerOneError("Unexpected page data or page size")
                    if not all(isinstance(item, dict) for item in body["data"]):
                        raise HackerOneError("Unexpected page item")
                    data.extend(body["data"])
                    links = body.get("links", {})
                    if not isinstance(links, dict): raise HackerOneError("Unexpected pagination links")
                    following = links.get("next")
                    if isinstance(following, dict): following = following.get("href")
                    if not following: break
                    url = self._next_url(following, url, original)
                    query = None
        except TimeoutError:
            raise HackerOneError("HackerOne pagination time budget exhausted") from None
        return {"data": data, "source": original, "query": params or {}, "fetched_at": utcnow(), "complete": not bool(following), "pages": page, "limit": max_pages}

    async def submit(self, payload):
        try:
            async with asyncio.timeout(30):
                return await self._request("POST", BASE + "/hackers/reports", payload=payload)
        except TimeoutError:
            raise HackerOneError("HackerOne write time budget exhausted; outcome unknown") from None
