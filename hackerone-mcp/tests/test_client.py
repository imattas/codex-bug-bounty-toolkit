import asyncio
import unittest

import httpx

from hackerone_mcp.client import HackerOneClient, HackerOneError


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_credential_free_startup_refuses_authenticated_read(self):
        client = HackerOneClient('', '')
        with self.assertRaisesRegex(HackerOneError, 'credentials'):
            await client.get('/hackers/programs')

    async def test_pagination_preserves_items_and_marks_truncation(self):
        def respond(request):
            self.assertEqual(request.url.host, 'api.hackerone.com')
            self.assertIn('authorization', request.headers)
            return httpx.Response(200, json={'data': [{'id': '1'}], 'links': {'next': '?page[number]=2'}})
        client = HackerOneClient('researcher', 'secret', transport=httpx.MockTransport(respond))
        result = await client.pages('/hackers/programs', max_pages=1)
        self.assertEqual(result['data'], [{'id': '1'}])
        self.assertFalse(result['complete'])
        self.assertEqual(result['pages'], 1)

    async def test_next_link_cannot_forward_credentials_outside_endpoint(self):
        for next_url in ('https://evil.test/v1/hackers/programs', 'http://api.hackerone.com/v1/hackers/programs', '/v1/hackers/me/reports', 'https://other@api.hackerone.com/v1/hackers/programs', '/v1/hackers/programs/../me/reports'):
            seen = []
            def respond(request):
                seen.append(str(request.url))
                return httpx.Response(200, json={'data': [], 'links': {'next': next_url}})
            client = HackerOneClient('u', 'token', transport=httpx.MockTransport(respond))
            with self.assertRaises(HackerOneError):
                await client.pages('/hackers/programs')
            self.assertEqual(len(seen), 1)

    async def test_get_retries_are_bounded_and_short_retry_after_is_honored(self):
        delays = []
        seen = []
        async def sleep(delay): delays.append(delay)
        def respond(request):
            seen.append(request)
            return httpx.Response(429, headers={'Retry-After': '1'}, json={'errors': ['secret']})
        client = HackerOneClient('u', 'secret', transport=httpx.MockTransport(respond), sleep=sleep)
        with self.assertRaises(HackerOneError) as caught:
            await client.get('/hackers/programs')
        self.assertEqual(len(seen), 3)
        self.assertEqual(delays, [1.0, 1.0])
        self.assertNotIn('secret', str(caught.exception))

    async def test_long_retry_after_defers_without_an_early_second_request(self):
        seen = []
        def respond(request):
            seen.append(request)
            return httpx.Response(429, headers={'Retry-After': '120'}, json={'data': []})
        client = HackerOneClient('u', 'token', transport=httpx.MockTransport(respond))
        with self.assertRaisesRegex(HackerOneError, 'retry later'):
            await client.get('/hackers/programs')
        self.assertEqual(len(seen), 1)

    async def test_post_never_retries_and_redirects_are_not_followed(self):
        seen = []
        def respond(request):
            seen.append(request)
            return httpx.Response(302, headers={'Location': 'https://evil.test/'})
        client = HackerOneClient('u', 'secret', transport=httpx.MockTransport(respond))
        with self.assertRaises(HackerOneError):
            await client.submit({'data': {}})
        self.assertEqual(len(seen), 1)

    async def test_post_429_is_not_retried_and_unlisted_paths_never_send(self):
        seen = []
        def respond(request):
            seen.append(str(request.url))
            return httpx.Response(429, headers={'Retry-After': '0'}, json={'data': []})
        client = HackerOneClient('u', 'token', transport=httpx.MockTransport(respond))
        with self.assertRaises(HackerOneError): await client.submit({'data': {}})
        self.assertEqual(len(seen), 1)
        for path in ('https://evil.test/', '/reports', '/hackers/programs/acme/../me/reports', '/hackers/programs/a%2fb'):
            with self.assertRaises(HackerOneError): await client.get(path)
        self.assertEqual(len(seen), 1)

    async def test_two_pages_follow_next_query_and_finish(self):
        def respond(request):
            if request.url.params.get('page[number]') == '2':
                return httpx.Response(200, json={'data': [{'id': '2'}], 'links': {'next': None}})
            return httpx.Response(200, json={'data': [{'id': '1'}], 'links': {'next': '/v1/hackers/programs?page[number]=2'}})
        client = HackerOneClient('u', 'token', transport=httpx.MockTransport(respond))
        result = await client.pages('/hackers/programs')
        self.assertEqual([row['id'] for row in result['data']], ['1', '2'])
        self.assertTrue(result['complete'])
        self.assertEqual(result['pages'], 2)

    async def test_invalid_json_response_does_not_expose_body(self):
        client = HackerOneClient('u', 'token', transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'token')))
        with self.assertRaises(HackerOneError) as caught: await client.get('/hackers/programs')
        self.assertNotIn('token', str(caught.exception))

    async def test_response_byte_limit_and_transport_errors_are_safe(self):
        for handler in (lambda r: httpx.Response(200, content=b'x' * 1025), lambda r: (_ for _ in ()).throw(httpx.ReadTimeout('secret token'))):
            client = HackerOneClient('u', 'secret', transport=httpx.MockTransport(handler), max_bytes=1024, sleep=lambda _: asyncio.sleep(0))
            with self.assertRaises(HackerOneError) as caught:
                await client.get('/hackers/programs')
            self.assertNotIn('secret', str(caught.exception))
