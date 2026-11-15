import tempfile
import unittest
from pathlib import Path

from hackerone_mcp.store import Store


class StoreTests(unittest.TestCase):
    def test_accounts_are_isolated_and_search_is_parameterized(self):
        with tempfile.TemporaryDirectory() as directory:
            alice = Store(Path(directory), 'alice')
            bob = Store(Path(directory), 'bob')
            alice.cache('own_reports', {'data': [{'id': '1', 'attributes': {'title': 'Stored injection', 'team_handle': 'acme'}}], 'complete': False, 'source': 'api', 'fetched_at': '2026-11-15T00:00:00+00:00', 'pages': 1})
            result = alice.search('injection')
            self.assertEqual(result['matches'][0]['id'], '1')
            self.assertFalse(result['coverage'][0]['complete'])
            self.assertEqual(bob.search('injection')['matches'], [])
            self.assertEqual(alice.search("' OR 1=1 --")['matches'], [])
            self.assertNotIn('alice', alice.path.name)

    def test_prepare_deduplicates_and_sending_claim_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory), 'alice')
            first = store.prepare('a' * 64, {'payload': {'data': {}}, 'bundle': '/tmp/bundle', 'snapshot': {}})
            again = store.prepare('a' * 64, {'payload': {'data': {}}, 'bundle': '/tmp/another', 'snapshot': {}})
            self.assertEqual(first['prepared_hash'], again['prepared_hash'])
            self.assertTrue(store.claim('a' * 64))
            self.assertFalse(Store(Path(directory), 'alice').claim('a' * 64))
            self.assertEqual(store.prepared('a' * 64)['state'], 'sending')
