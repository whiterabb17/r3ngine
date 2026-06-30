from unittest.mock import MagicMock, patch
from django.test import TestCase
from reNgine.tasks.fuzzing import filter_fuzz_batch_with_redis

class TestFuzzNoiseReduction(TestCase):
    def setUp(self):
        self.mock_redis = MagicMock()
        self.mock_pipeline = MagicMock()
        self.mock_redis.pipeline.return_value = self.mock_pipeline

    def test_filter_fuzz_batch_with_redis_deduplicates(self):
        # Prepare simulated FFUF results (same format as real output)
        # We will create:
        # - 15 duplicate 403 hits (same status, length, words, lines)
        # - 5 duplicate 500 hits
        # - 3 unique 200 hits
        batch = []
        for i in range(15):
            batch.append({
                'url': f'http://example.com/admin{i}',
                'status': 403,
                'length': 4550,
                'words': 656,
                'lines': 90
            })
        for i in range(5):
            batch.append({
                'url': f'http://example.com/err{i}',
                'status': 500,
                'length': 961,
                'words': 137,
                'lines': 29
            })
        for i in range(3):
            batch.append({
                'url': f'http://example.com/ok{i}',
                'status': 200,
                'length': 1000 + i, # unique lengths
                'words': 50,
                'lines': 5
            })

        # Setup mock pipeline execute return values.
        # Since we have 15 + 5 + 3 = 23 items.
        # For each item, pipeline queues:
        # - INCR key
        # - EXPIRE key
        # We mock execute() to return:
        # [1, True, 2, True, ..., 15, True] (for 403s)
        # [1, True, 2, True, ..., 5, True] (for 500s)
        # [1, True, 1, True, 1, True] (for uniques)
        mock_pipeline_results = []
        for val in range(1, 16):
            mock_pipeline_results.extend([val, True])
        for val in range(1, 6):
            mock_pipeline_results.extend([val, True])
        for val in range(3):
            mock_pipeline_results.extend([1, True])

        self.mock_pipeline.execute.return_value = mock_pipeline_results

        # Call the filter function with max_repeat = 10
        with patch('reNgine.tasks.fuzzing.Redis.from_url', return_value=self.mock_redis):
            filtered = filter_fuzz_batch_with_redis(
                batch=batch,
                scan_history_id=1,
                subdomain_id=1,
                max_repeat=10,
                tool_name='ffuf'
            )

        # Assertions
        # Total items kept should be:
        # - 10 of the 403s (since max_repeat=10)
        # - 5 of the 500s (since total 5 < 10)
        # - 3 of the 200s (all unique)
        # Total: 10 + 5 + 3 = 18
        self.assertEqual(len(filtered), 18)

        kept_403s = [x for x in filtered if x['status'] == 403]
        kept_500s = [x for x in filtered if x['status'] == 500]
        kept_200s = [x for x in filtered if x['status'] == 200]

        self.assertEqual(len(kept_403s), 10)
        self.assertEqual(len(kept_500s), 5)
        self.assertEqual(len(kept_200s), 3)

    def test_filter_fuzz_batch_redis_connection_error_graceful_fallback(self):
        # If Redis raises an exception, the function should return the original batch
        batch = [{'url': 'http://example.com/1', 'status': 200}]
        
        with patch('reNgine.tasks.fuzzing.Redis.from_url', side_effect=Exception("Redis down")):
            filtered = filter_fuzz_batch_with_redis(
                batch=batch,
                scan_history_id=1,
                subdomain_id=1,
                max_repeat=10,
                tool_name='ffuf'
            )
            
        self.assertEqual(filtered, batch)
