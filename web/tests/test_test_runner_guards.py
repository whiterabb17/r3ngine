"""Guards installed by reNgine.test_runner.RengineTestRunner."""
import builtins
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import tldextract
import tldextract.tldextract

from reNgine import test_runner


@unittest.skipUnless(
    builtins.open is test_runner._open_rejecting_mocks,
    'only meaningful under RengineTestRunner',
)
class MockPathGuardTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='rengine_guard_')
        self.addCleanup(tmp.cleanup)
        self.base = tmp.name
        self.task = MagicMock()
        mark = len(test_runner._mock_path_violations)
        # The guard also records violations so a swallowed TypeError still
        # fails the test; these ones are provoked on purpose.
        self.addCleanup(lambda: test_runner._mock_path_violations.__delitem__(slice(mark, None)))

    def test_makedirs_rejects_stringified_mock(self):
        with self.assertRaisesRegex(TypeError, 'path built from a mock'):
            os.makedirs(f'{self.task.results_dir}/secrets_temp', exist_ok=True)

    def test_mkdir_rejects_mock_object(self):
        with self.assertRaisesRegex(TypeError, 'path built from a mock'):
            os.mkdir(self.task.results_dir)

    def test_path_mkdir_rejects_stringified_mock(self):
        with self.assertRaisesRegex(TypeError, 'path built from a mock'):
            Path(self.base, str(self.task.results_dir)).mkdir(parents=True)

    def test_open_for_writing_rejects_stringified_mock(self):
        with self.assertRaisesRegex(TypeError, 'path built from a mock'):
            open(os.path.join(self.base, f'{self.task.output_path}.json'), 'w')

    def test_path_write_text_rejects_stringified_mock(self):
        with self.assertRaisesRegex(TypeError, 'path built from a mock'):
            Path(self.base, f'{self.task.output_path}.txt').write_text('x')

    def test_real_paths_still_work(self):
        target = Path(self.base, 'a', 'b')
        os.makedirs(target)
        Path(target, 'c').mkdir()
        with open(target / 'out.txt', 'w') as fh:
            fh.write('ok')
        self.assertEqual((target / 'out.txt').read_text(), 'ok')

    def test_reading_a_missing_mock_path_is_left_alone(self):
        with self.assertRaises(FileNotFoundError):
            open(os.path.join(self.base, str(self.task.results_dir)))


@unittest.skipUnless(
    builtins.open is test_runner._open_rejecting_mocks,
    'only meaningful under RengineTestRunner',
)
class SwallowedViolationTest(unittest.TestCase):
    def test_swallowed_violation_still_fails_the_test(self):
        class _SwallowsTypeError(unittest.TestCase):
            def runTest(self):
                try:
                    os.makedirs(f'{MagicMock().results_dir}/x', exist_ok=True)
                except Exception:
                    pass  # what a broad production except block would do

        result_class = type(
            'Result', (test_runner._MockPathGuardResultMixin, unittest.TestResult), {}
        )
        result = result_class()
        mark = len(test_runner._mock_path_violations)
        try:
            _SwallowsTypeError().run(result)
        finally:
            del test_runner._mock_path_violations[mark:]

        self.assertEqual(len(result.errors), 1)
        self.assertIn('path built from a mock', result.errors[0][1])


@unittest.skipUnless(
    builtins.open is test_runner._open_rejecting_mocks,
    'only meaningful under RengineTestRunner',
)
class TldextractOfflineTest(unittest.TestCase):
    def test_extractor_uses_bundled_snapshot_without_fetching(self):
        extractor = tldextract.tldextract.TLD_EXTRACTOR
        self.assertEqual(extractor.suffix_list_urls, ())
        with patch('requests.Session.get', side_effect=AssertionError('network fetch')):
            result = tldextract.extract('api.shop.example.co.uk')
        self.assertEqual(result.domain, 'example')
        self.assertEqual(result.suffix, 'co.uk')
        self.assertEqual(result.subdomain, 'api.shop')
