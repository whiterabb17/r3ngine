"""Closing a batched step and its follow-up crawl."""
import tempfile
import uuid
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.temporal.activities import chunked
from reNgine.temporal.activities.chunked import _fuzz_follow_up, finalize_chunked_task_activity
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain


class FinalizeTests(TestCase):

    def setUp(self):
        domain = Domain.objects.create(name='fin.example.test', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='fin-engine', yaml_configuration='')
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=RUNNING_TASK, start_scan_date=timezone.now())
        self.row = ScanActivity.objects.create(
            scan_of=scan, task_uid=uuid.uuid4(), name='dir_file_fuzz', title='Directory & File Fuzz',
            tier=4, status=RUNNING_TASK, time=timezone.now(), time_started=timezone.now())
        self.results_dir = tempfile.mkdtemp()
        chunked._write_json(f'{self.results_dir}/batches/dir_file_fuzz/plan.json', {
            'version': chunked.PLAN_VERSION, 'scope': chunked._plan_scope({}), 'batches': [['a'], ['b']],
        })

    def _finalize(self, results):
        return finalize_chunked_task_activity(self.results_dir, 'dir_file_fuzz', self.row.id, results)

    def test_all_batches_done_closes_the_row(self):
        self.assertTrue(self._finalize([{'index': 0, 'status': 'done'}, {'index': 1, 'status': 'done'}]))
        self.row.refresh_from_db()
        self.assertEqual((self.row.status, self.row.error_message), (SUCCESS_TASK, None))

    def test_an_unfinished_batch_fails_the_row_with_the_batch_numbers(self):
        self.assertFalse(self._finalize([{'index': 0, 'status': 'done'}, {'index': 1, 'status': 'failed'}]))
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, FAILED_TASK)
        self.assertIn('1/2 batches did not finish (2)', self.row.error_message)

    def test_an_aborted_row_is_left_alone(self):
        ScanActivity.objects.filter(pk=self.row.pk).update(status=ABORTED_TASK)
        self._finalize([{'index': 0, 'status': 'done'}, {'index': 1, 'status': 'done'}])
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, ABORTED_TASK)


class FuzzFollowUpTests(TestCase):
    """The batches skip the fuzzer's trailing crawl; it runs once after them."""

    def _follow_up(self, section):
        ctx = {'yaml_configuration': {'dir_file_fuzz': section}, 'track': False, 'activity_id': 7}
        with patch('reNgine.temporal.activities.chunked._run_task') as run_task:
            _fuzz_follow_up(ctx, ['https://a.example.test/'])
        return run_task

    def test_the_targets_are_crawled_once(self):
        run_task = self._follow_up({})
        run_task.assert_called_once()
        self.assertEqual(run_task.call_args.kwargs['urls'], ['https://a.example.test/'])

    def test_no_crawl_when_the_engine_turns_it_off(self):
        self._follow_up({'enable_http_crawl': False}).assert_not_called()
