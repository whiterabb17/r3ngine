# web/tests/test_employee_intelligence.py
import json
import os
from unittest.mock import MagicMock, patch

from django.test import TestCase


class TestRunTheharvesterEmployees(TestCase):
    @patch('reNgine.tasks.employee_intelligence.subprocess.run')
    @patch('reNgine.tasks.employee_intelligence.save_employee')
    @patch('reNgine.tasks.employee_intelligence.ScanHistory')
    def test_returns_count_of_new_employees(self, mock_sh, mock_save, mock_subproc):
        from reNgine.tasks.employee_intelligence import _run_theharvester_employees

        mock_sh.objects.get.return_value = MagicMock()
        mock_save.return_value = (MagicMock(), True)

        def fake_run(cmd, **kwargs):
            # theHarvester appends .json to the base name passed via -f
            output_base = cmd[cmd.index('-f') + 1]
            output_json = f'{output_base}.json'
            os.makedirs(os.path.dirname(output_json), exist_ok=True)
            with open(output_json, 'w') as f:
                json.dump({'linkedin_people': ['Alice Smith', 'Bob Jones'], 'twitter_people': []}, f)
            return MagicMock(returncode=0)

        mock_subproc.side_effect = fake_run
        count = _run_theharvester_employees(1, 'example.com')
        self.assertEqual(count, 2)

    @patch('reNgine.tasks.employee_intelligence.subprocess.run')
    @patch('reNgine.tasks.employee_intelligence.ScanHistory')
    def test_returns_zero_when_no_output_file(self, mock_sh, mock_subproc):
        from reNgine.tasks.employee_intelligence import _run_theharvester_employees

        mock_sh.objects.get.return_value = MagicMock()
        mock_subproc.return_value = MagicMock(returncode=1)
        count = _run_theharvester_employees(1, 'example.com')
        self.assertEqual(count, 0)


class TestRunLinkedintEmployees(TestCase):
    @patch('reNgine.tasks.osint.run_linkedint', return_value=None)
    @patch('reNgine.tasks.employee_intelligence.ScanHistory')
    def test_returns_delta_employee_count(self, mock_sh, _run_li):
        from reNgine.tasks.employee_intelligence import _run_linkedint_employees

        mock_scan = MagicMock()
        mock_scan.employees.count.side_effect = [3, 5]  # before=3, after=5
        mock_sh.objects.get.return_value = mock_scan

        result = _run_linkedint_employees(1, 'example.com')
        self.assertEqual(result, 2)

    @patch('reNgine.tasks.osint.run_linkedint', return_value=None)
    @patch('reNgine.tasks.employee_intelligence.ScanHistory')
    def test_returns_zero_when_count_unchanged(self, mock_sh, _run_li):
        from reNgine.tasks.employee_intelligence import _run_linkedint_employees

        mock_scan = MagicMock()
        mock_scan.employees.count.side_effect = [5, 5]
        mock_sh.objects.get.return_value = mock_scan

        result = _run_linkedint_employees(1, 'example.com')
        self.assertEqual(result, 0)


class TestRunEmployeeIntelligence(TestCase):
    @patch('reNgine.tasks.employee_intelligence._clear_active')
    @patch('reNgine.tasks.employee_intelligence._check_stop_signal', return_value=False)
    @patch('reNgine.tasks.employee_intelligence._push_to_stream')
    @patch('reNgine.tasks.employee_intelligence._run_theharvester_employees', return_value=2)
    @patch('reNgine.tasks.employee_intelligence._run_linkedint_employees', return_value=1)
    @patch('reNgine.tasks.employee_intelligence._run_hunter_employees', return_value=3)
    def test_pushes_complete_event_with_total(
        self, mock_hunter, mock_linkedint, mock_theharvester, mock_push, _stop, _clear
    ):
        from reNgine.tasks.employee_intelligence import run_employee_intelligence

        run_employee_intelligence(42, 'example.com', 'test-job-id')

        complete_calls = [
            c for c in mock_push.call_args_list
            if c[0][1].get('type') == 'employee_intel_complete'
        ]
        self.assertEqual(len(complete_calls), 1)
        self.assertEqual(complete_calls[0][0][1]['total_found'], 6)

    @patch('reNgine.tasks.employee_intelligence._clear_active')
    @patch('reNgine.tasks.employee_intelligence._check_stop_signal', return_value=True)
    @patch('reNgine.tasks.employee_intelligence._push_to_stream')
    def test_stops_early_on_stop_signal(self, mock_push, _stop, _clear):
        from reNgine.tasks.employee_intelligence import run_employee_intelligence

        run_employee_intelligence(42, 'example.com', 'test-job-id')

        cancelled_calls = [
            c for c in mock_push.call_args_list
            if c[0][1].get('status') == 'cancelled'
        ]
        self.assertGreater(len(cancelled_calls), 0)

    @patch('reNgine.tasks.employee_intelligence._clear_active')
    @patch('reNgine.tasks.employee_intelligence._check_stop_signal', return_value=False)
    @patch('reNgine.tasks.employee_intelligence._push_to_stream')
    @patch('reNgine.tasks.employee_intelligence._run_theharvester_employees',
           side_effect=RuntimeError('subprocess failed'))
    @patch('reNgine.tasks.employee_intelligence._run_linkedint_employees', return_value=0)
    @patch('reNgine.tasks.employee_intelligence._run_hunter_employees', return_value=0)
    def test_continues_after_tool_error(
        self, mock_hunter, mock_linkedint, _theharvester, _push, _stop, _clear
    ):
        from reNgine.tasks.employee_intelligence import run_employee_intelligence

        run_employee_intelligence(42, 'example.com', 'test-job-id')

        self.assertTrue(mock_linkedint.called)
        self.assertTrue(mock_hunter.called)
