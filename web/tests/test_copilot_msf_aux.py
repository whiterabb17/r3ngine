"""Gated MSF aux approve/execute with mocked MSFRPC."""
from __future__ import annotations

from django.test import TestCase, tag
from unittest.mock import MagicMock, patch

from copilot.models import MsfAuxAttempt
from copilot.msf_aux import approve_and_start, execute_attempt, propose_attempt


@tag('unit')
class MsfAuxServiceTests(TestCase):
    @patch('copilot.msf_aux.assert_rhosts_in_scope')
    def test_propose_attempt(self, scope_mock):
        scope_mock.return_value = None
        attempt = propose_attempt(
            project_slug='demo',
            module='auxiliary/scanner/http/title',
            options={'RHOSTS': 'target.example'},
        )
        self.assertEqual(attempt.status, MsfAuxAttempt.STATUS_PROPOSED)
        self.assertEqual(attempt.module, 'auxiliary/scanner/http/title')

    @patch('copilot.msf_aux._start_msf_aux_workflow', return_value='msf-aux-1')
    @patch('copilot.msf_aux.assert_rhosts_in_scope')
    def test_approve_starts_workflow(self, scope_mock, start_wf):
        scope_mock.return_value = None
        attempt = propose_attempt(
            project_slug='demo',
            module='auxiliary/scanner/http/title',
            options={'RHOSTS': 'target.example'},
        )
        started = approve_and_start(attempt)
        self.assertEqual(started.status, MsfAuxAttempt.STATUS_RUNNING)
        self.assertEqual(started.temporal_workflow_id, 'msf-aux-1')
        start_wf.assert_called_once()

    @patch('copilot.msf_aux.MsfrpcClient')
    @patch('copilot.msf_aux.assert_rhosts_in_scope')
    def test_execute_success(self, scope_mock, client_cls):
        scope_mock.return_value = None
        attempt = propose_attempt(
            project_slug='demo',
            module='auxiliary/scanner/http/title',
            options={'RHOSTS': 'target.example'},
        )
        attempt.status = MsfAuxAttempt.STATUS_RUNNING
        attempt.save(update_fields=['status'])

        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = None
        client.console_create_and_run.return_value = '[*] title: Example'
        client_cls.return_value = client

        result = execute_attempt(attempt.id)
        self.assertEqual(result['status'], MsfAuxAttempt.STATUS_SUCCEEDED)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, MsfAuxAttempt.STATUS_SUCCEEDED)
        self.assertIn('title', (attempt.result or {}).get('output', ''))
        client.console_create_and_run.assert_called_once()
        client.module_execute.assert_not_called()

    @patch('copilot.msf_aux.MsfrpcClient')
    @patch('copilot.msf_aux.assert_rhosts_in_scope')
    def test_execute_skips_retry_after_claim(self, scope_mock, client_cls):
        scope_mock.return_value = None
        attempt = propose_attempt(
            project_slug='demo',
            module='auxiliary/scanner/http/title',
            options={'RHOSTS': 'target.example'},
        )
        attempt.status = MsfAuxAttempt.STATUS_RUNNING
        attempt.result = {'execution_claimed': True, 'claimed_at': '2026-01-01T00:00:00Z'}
        attempt.save(update_fields=['status', 'result'])

        result = execute_attempt(attempt.id)
        self.assertEqual(result['status'], 'failed')
        client_cls.assert_not_called()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, MsfAuxAttempt.STATUS_FAILED)
