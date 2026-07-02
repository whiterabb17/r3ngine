"""Tests for web/reNgine/osint/domain_security.py.

run_command returns a 2-tuple: (return_code: int, output: str)

Spoofy invocation:
    cmd = [_SPOOFY_PYTHON, 'spoofy.py', '-d', host, '-o', 'json']
    return_code, output = run_command(cmd, cwd=_SPOOFY_DIR)

Results are saved to OsintStaging with osint_type='domain_security'.
"""
import json
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, OsintStaging
from startScan.models import Domain as ScanDomain
from targetApp.models import Domain
from scanEngine.models import EngineType


class FakeSelf:
    """Minimal self-like object expected by run_spoofcheck."""
    pass


class TestRunSpoofcheck(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example-test.local')
        engine = EngineType.objects.create(
            engine_name='Test',
            yaml_configuration='osint: {}',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

    # ------------------------------------------------------------------
    # JSON output path (Spoofy -o json)
    # ------------------------------------------------------------------

    @patch('reNgine.osint.domain_security.run_command')
    def test_run_spoofcheck_saves_result_json(self, mock_run):
        """JSON output from Spoofy is parsed and saved to OsintStaging."""
        from reNgine.osint.domain_security import run_spoofcheck

        spoofy_output = json.dumps([{
            'DOMAIN': 'example-test.local',
            'SPF': 'v=spf1 ~all',
            'DMARC': None,
            'SPOOFING_POSSIBLE': True,
            'SPOOFING_TYPE': 'Spoofable: Missing DMARC',
        }])
        mock_run.return_value = (0, spoofy_output)

        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        staging = OsintStaging.objects.filter(
            scan_history=self.scan,
            osint_type='domain_security',
        ).first()
        self.assertIsNotNone(staging, "OsintStaging record should be created")
        self.assertIn('spoofcheck', staging.metadata)
        result = staging.metadata['spoofcheck']
        self.assertTrue(result['spoofable'])
        self.assertEqual(result['spf'], 'v=spf1 ~all')

    @patch('reNgine.osint.domain_security.run_command')
    def test_run_spoofcheck_not_spoofable(self, mock_run):
        """SPOOFING_POSSIBLE=False is stored correctly."""
        from reNgine.osint.domain_security import run_spoofcheck

        spoofy_output = json.dumps([{
            'DOMAIN': 'example-test.local',
            'SPF': 'v=spf1 -all',
            'DMARC': 'v=DMARC1;p=reject',
            'SPOOFING_POSSIBLE': False,
            'SPOOFING_TYPE': 'Spoofing is not possible',
        }])
        mock_run.return_value = (0, spoofy_output)

        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        staging = OsintStaging.objects.filter(
            scan_history=self.scan,
            osint_type='domain_security',
        ).first()
        self.assertIsNotNone(staging)
        result = staging.metadata['spoofcheck']
        self.assertFalse(result['spoofable'])
        self.assertEqual(result['dmarc'], 'v=DMARC1;p=reject')

    # ------------------------------------------------------------------
    # Plain text fallback
    # ------------------------------------------------------------------

    @patch('reNgine.osint.domain_security.run_command')
    def test_run_spoofcheck_plaintext_spoofable(self, mock_run):
        """Plain-text output containing spoofable marker is handled."""
        from reNgine.osint.domain_security import run_spoofcheck

        mock_run.return_value = (
            0,
            '[+] Spoofing possible for example-test.local\n'
            '[*] SPF record: v=spf1 ~all\n',
        )

        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        staging = OsintStaging.objects.filter(
            scan_history=self.scan,
            osint_type='domain_security',
        ).first()
        self.assertIsNotNone(staging)
        self.assertIn('spoofcheck', staging.metadata)

    @patch('reNgine.osint.domain_security.run_command')
    def test_run_spoofcheck_handles_empty_output(self, mock_run):
        """Empty output (non-zero exit) does not raise and creates no staging record."""
        from reNgine.osint.domain_security import run_spoofcheck

        mock_run.return_value = (1, '')

        # Should not raise
        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        count = OsintStaging.objects.filter(
            scan_history=self.scan,
            osint_type='domain_security',
        ).count()
        self.assertEqual(count, 0)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @patch('reNgine.osint.domain_security.run_command')
    def test_run_spoofcheck_handles_malformed_json(self, mock_run):
        """Malformed JSON falls back to text parsing and does not raise."""
        from reNgine.osint.domain_security import run_spoofcheck

        mock_run.return_value = (0, '{not valid json}}')

        # Should not raise
        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')

    @patch('reNgine.osint.domain_security.run_command')
    def test_run_spoofcheck_idempotent(self, mock_run):
        """Running twice for the same domain/scan updates the existing record (no duplicate)."""
        from reNgine.osint.domain_security import run_spoofcheck

        spoofy_output = json.dumps([{
            'DOMAIN': 'example-test.local',
            'SPF': 'v=spf1 ~all',
            'DMARC': None,
            'SPOOFING_POSSIBLE': True,
            'SPOOFING_TYPE': 'Spoofable',
        }])
        mock_run.return_value = (0, spoofy_output)

        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')
        run_spoofcheck(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        count = OsintStaging.objects.filter(
            scan_history=self.scan,
            osint_type='domain_security',
        ).count()
        self.assertEqual(count, 1, "Second run should update, not create a duplicate")
