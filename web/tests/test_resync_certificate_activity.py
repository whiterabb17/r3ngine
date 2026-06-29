"""Unit tests for resync_single_certificate in certificate_tasks.py."""
from unittest.mock import patch, MagicMock
import subprocess
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, CertificateIntelligence
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType


def _make_scan_and_cert():
    project = Project.objects.create(name='p-resync', slug='p-resync', insert_date=timezone.now())
    domain = Domain.objects.create(name='resync.test', project=project)
    engine = EngineType.objects.create(engine_name='eng-resync', yaml_configuration='')
    scan = ScanHistory.objects.create(
        domain=domain,
        scan_type=engine,
        scan_status=2,
        start_scan_date='2026-06-21T00:00:00Z',
    )
    cert = CertificateIntelligence.objects.create(
        scan_history=scan,
        target_domain=domain,
        host='api.resync.test',
        port=443,
        subject_cn='api.resync.test',
        subject_an=['api.resync.test'],
        issuer_cn='Old CA',
        issuer_org='Old CA Inc',
        not_before=timezone.now(),
        not_after=timezone.now(),
        tls_version='TLSv1.2',
        cipher='TLS_RSA_WITH_RC4_128_SHA',
        fingerprint_sha256='old:fp',
        self_signed=False,
        mismatched=False,
        is_expired=False,
        has_weak_cipher=True,
        trust_chain=[],
        raw_json={},
    )
    return cert


TLSX_SAMPLE_LINE = (
    '{"host":"api.resync.test","port":443,"tls_version":"TLSv1.3",'
    '"cipher":"TLS_AES_256_GCM_SHA384","subject_cn":"api.resync.test",'
    '"subject_an":["api.resync.test"],"issuer_cn":"New CA",'
    '"issuer_org":["New CA Inc"],"not_before":"2026-01-01T00:00:00Z",'
    '"not_after":"2027-01-01T00:00:00Z",'
    '"fingerprint_hash":{"sha256":"new:fp:aa:bb"},'
    '"self_signed":false,"mismatched":false}'
)


class ResyncSingleCertificateTests(TestCase):

    def setUp(self):
        self.cert = _make_scan_and_cert()

    @patch('reNgine.tasks.certificate.subprocess.run')
    def test_resync_updates_record(self, mock_run):
        mock_run.return_value = MagicMock(stdout=TLSX_SAMPLE_LINE + '\n', returncode=0)
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(self.cert.id)
        self.assertIsNotNone(result)
        self.cert.refresh_from_db()
        self.assertEqual(self.cert.tls_version, 'TLSv1.3')
        self.assertEqual(self.cert.cipher, 'TLS_AES_256_GCM_SHA384')
        self.assertEqual(self.cert.issuer_cn, 'New CA')
        self.assertFalse(self.cert.has_weak_cipher)

    @patch('reNgine.tasks.certificate.subprocess.run')
    def test_resync_returns_none_on_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(self.cert.id)
        self.assertIsNone(result)

    @patch('reNgine.tasks.certificate.subprocess.run')
    def test_resync_returns_none_on_host_mismatch(self, mock_run):
        # tlsx returns data for a different host — should be skipped
        other_host_line = TLSX_SAMPLE_LINE.replace('api.resync.test', 'other.host.test')
        mock_run.return_value = MagicMock(stdout=other_host_line + '\n', returncode=0)
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(self.cert.id)
        self.assertIsNone(result)

    @patch('reNgine.tasks.certificate.subprocess.run', side_effect=FileNotFoundError)
    def test_resync_returns_none_when_tlsx_missing(self, mock_run):
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(self.cert.id)
        self.assertIsNone(result)

    def test_resync_returns_none_for_missing_cert(self):
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(cert_id=999999)
        self.assertIsNone(result)

    @patch('reNgine.tasks.certificate.subprocess.run',
           side_effect=subprocess.TimeoutExpired(cmd='tlsx', timeout=60))
    def test_resync_returns_none_on_timeout(self, mock_run):
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(self.cert.id)
        self.assertIsNone(result)

    @patch('reNgine.tasks.certificate.subprocess.run')
    def test_resync_rejects_host_with_unsafe_chars(self, mock_run):
        # The cert's host field contains shell metacharacters — must be rejected.
        self.cert.host = 'host; rm -rf /'
        self.cert.save(update_fields=['host'])
        from reNgine.tasks.certificate import resync_single_certificate
        result = resync_single_certificate(self.cert.id)
        self.assertIsNone(result)
        mock_run.assert_not_called()
