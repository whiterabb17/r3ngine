from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch
from datetime import timedelta
from startScan.models import (
    ScanHistory, EngineType, Vulnerability, VulnerabilityHistory, Subdomain, EmailBreach,
)
from targetApp.models import Domain
from dashboard.models import Project
from reNgine.tasks.report import build_target_report_context


def _project():
    return Project.objects.create(
        name='Test Project Task',
        slug='test-project-task',
        insert_date=timezone.now(),
    )


def _engine():
    return EngineType.objects.create(
        engine_name='test-engine-task',
        yaml_configuration='',
    )


def _domain(project):
    return Domain.objects.create(
        name='target.example.com',
        project=project,
        insert_date=timezone.now(),
    )


def _scan(domain, engine, days_ago=0):
    return ScanHistory.objects.create(
        domain=domain,
        scan_type=engine,
        scan_status=2,
        start_scan_date=timezone.now() - timedelta(days=days_ago),
    )


def _sub(scan, domain, name='api.target.example.com'):
    obj, _ = Subdomain.objects.get_or_create(
        name=name, scan_history=scan, target_domain=domain,
    )
    return obj


def _vuln(scan, domain, name='SQL Injection', severity=3, validation_status='new'):
    sub = _sub(scan, domain)
    return Vulnerability.objects.create(
        scan_history=scan, target_domain=domain, subdomain=sub,
        name=name, severity=severity, template_id='sqli-001',
        validation_status=validation_status, discovered_date=timezone.now(),
    )


def _vh(scan, vuln, group_key='gk1', is_remediated=False, remediation_date=None):
    return VulnerabilityHistory.objects.create(
        scan_history=scan, vulnerability=vuln, group_key=group_key,
        first_seen=timezone.now() - timedelta(days=10),
        last_seen=timezone.now(), is_remediated=is_remediated,
        remediation_date=remediation_date, total_occurrences=1,
        affected_subdomains_count=1,
    )


@patch('reNgine.tasks.report.generate_findings_timeline_chart', return_value='b64_tl')
@patch('reNgine.tasks.report.generate_severity_trend_chart', return_value='b64')
class BuildTargetReportContextTest(TestCase):
    def setUp(self):
        self.project = _project()
        self.engine = _engine()
        self.domain = _domain(self.project)
        self.scan1 = _scan(self.domain, self.engine, days_ago=14)
        self.scan2 = _scan(self.domain, self.engine, days_ago=0)

    def test_raises_on_single_scan(self, _sev, _tl):
        with self.assertRaises(ValueError):
            build_target_report_context(self.domain.id, [self.scan1.id], [])

    def test_always_present_keys_returned(self, _sev, _tl):
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        for key in ('domain', 'selected_scans', 'date_range', 'exec_summary',
                    'severity_trend', 'severity_trend_chart',
                    'findings_timeline', 'findings_timeline_chart',
                    'vuln_timeline', 'included_sections'):
            self.assertIn(key, ctx)

    def test_findings_timeline_structure(self, _sev, _tl):
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        self.assertEqual(len(ctx['findings_timeline']), 2)
        row = ctx['findings_timeline'][0]
        for key in ('scan', 'date', 'new_findings', 'resolved', 'open_total'):
            self.assertIn(key, row)
        self.assertIsInstance(row['new_findings'], int)
        self.assertIsInstance(row['open_total'], int)

    def test_vuln_timeline_open_in_both_scans(self, _sev, _tl):
        v1 = _vuln(self.scan1, self.domain)
        _vh(self.scan1, v1, group_key='gk1', is_remediated=False)
        v2 = _vuln(self.scan2, self.domain)
        _vh(self.scan2, v2, group_key='gk1', is_remediated=False)
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        statuses = [s['status'] for s in ctx['vuln_timeline'][0]['scan_statuses']]
        self.assertEqual(statuses, ['open', 'open'])

    def test_vuln_timeline_not_detected_when_absent_in_scan2(self, _sev, _tl):
        v1 = _vuln(self.scan1, self.domain)
        _vh(self.scan1, v1, group_key='gk2', is_remediated=False)
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        statuses = [s['status'] for s in ctx['vuln_timeline'][0]['scan_statuses']]
        self.assertEqual(statuses[0], 'open')
        self.assertEqual(statuses[1], 'not_detected')

    def test_vuln_timeline_manually_resolved(self, _sev, _tl):
        v1 = _vuln(self.scan1, self.domain, validation_status='new')
        _vh(self.scan1, v1, group_key='gk3')
        v2 = _vuln(self.scan2, self.domain, validation_status='resolved')
        _vh(self.scan2, v2, group_key='gk3')
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        entry = ctx['vuln_timeline'][0]
        self.assertEqual(entry['scan_statuses'][1]['status'], 'resolved')
        self.assertEqual(entry['remediation_type'], 'manual')

    def test_vuln_timeline_false_positive(self, _sev, _tl):
        v1 = _vuln(self.scan1, self.domain, validation_status='new')
        _vh(self.scan1, v1, group_key='gk4')
        v2 = _vuln(self.scan2, self.domain, validation_status='false_positive')
        _vh(self.scan2, v2, group_key='gk4')
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        self.assertEqual(ctx['vuln_timeline'][0]['scan_statuses'][1]['status'], 'false_positive')

    def test_vuln_timeline_ignore_info(self, _sev, _tl):
        v = _vuln(self.scan1, self.domain, severity=0)
        _vh(self.scan1, v, group_key='gk5')
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [], ignore_info=True)
        self.assertEqual(len(ctx['vuln_timeline']), 0)

    def test_subdomain_delta(self, _sev, _tl):
        for name in ['a.example.com', 'b.example.com', 'c.example.com']:
            Subdomain.objects.create(name=name, scan_history=self.scan1, target_domain=self.domain)
        for name in ['b.example.com', 'c.example.com', 'd.example.com']:
            Subdomain.objects.create(name=name, scan_history=self.scan2, target_domain=self.domain)
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], ['subdomain_changes'])
        delta = ctx['subdomain_delta'][0]
        self.assertEqual(delta['added'], ['d.example.com'])
        self.assertEqual(delta['removed'], ['a.example.com'])

    def test_optional_section_absent_returns_none(self, _sev, _tl):
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        self.assertIsNone(ctx['subdomain_delta'])
        self.assertIsNone(ctx['attack_surface_trend'])
        self.assertIsNone(ctx['email_breaches'])

    def test_severity_trend_counts(self, _sev, _tl):
        v = _vuln(self.scan1, self.domain, severity=3)
        _vh(self.scan1, v, group_key='gk6', is_remediated=False)
        ctx = build_target_report_context(self.domain.id, [self.scan1.id, self.scan2.id], [])
        scan1_row = next(r for r in ctx['severity_trend'] if r['scan_id'] == self.scan1.id)
        self.assertEqual(scan1_row['high'], 1)
        self.assertEqual(scan1_row['critical'], 0)
