"""
Tests for ScanHistorySerializer.get_tier_info — specifically the active_tier
calculation that was fixed to use max() instead of min() to avoid showing a
lower tier when a higher tier is actively running.
"""
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from reNgine.definitions import INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK, FAILED_TASK
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain


def _make_scan(scan_status=RUNNING_TASK):
    project = Project.objects.create(
        name='tier-test', slug='tier-test', insert_date=timezone.now()
    )
    engine = EngineType.objects.create(engine_name='tier-engine', yaml_configuration='')
    domain = Domain.objects.create(
        name='tier.example', project=project, insert_date=timezone.now()
    )
    return ScanHistory.objects.create(
        domain=domain,
        scan_type=engine,
        scan_status=scan_status,
        start_scan_date=timezone.now(),
    )


def _act(scan, name, tier, status):
    return ScanActivity.objects.create(
        scan_of=scan,
        name=name,
        title=name.replace('_', ' ').title(),
        tier=tier,
        status=status,
        time=timezone.now(),
    )


class TestScanHistorySerializerTierInfo(TestCase):
    """get_tier_info must show the HIGHEST active tier, not the lowest."""

    def _tier_info(self, scan):
        from api.serializers import ScanHistorySerializer
        s = ScanHistorySerializer()
        return s.get_tier_info(scan)

    def test_no_activities_returns_zeros(self):
        scan = _make_scan()
        info = self._tier_info(scan)
        self.assertEqual(info, {'current_tier': 0, 'total_tiers': 0, 'current_tier_progress': 0})

    def test_normal_progression_tier1_complete_tier6_running(self):
        """When tier 1 is fully done and tier 6 is running, current_tier must be 6."""
        scan = _make_scan()
        _act(scan, 'subdomain_discovery', 1, SUCCESS_TASK)
        _act(scan, 'vulnerability_scan',  6, RUNNING_TASK)
        _act(scan, 'correlate_vulnerabilities', 7, INITIATED_TASK)

        info = self._tier_info(scan)
        self.assertEqual(info['current_tier'], 6)
        self.assertEqual(info['total_tiers'], 7)

    def test_stuck_initiated_lower_tier_does_not_mask_active_higher_tier(self):
        """
        Regression: tier 1 has one SUCCESS and one INITIATED (never started).
        Tier 6 is RUNNING.  current_tier must be 6, not 1.
        """
        scan = _make_scan()
        _act(scan, 'subdomain_discovery',  1, SUCCESS_TASK)
        _act(scan, 'vigolium_harvest',     1, INITIATED_TASK)  # planned but not yet executed
        _act(scan, 'vulnerability_scan',   6, RUNNING_TASK)
        _act(scan, 'correlate_vulnerabilities', 7, INITIATED_TASK)

        info = self._tier_info(scan)
        self.assertEqual(info['current_tier'], 6, 'Stuck INITIATED on tier 1 must not override running tier 6')
        self.assertEqual(info['total_tiers'], 7)

    def test_all_tiers_complete_reports_highest_tier(self):
        """When every activity is SUCCESS/FAILED, active_tier should equal total_tiers."""
        scan = _make_scan(scan_status=SUCCESS_TASK)
        _act(scan, 'subdomain_discovery',      1, SUCCESS_TASK)
        _act(scan, 'http_crawl',               2, SUCCESS_TASK)
        _act(scan, 'vulnerability_scan',        6, SUCCESS_TASK)
        _act(scan, 'correlate_vulnerabilities', 7, SUCCESS_TASK)

        info = self._tier_info(scan)
        self.assertEqual(info['total_tiers'], 7)
        # All tiers are complete; active_tier falls to max(completed) + 1 clamped to total
        self.assertEqual(info['current_tier'], 7)

    def test_tier_task_progress_reflects_active_tier(self):
        """current_tier_progress is computed for the active tier's tasks."""
        scan = _make_scan()
        _act(scan, 'subdomain_discovery', 1, SUCCESS_TASK)
        # Tier 6: 1 of 2 done
        _act(scan, 'vulnerability_scan', 6, SUCCESS_TASK)
        _act(scan, 'nuclei_scan',        6, RUNNING_TASK)
        _act(scan, 'correlate_vulnerabilities', 7, INITIATED_TASK)

        info = self._tier_info(scan)
        self.assertEqual(info['current_tier'], 6)
        self.assertEqual(info['current_tier_progress'], 50.0)

    def test_only_tier_zero_activities_returns_zeros(self):
        """Tier 0 (target_profiling) is excluded; should return 0/0/0 with no other tiers."""
        scan = _make_scan()
        _act(scan, 'target_profiling', 0, SUCCESS_TASK)

        info = self._tier_info(scan)
        self.assertEqual(info, {'current_tier': 0, 'total_tiers': 0, 'current_tier_progress': 0})
