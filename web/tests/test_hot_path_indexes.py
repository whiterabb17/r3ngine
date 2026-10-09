"""Tests for the hot-path indexes on ``ScanActivity`` and ``Vulnerability``.

Both tables are read on every task start and on every scan detail page render,
and both went 63 migrations without a single non-key index. These tests pin the
index set in place so a later model edit cannot silently drop one, and assert
that the hand-written ``0064_scan_hot_path_indexes`` migration actually matches
the models — the failure mode hand-written migrations invite.

That second check matters operationally: ``docker/web/entrypoint.sh`` runs
``makemigrations --noinput`` when ``DEBUG=1``, so any model/migration drift in
this app becomes an auto-generated migration on the next developer boot.

No fixtures are created — these are schema-level assertions.
"""
from django.core.management import call_command
from django.test import TestCase, override_settings

from startScan.models import CweId, ScanActivity, Vulnerability, VulnerabilityTags


def _index_map(model) -> dict:
    """Map ``{index name: tuple of fields}`` for a model's ``Meta.indexes``."""
    return {index.name: tuple(index.fields) for index in model._meta.indexes}


class TestScanActivityIndexes(TestCase):
    """The three ScanActivity access patterns that run during every scan."""

    def setUp(self):
        self.indexes = _index_map(ScanActivity)

    def test_row_claim_index(self):
        """reNgine/temporal/activities/__init__.py claims a row per task start."""
        self.assertEqual(self.indexes.get('sa_scan_name_idx'), ('scan_of', 'name'))

    def test_timeline_ordering_index(self):
        """api/scan_summary_views.py orders the timeline by tier then start time."""
        self.assertEqual(
            self.indexes.get('sa_scan_tier_started_idx'),
            ('scan_of', 'tier', 'time_started'),
        )

    def test_abort_reconcile_index(self):
        """Orphan reconciliation and zombie sweeps filter on scan_of + status."""
        self.assertEqual(
            self.indexes.get('sa_scan_status_started_idx'),
            ('scan_of', 'status', 'time_started'),
        )


class TestVulnerabilityIndexes(TestCase):
    """The three Vulnerability read paths behind the scan and target summaries."""

    def setUp(self):
        self.indexes = _index_map(Vulnerability)

    def test_scan_severity_index(self):
        """Severity is ordered descending — the queries all use order_by('-severity')."""
        self.assertEqual(self.indexes.get('vuln_scan_sev_idx'), ('scan_history', '-severity'))

    def test_target_severity_index(self):
        """Serves both the per-severity counts and the -severity/-discovered_date list."""
        self.assertEqual(
            self.indexes.get('vuln_target_sev_date_idx'),
            ('target_domain', '-severity', '-discovered_date'),
        )

    def test_subdomain_severity_index(self):
        """api/serializers/hosts.py buckets a per-subdomain queryset by severity."""
        self.assertEqual(
            self.indexes.get('vuln_subdomain_sev_idx'),
            ('subdomain', 'severity'),
        )

    def test_index_count_is_pinned(self):
        """Vulnerability is insert-heavy; every extra index costs write time.

        This is a deliberate speed bump, not a correctness rule: if a new index
        is genuinely justified, update the count and record the query it serves.
        """
        self.assertEqual(len(self.indexes), 3)


class TestVulnWritePathLookupIndexes(TestCase):
    """``get_or_create`` lookup columns in reNgine/common_func/vuln_helpers.py."""

    def test_vulnerability_tag_name_indexed(self):
        self.assertTrue(VulnerabilityTags._meta.get_field('name').db_index)

    def test_cwe_name_indexed(self):
        self.assertTrue(CweId._meta.get_field('name').db_index)


class TestMigrationStateMatchesModels(TestCase):
    """The hand-written migration must leave no drift against the models."""

    # settings_test_local disables migrations to speed up DB setup, which would
    # make every model look like a pending change; read the real ones here.
    @override_settings(MIGRATION_MODULES={})
    def test_no_pending_startscan_migrations(self):
        """``makemigrations --check`` exits non-zero when changes are missing.

        Scoped to ``startScan`` so unrelated drift in another app cannot fail
        this test.
        """
        try:
            call_command('makemigrations', 'startScan', '--check', '--dry-run', verbosity=0)
        except SystemExit as exc:  # raised with code 1 when changes are detected
            self.fail(
                'startScan models have changes with no matching migration. '
                'The hand-written 0064_scan_hot_path_indexes migration is out of '
                'sync with startScan/models.py (exit code %s).' % exc.code
            )
