"""Hot-path indexes for startScan_scanactivity and startScan_vulnerability.

Neither table carried a single index beyond its primary key and foreign keys,
despite being the two most frequently read tables in the product: every task
start claims a ScanActivity row, and every scan detail page aggregates
Vulnerability by severity.

Trade-off: startScan_vulnerability is insert-heavy while a scan runs — a nuclei
pass can add thousands of rows in a burst — and each index here is another
B-tree that every INSERT must maintain. Three indexes are a deliberate cost on
write throughput bought back on the read paths listed against each index below.
Do not add further indexes to this table without measuring the write side.

startScan_scanactivity is comparatively low-volume (tens to hundreds of rows per
scan), so its three indexes are close to free.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0063_scanactivity_target_host'),
    ]

    operations = [
        # --- ScanActivity ---
        # reNgine/temporal/activities/__init__.py:246 — select_for_update row
        # claim filtered on (scan_of, name); runs once per task start.
        migrations.AddIndex(
            model_name='scanactivity',
            index=models.Index(fields=['scan_of', 'name'], name='sa_scan_name_idx'),
        ),
        # api/scan_summary_views.py:182 — timeline ordered by
        # ('tier', 'time_started', 'time') within a scan.
        migrations.AddIndex(
            model_name='scanactivity',
            index=models.Index(
                fields=['scan_of', 'tier', 'time_started'],
                name='sa_scan_tier_started_idx',
            ),
        ),
        # reNgine/temporal/activities/__init__.py:2222/2268/2288 — failure
        # rollup, orphan reconciliation and zombie sweep, all filtered on
        # (scan_of, status) with a time_started NULL test.
        migrations.AddIndex(
            model_name='scanactivity',
            index=models.Index(
                fields=['scan_of', 'status', 'time_started'],
                name='sa_scan_status_started_idx',
            ),
        ),

        # --- Vulnerability ---
        # api/serializers.py:548 and api/target_summary_serializers.py:25 —
        # .filter(scan_history=...).order_by('-severity').first()
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['scan_history', '-severity'], name='vuln_scan_sev_idx'),
        ),
        # api/scan_summary_views.py:87-92 — six severity counts over a
        # target_domain queryset; api/scan_summary_views.py:278 and
        # api/target_summary_views.py:186 — order_by('-severity', '-discovered_date').
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(
                fields=['target_domain', '-severity', '-discovered_date'],
                name='vuln_target_sev_date_idx',
            ),
        ),
        # api/serializers.py:834 — per-subdomain queryset bucketed by severity
        # at api/serializers.py:856-906.
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['subdomain', 'severity'], name='vuln_subdomain_sev_idx'),
        ),

        # --- get_or_create lookup keys in the vuln write path ---
        # reNgine/common_func.py:786 and :811 look these rows up by name on
        # every tag and CWE attached to a finding. CveId.name already carries
        # unique=True/db_index=True. VulnerabilityReference.url is deliberately
        # left unindexed — see the migration docstring in the review notes:
        # max_length=5000 exceeds the B-tree index tuple limit.
        migrations.AlterField(
            model_name='vulnerabilitytags',
            name='name',
            field=models.CharField(db_index=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='cweid',
            name='name',
            field=models.CharField(db_index=True, max_length=100),
        ),
    ]
