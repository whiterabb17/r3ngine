"""Composite indexes for ScanHistory list/status poll filters.

Hot paths filter by domain (often via project slug join) and scan_status, then
order by -start_scan_date. Without these, listScanHistory / scan_status /
recent-scans loops paid a sequential scan as history grew.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0072_performancebenchmark'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='scanhistory',
            index=models.Index(
                fields=['domain', 'scan_status', '-start_scan_date'],
                name='sh_domain_status_started_idx',
            ),
        ),
        migrations.AddIndex(
            model_name='scanhistory',
            index=models.Index(
                fields=['domain', '-start_scan_date'],
                name='sh_domain_started_idx',
            ),
        ),
    ]
