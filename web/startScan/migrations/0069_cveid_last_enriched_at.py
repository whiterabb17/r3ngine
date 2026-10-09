from django.db import migrations, models
from django.utils import timezone


def backfill_last_enriched_at(apps, schema_editor):
    """Treat existing CVSS-bearing rows as already enriched so in-flight scans skip them."""
    CveId = apps.get_model('startScan', 'CveId')
    now = timezone.now()
    CveId.objects.filter(
        cvss_v31_base_score__isnull=False,
        last_enriched_at__isnull=True,
    ).update(last_enriched_at=now)


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0068_vulnerability_agent_enrichment_db_default'),
    ]

    operations = [
        migrations.AddField(
            model_name='cveid',
            name='last_enriched_at',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.RunPython(backfill_last_enriched_at, migrations.RunPython.noop),
    ]
