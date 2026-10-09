import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0069_cveid_last_enriched_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='subdomain',
            name='final_url',
            field=models.CharField(blank=True, max_length=2000, null=True),
        ),
        migrations.AddField(
            model_name='subdomain',
            name='duplicate_of',
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                related_name='duplicates', to='startScan.subdomain',
            ),
        ),
        migrations.AddField(
            model_name='subdomain',
            name='dedup_reason',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
