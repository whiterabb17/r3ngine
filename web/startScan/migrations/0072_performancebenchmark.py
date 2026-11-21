from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0071_vulnerability_cvss_estimated'),
    ]

    operations = [
        migrations.CreateModel(
            name='PerformanceBenchmark',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('http_url', models.CharField(max_length=30000)),
                ('performance_score', models.FloatField(blank=True, null=True)),
                ('accessibility_score', models.FloatField(blank=True, null=True)),
                ('best_practices_score', models.FloatField(blank=True, null=True)),
                ('seo_score', models.FloatField(blank=True, null=True)),
                ('fcp_ms', models.FloatField(blank=True, null=True)),
                ('lcp_ms', models.FloatField(blank=True, null=True)),
                ('tbt_ms', models.FloatField(blank=True, null=True)),
                ('cls', models.FloatField(blank=True, null=True)),
                ('speed_index_ms', models.FloatField(blank=True, null=True)),
                ('tti_ms', models.FloatField(blank=True, null=True)),
                ('ttfb_ms', models.FloatField(blank=True, null=True)),
                ('raw_json', models.JSONField(blank=True, default=dict)),
                ('error', models.TextField(blank=True, null=True)),
                ('captured_at', models.DateTimeField(auto_now_add=True)),
                ('endpoint', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='performance_benchmarks', to='startScan.endpoint',
                )),
                ('scan_history', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='performance_benchmarks', to='startScan.scanhistory',
                )),
                ('subdomain', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                    related_name='performance_benchmarks', to='startScan.subdomain',
                )),
            ],
            options={
                'ordering': ['-captured_at'],
            },
        ),
        migrations.AddIndex(
            model_name='performancebenchmark',
            index=models.Index(fields=['scan_history', 'performance_score'], name='startScan_p_scan_hi_perf_idx'),
        ),
    ]
