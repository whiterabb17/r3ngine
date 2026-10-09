# Generated manually for InstalledExternalTool live status + ToolArgSchemaCache

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanEngine', '0017_proxy_only_after_ban'),
    ]

    operations = [
        migrations.AddField(
            model_name='installedexternaltool',
            name='is_present',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='installedexternaltool',
            name='resolved_path',
            field=models.CharField(blank=True, max_length=1500, null=True),
        ),
        migrations.AddField(
            model_name='installedexternaltool',
            name='detected_version',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='installedexternaltool',
            name='last_seen_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='installedexternaltool',
            name='last_sync_error',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.CreateModel(
            name='ToolArgSchemaCache',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pipeline_tool', models.CharField(db_index=True, max_length=100)),
                ('binary_name', models.CharField(max_length=100)),
                ('binary_path', models.CharField(blank=True, default='', max_length=1500)),
                ('version_fingerprint', models.CharField(blank=True, default='', max_length=200)),
                ('schema', models.JSONField(blank=True, default=list)),
                ('raw_help_hash', models.CharField(blank=True, default='', max_length=64)),
                ('fetched_at', models.DateTimeField(blank=True, null=True)),
                ('source', models.CharField(
                    choices=[('help', 'Help'), ('seed_fallback', 'Seed fallback')],
                    default='seed_fallback',
                    max_length=32,
                )),
            ],
            options={
                'indexes': [
                    models.Index(fields=['pipeline_tool', 'binary_name'], name='toolargs_pipe_bin_idx'),
                ],
                'unique_together': {('pipeline_tool', 'binary_name')},
            },
        ),
    ]
