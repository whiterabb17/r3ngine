# Generated manually for SafePocAttempt

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mcp', '0007_rename_attack_path_proposal_indexes'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SafePocAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('scan_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('vulnerability_id', models.IntegerField(db_index=True)),
                ('status', models.CharField(
                    choices=[
                        ('proposed', 'Proposed'),
                        ('approved', 'Approved'),
                        ('running', 'Running'),
                        ('succeeded', 'Succeeded'),
                        ('failed', 'Failed'),
                        ('aborted', 'Aborted'),
                        ('rejected', 'Rejected'),
                    ],
                    db_index=True,
                    default='proposed',
                    max_length=16,
                )),
                ('template_id', models.CharField(max_length=64)),
                ('params', models.JSONField(default=dict)),
                ('rationale', models.TextField(blank=True, default='')),
                ('agent_id', models.CharField(blank=True, default='', max_length=128)),
                ('result', models.JSONField(blank=True, null=True)),
                ('operator_edited', models.BooleanField(default=False)),
                ('temporal_workflow_id', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('approved_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='safe_poc_attempts_created',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('updated_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='safe_poc_attempts_updated',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
        ),
        migrations.AddIndex(
            model_name='safepocattempt',
            index=models.Index(fields=['project_slug', 'status', '-created_at'], name='mcp_safepoc_project_idx'),
        ),
        migrations.AddIndex(
            model_name='safepocattempt',
            index=models.Index(fields=['scan_id', 'status'], name='mcp_safepoc_scan_id_idx'),
        ),
        migrations.AddIndex(
            model_name='safepocattempt',
            index=models.Index(fields=['vulnerability_id', 'status'], name='mcp_safepoc_vuln_id_idx'),
        ),
    ]
