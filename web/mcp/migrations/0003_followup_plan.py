# Generated manually for FollowupPlan

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mcp', '0002_agent_identity'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FollowupPlan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('scan_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('assessment_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('status', models.CharField(
                    choices=[
                        ('proposed', 'Proposed'),
                        ('approved', 'Approved'),
                        ('running', 'Running'),
                        ('done', 'Done'),
                        ('failed', 'Failed'),
                        ('aborted', 'Aborted'),
                        ('rejected', 'Rejected'),
                    ],
                    db_index=True,
                    default='proposed',
                    max_length=16,
                )),
                ('rationale', models.TextField(blank=True, default='')),
                ('steps', models.JSONField(default=list)),
                ('temporal_workflow_ids', models.JSONField(default=list)),
                ('retry_count', models.PositiveIntegerField(default=0)),
                ('operator_edited', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('approved_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='followup_plans_created',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('updated_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='followup_plans_updated',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
        ),
        migrations.AddIndex(
            model_name='followupplan',
            index=models.Index(fields=['project_slug', 'status', '-created_at'], name='mcp_followu_project_idx'),
        ),
        migrations.AddIndex(
            model_name='followupplan',
            index=models.Index(fields=['scan_id', 'status'], name='mcp_followu_scan_id_idx'),
        ),
        migrations.AddIndex(
            model_name='followupplan',
            index=models.Index(fields=['assessment_id', 'status'], name='mcp_followu_assess_idx'),
        ),
    ]
