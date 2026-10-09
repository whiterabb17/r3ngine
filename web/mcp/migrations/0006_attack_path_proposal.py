# Generated manually for AttackPathProposal

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mcp', '0005_rename_mcp_mcpagen_key_id_7c1a0e_idx_mcp_mcpagen_key_id_ff8590_idx_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackPathProposal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('scan_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('target_path_id', models.CharField(blank=True, db_index=True, default='', max_length=128)),
                ('impact_assessment_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('status', models.CharField(
                    choices=[
                        ('proposed', 'Proposed'),
                        ('approved', 'Approved'),
                        ('applied', 'Applied'),
                        ('aborted', 'Aborted'),
                        ('rejected', 'Rejected'),
                    ],
                    db_index=True,
                    default='proposed',
                    max_length=16,
                )),
                ('operation', models.CharField(
                    choices=[
                        ('enrich', 'Enrich'),
                        ('create', 'Create'),
                        ('update', 'Update'),
                        ('dismiss', 'Dismiss'),
                        ('trigger_apme', 'Trigger APME'),
                        ('recalculate_apme', 'Recalculate APME'),
                    ],
                    max_length=32,
                )),
                ('payload', models.JSONField(default=dict)),
                ('rationale', models.TextField(blank=True, default='')),
                ('agent_id', models.CharField(blank=True, default='', max_length=128)),
                ('result', models.JSONField(blank=True, null=True)),
                ('operator_edited', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('approved_at', models.DateTimeField(blank=True, null=True)),
                ('applied_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='attack_path_proposals_created',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('updated_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='attack_path_proposals_updated',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
        ),
        migrations.AddIndex(
            model_name='attackpathproposal',
            index=models.Index(fields=['project_slug', 'status', '-created_at'], name='mcp_attackp_project_idx'),
        ),
        migrations.AddIndex(
            model_name='attackpathproposal',
            index=models.Index(fields=['scan_id', 'status'], name='mcp_attackp_scan_id_idx'),
        ),
        migrations.AddIndex(
            model_name='attackpathproposal',
            index=models.Index(fields=['target_path_id', 'status'], name='mcp_attackp_path_id_idx'),
        ),
    ]
