# Generated manually for Copilot v2 MSF + Trace

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('copilot', '0002_rename_copilot_cop_project_8a2b1c_idx_copilot_cop_project_4b92a2_idx_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='copilotactionproposal',
            name='msf_aux_attempt_id',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='copilotactionproposal',
            name='action_type',
            field=models.CharField(
                choices=[
                    ('validate', 'Validate'),
                    ('safe_poc', 'SAFE PoC'),
                    ('followup', 'Follow-up'),
                    ('remediation', 'Remediation'),
                    ('msf_module', 'MSF module'),
                ],
                db_index=True,
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name='MsfAuxAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('scan_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('vulnerability_id', models.IntegerField(blank=True, db_index=True, null=True)),
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
                ('module', models.CharField(max_length=255)),
                ('options', models.JSONField(default=dict)),
                ('rationale', models.TextField(blank=True, default='')),
                ('result', models.JSONField(blank=True, null=True)),
                ('error', models.TextField(blank=True, default='')),
                ('temporal_workflow_id', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('approved_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='msf_aux_attempts_created',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('decided_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='msf_aux_attempts_decided',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='CopilotTraceEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('turn_id', models.CharField(blank=True, db_index=True, default='', max_length=64)),
                ('event_type', models.CharField(
                    choices=[
                        ('retrieve', 'Retrieve'),
                        ('decision', 'Decision'),
                        ('proposal', 'Proposal'),
                        ('msf_aux', 'MSF aux'),
                        ('thought', 'Thought'),
                        ('error', 'Error'),
                    ],
                    db_index=True,
                    max_length=32,
                )),
                ('summary', models.CharField(blank=True, default='', max_length=512)),
                ('payload', models.JSONField(blank=True, default=dict)),
                ('proposal_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('msf_aux_attempt_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('session', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='trace_events',
                    to='copilot.copilotsession',
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='msfauxattempt',
            index=models.Index(fields=['project_slug', 'status', '-created_at'], name='copilot_msf_project_idx'),
        ),
        migrations.AddIndex(
            model_name='msfauxattempt',
            index=models.Index(fields=['vulnerability_id', 'status'], name='copilot_msf_vuln_idx'),
        ),
        migrations.AddIndex(
            model_name='copilottraceevent',
            index=models.Index(fields=['project_slug', '-created_at'], name='copilot_tr_project_idx'),
        ),
        migrations.AddIndex(
            model_name='copilottraceevent',
            index=models.Index(fields=['session', 'turn_id'], name='copilot_tr_session_idx'),
        ),
    ]
