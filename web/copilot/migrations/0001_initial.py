# Generated manually for Assessment Copilot

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CopilotSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255, unique=True)),
                ('enabled', models.BooleanField(default=True)),
                ('memory_scope', models.CharField(
                    choices=[
                        ('project', 'Per project'),
                        ('org', 'Per organization'),
                        ('global', 'Global (local corpus)'),
                        ('tiered', 'Tiered (project + curated global)'),
                    ],
                    default='project',
                    max_length=16,
                )),
                ('model_id', models.CharField(blank=True, default='', max_length=255)),
                ('org_id', models.CharField(blank=True, default='', max_length=255)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('updated_by', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='copilot_settings_updated', to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'Copilot settings',
                'verbose_name_plural': 'Copilot settings',
            },
        ),
        migrations.CreateModel(
            name='CopilotSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('scan_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('assessment_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('title', models.CharField(blank=True, default='New conversation', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='copilot_sessions', to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-updated_at'],
            },
        ),
        migrations.CreateModel(
            name='CopilotMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(
                    choices=[('user', 'User'), ('assistant', 'Assistant'), ('system', 'System')],
                    max_length=16,
                )),
                ('content', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('session', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='messages', to='copilot.copilotsession',
                )),
            ],
            options={
                'ordering': ['created_at'],
            },
        ),
        migrations.CreateModel(
            name='CopilotActionProposal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_slug', models.CharField(db_index=True, max_length=255)),
                ('scan_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('assessment_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('vulnerability_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('action_type', models.CharField(
                    choices=[
                        ('validate', 'Validate'),
                        ('safe_poc', 'SAFE PoC'),
                        ('followup', 'Follow-up'),
                        ('remediation', 'Remediation'),
                    ],
                    db_index=True,
                    max_length=32,
                )),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('approved', 'Approved'),
                        ('rejected', 'Rejected'),
                        ('failed', 'Failed'),
                    ],
                    db_index=True,
                    default='pending',
                    max_length=16,
                )),
                ('summary', models.CharField(blank=True, default='', max_length=512)),
                ('rationale', models.TextField(blank=True, default='')),
                ('payload', models.JSONField(default=dict)),
                ('safe_poc_attempt_id', models.IntegerField(blank=True, null=True)),
                ('followup_plan_id', models.IntegerField(blank=True, null=True)),
                ('result', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('decided_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='copilot_proposals_created', to=settings.AUTH_USER_MODEL,
                )),
                ('decided_by', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='copilot_proposals_decided', to=settings.AUTH_USER_MODEL,
                )),
                ('session', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='proposals', to='copilot.copilotsession',
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='copilotsession',
            index=models.Index(fields=['project_slug', '-updated_at'], name='copilot_cop_project_6c0f1a_idx'),
        ),
        migrations.AddIndex(
            model_name='copilotactionproposal',
            index=models.Index(fields=['project_slug', 'status', '-created_at'], name='copilot_cop_project_8a2b1c_idx'),
        ),
        migrations.AddIndex(
            model_name='copilotactionproposal',
            index=models.Index(fields=['vulnerability_id', 'status'], name='copilot_cop_vulnera_9d3e4f_idx'),
        ),
    ]
