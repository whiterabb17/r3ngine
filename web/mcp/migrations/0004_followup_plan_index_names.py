# Generated manually — align FollowupPlan index names with Django defaults

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mcp', '0003_followup_plan'),
    ]

    operations = [
        migrations.RenameIndex(
            model_name='followupplan',
            new_name='mcp_followu_project_f7c2f3_idx',
            old_name='mcp_followu_project_idx',
        ),
        migrations.RenameIndex(
            model_name='followupplan',
            new_name='mcp_followu_scan_id_20530a_idx',
            old_name='mcp_followu_scan_id_idx',
        ),
        migrations.RenameIndex(
            model_name='followupplan',
            new_name='mcp_followu_assessm_387473_idx',
            old_name='mcp_followu_assess_idx',
        ),
    ]
