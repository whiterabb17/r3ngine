from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0073_scanhistory_list_indexes'),
    ]

    operations = [
        migrations.AddField(
            model_name='impactassessment',
            name='llm_report_remediation',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='impactassessment',
            name='llm_report_remediation_fingerprint',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
    ]
