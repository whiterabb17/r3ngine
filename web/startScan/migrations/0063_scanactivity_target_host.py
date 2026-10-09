from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0062_alter_targetreport_report_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanactivity',
            name='target_host',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
