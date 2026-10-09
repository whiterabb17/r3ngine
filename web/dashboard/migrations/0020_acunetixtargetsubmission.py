import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0019_osint_expansion_api_keys'),
        ('startScan', '0063_scanactivity_target_host'),
    ]

    operations = [
        migrations.CreateModel(
            name='AcunetixTargetSubmission',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('host', models.CharField(max_length=500, unique=True)),
                ('target_url', models.CharField(blank=True, default='', max_length=1000)),
                ('acunetix_target_id', models.CharField(blank=True, default='', max_length=100)),
                ('last_submitted_at', models.DateTimeField()),
                ('submission_count', models.PositiveIntegerField(default=1)),
                ('last_scan_history', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='acunetix_submissions',
                    to='startScan.scanhistory',
                )),
            ],
        ),
        migrations.AddIndex(
            model_name='acunetixtargetsubmission',
            index=models.Index(fields=['last_submitted_at'], name='dashboard_a_last_su_0f1c4a_idx'),
        ),
    ]
