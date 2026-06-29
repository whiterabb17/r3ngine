import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0053_email_add_source'),
        ('targetApp', '__first__'),
    ]

    operations = [
        migrations.CreateModel(
            name='DnsRecord',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('record_type', models.CharField(max_length=10)),
                ('value', models.TextField()),
                ('source', models.CharField(blank=True, max_length=200)),
                ('raw_metadata', models.JSONField(blank=True, default=dict)),
                ('scan_history', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='dns_records',
                    to='startScan.scanhistory',
                )),
                ('target_domain', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='targetApp.domain',
                )),
                ('subdomain', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='dns_records',
                    to='startScan.subdomain',
                )),
            ],
            options={
                'unique_together': {('scan_history', 'record_type', 'value')},
            },
        ),
    ]
