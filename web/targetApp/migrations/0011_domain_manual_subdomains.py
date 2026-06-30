from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('targetApp', '0010_domaininfo_whois_raw'),
    ]

    operations = [
        migrations.AddField(
            model_name='domain',
            name='manual_subdomains',
            field=models.TextField(blank=True, null=True),
        ),
    ]
