from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0023_securitytrailsapikey'),
    ]

    operations = [
        migrations.AddField(
            model_name='llmconfig',
            name='base_url',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
