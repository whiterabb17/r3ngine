# Generated manually for OsintStaging agent verification badges

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0065_alter_email_source_choices'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='osintstaging',
            name='agent_verified',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='osintstaging',
            name='agent_verified_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='osintstaging',
            name='agent_verified_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='osint_staging_verifications',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
