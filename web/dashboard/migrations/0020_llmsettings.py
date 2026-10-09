from django.db import migrations, models


def seed_llm_settings(apps, schema_editor):
    LLMSettings = apps.get_model('dashboard', 'LLMSettings')
    LLMConfig = apps.get_model('dashboard', 'LLMConfig')
    enabled = LLMConfig.objects.filter(is_active=True).exists()
    LLMSettings.objects.get_or_create(pk=1, defaults={'enabled': enabled})


def unseed_llm_settings(apps, schema_editor):
    LLMSettings = apps.get_model('dashboard', 'LLMSettings')
    LLMSettings.objects.filter(pk=1).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0019_osint_expansion_api_keys'),
    ]

    operations = [
        migrations.CreateModel(
            name='LLMSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'LLM settings',
                'verbose_name_plural': 'LLM settings',
            },
        ),
        migrations.RunPython(seed_llm_settings, unseed_llm_settings),
    ]
