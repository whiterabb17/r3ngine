from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanEngine', '0016_scanworker'),
    ]

    operations = [
        migrations.AddField(
            model_name='proxy',
            name='priority_proxies',
            field=models.TextField(
                blank=True,
                null=True,
                help_text=(
                    'One proxy per line, tried before the scraped pool. Never '
                    'touched by the automatic proxy fetch and never dropped by '
                    'a health check.'
                ),
            ),
        ),
        migrations.AddField(
            model_name='proxy',
            name='use_priority_proxies',
            field=models.BooleanField(
                default=True,
                help_text='Try the manual proxies above before the scraped pool.',
            ),
        ),
        migrations.AddField(
            model_name='proxy',
            name='proxy_only_after_ban',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Scan directly and switch to the proxy pool only when the '
                    'target is found to be blocking us. A short probe against a '
                    "sample of the target's own endpoints decides, before the "
                    'vulnerability stage starts. Leave off to always use the '
                    'proxy pool.'
                ),
            ),
        ),
    ]
