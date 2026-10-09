"""Record the mailbox-verification choice added to Email.source.

Upstream added SOURCE_MAILBOX_VERIFY to the field's choices without a migration,
which leaves `makemigrations --check` failing. Choices are validation metadata
only, so this alters nothing in the database.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0064_scan_hot_path_indexes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='email',
            name='source',
            field=models.CharField(
                blank=True,
                choices=[
                    ('manual', 'Manual'),
                    ('hunter', 'Hunter.io'),
                    ('harvester', 'theHarvester'),
                    ('phonebook', 'Phonebook.cz'),
                    ('pattern', 'Pattern Inference'),
                    ('crawled', 'Crawled URLs'),
                    ('mailbox_verify', 'Mailbox Verified'),
                ],
                default='hunter',
                max_length=50,
            ),
        ),
    ]
