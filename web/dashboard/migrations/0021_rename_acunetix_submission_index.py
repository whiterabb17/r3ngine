"""Give the submission index the explicit name the model now declares.

0020 hardcoded a name in the style Django generates from a hash, but not the
hash Django actually computes, so `makemigrations --check` reported permanent
drift. Renaming to a plain, readable name removes the hash from the equation
instead of copying the right one.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0020_acunetixtargetsubmission'),
    ]

    operations = [
        migrations.RenameIndex(
            model_name='acunetixtargetsubmission',
            new_name='acu_submission_sent_idx',
            old_name='dashboard_a_last_su_0f1c4a_idx',
        ),
    ]
