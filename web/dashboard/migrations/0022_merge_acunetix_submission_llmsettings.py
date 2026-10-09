"""Merge the two 0020 branches of the dashboard app.

0020_acunetixtargetsubmission (with its 0021 follow-up) and 0020_llmsettings were
written independently on either side of the upstream merge, leaving the app with
two leaf migrations, which Django refuses to migrate. Neither is renamed: the
local pair is already applied on deployed databases and would be re-applied under
a new name, and upstream's own later migrations will depend on 0020_llmsettings
by name.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0021_rename_acunetix_submission_index'),
        ('dashboard', '0020_llmsettings'),
    ]

    operations = []
