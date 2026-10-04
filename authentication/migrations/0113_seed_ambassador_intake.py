from datetime import datetime, timezone
from django.db import migrations


def seed(apps, schema_editor):
    Intake = apps.get_model('authentication', 'AmbassadorIntake')
    Intake.objects.get_or_create(slug='october-2026', defaults={
        'title': 'October 2026 – March 2027',
        'opens_at': datetime(2026, 9, 1, tzinfo=timezone.utc),
        # Midnight October 11 WAT: applications accepted throughout October 10.
        'closes_at': datetime(2026, 10, 10, 23, tzinfo=timezone.utc),
        'active': True,
    })


class Migration(migrations.Migration):
    dependencies = [('authentication', '0112_ambassador_applications')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
