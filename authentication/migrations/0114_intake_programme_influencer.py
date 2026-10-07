from datetime import datetime, timezone
from django.db import migrations, models


def seed(apps, schema_editor):
    Intake = apps.get_model('authentication', 'AmbassadorIntake')
    # Influencer applications are rolling (an ongoing role, not a cohort),
    # so this intake stays open until an admin closes it.
    Intake.objects.get_or_create(slug='influencer', defaults={
        'programme': 'influencer',
        'title': 'MyFund Influencer Programme',
        'opens_at': datetime(2026, 10, 1, tzinfo=timezone.utc),
        'closes_at': datetime(2030, 12, 31, 23, tzinfo=timezone.utc),
        'active': True,
    })


class Migration(migrations.Migration):
    dependencies = [('authentication', '0113_seed_ambassador_intake')]
    operations = [
        migrations.AddField(
            model_name='ambassadorintake',
            name='programme',
            field=models.CharField(choices=[('ambassador', 'Ambassador'), ('influencer', 'Influencer')], db_index=True, default='ambassador', max_length=20),
        ),
        migrations.RunPython(seed, migrations.RunPython.noop),
    ]
