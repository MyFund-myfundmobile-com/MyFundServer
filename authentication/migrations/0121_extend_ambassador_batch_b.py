from datetime import datetime, timezone
from django.db import migrations


def extend_batch_b(apps, schema_editor):
    Intake = apps.get_model("authentication", "AmbassadorIntake")
    Intake.objects.using(schema_editor.connection.alias).filter(
        slug="october-2026", programme="ambassador",
    ).update(
        # Exclusive cutoff: November 2 midnight WAT, allowing all November 1.
        closes_at=datetime(2026, 11, 1, 23, tzinfo=timezone.utc),
        active=True,
    )


class Migration(migrations.Migration):
    dependencies = [("authentication", "0120_ambassador_performance_notifications")]
    operations = [migrations.RunPython(extend_batch_b, migrations.RunPython.noop)]
