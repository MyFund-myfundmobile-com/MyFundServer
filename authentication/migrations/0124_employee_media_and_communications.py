from django.db import migrations, models


def move_samuel_to_media_and_communications(apps, schema_editor):
    """Keep Samuel's existing payroll record when Engagement split out."""
    Employee = apps.get_model("authentication", "Employee")
    Employee.objects.filter(
        department="Engagement", name__icontains="samuel"
    ).update(department="Media and Communications")


class Migration(migrations.Migration):
    dependencies = [("authentication", "0123_book_reading_progress")]

    operations = [
        migrations.AlterField(
            model_name="employee",
            name="department",
            field=models.CharField(
                choices=[
                    ("Tech", "Tech"),
                    ("Engagement", "Engagement"),
                    ("Media and Communications", "Media and Communications"),
                    ("CX", "CX"),
                    ("Operations", "Operations"),
                    ("Property", "Property"),
                    ("Other", "Other"),
                ],
                default="Other",
                max_length=50,
            ),
        ),
        migrations.RunPython(move_samuel_to_media_and_communications, migrations.RunPython.noop),
    ]
