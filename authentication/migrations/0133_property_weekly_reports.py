from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0132_ambassador_decisions"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cxweeklyreport",
            name="department",
            field=models.CharField(
                choices=[("CX", "CX"), ("Engagement", "Engagement"), ("Media", "Media and Communications"),
                         ("Property", "Property and Projects")],
                db_index=True, default="CX", max_length=20,
            ),
        ),
    ]
