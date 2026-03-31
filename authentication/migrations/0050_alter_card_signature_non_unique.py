from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0049_add_card_updated_at_for_real"),
    ]

    operations = [
        migrations.AlterField(
            model_name="card",
            name="signature",
            field=models.CharField(
                max_length=255, null=True, blank=True, db_index=True
            ),
        ),
    ]
