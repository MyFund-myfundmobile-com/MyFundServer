from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0048_remove_card_updated_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="card",
            name="updated_at",
            field=models.DateTimeField(
                auto_now=True, default=django.utils.timezone.now
            ),
            preserve_default=False,
        ),
    ]
