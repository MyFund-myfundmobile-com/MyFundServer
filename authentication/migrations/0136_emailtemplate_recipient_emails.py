from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0135_top_saver_photo")]

    operations = [
        migrations.AddField(
            model_name="emailtemplate",
            name="recipient_emails",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
