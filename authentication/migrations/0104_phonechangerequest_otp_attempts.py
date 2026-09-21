from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0103_clear_id_upload_placeholder")]
    operations = [migrations.AddField(
        model_name="phonechangerequest", name="otp_attempts",
        field=models.PositiveSmallIntegerField(default=0),
    )]
