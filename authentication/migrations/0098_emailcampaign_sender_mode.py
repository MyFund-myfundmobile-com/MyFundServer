from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0097_pushcampaign")]
    operations = [migrations.AddField(model_name="emailcampaign", name="sender_mode", field=models.CharField(default="hello", max_length=20))]
