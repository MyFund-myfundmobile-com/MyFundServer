from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0134_top_saver_recognition"),
    ]

    operations = [
        migrations.AddField(
            model_name="topsaverrecognition",
            name="photo_file_id",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="topsaverrecognition",
            name="photo_path",
            field=models.CharField(blank=True, max_length=500),
        ),
    ]
