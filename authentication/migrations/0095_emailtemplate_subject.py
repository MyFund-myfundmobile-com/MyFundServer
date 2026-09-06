from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0094_emailcampaign_template_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='emailtemplate',
            name='subject',
            field=models.CharField(max_length=255, null=True, blank=True),
        ),
    ]
