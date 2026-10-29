from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0131_first_save_guide"),
    ]

    operations = [
        migrations.AddField(
            model_name="ambassadorintake",
            name="group_link",
            field=models.URLField(blank=True, help_text="WhatsApp group link for selected ambassadors.", max_length=500),
        ),
        migrations.AddField(
            model_name="ambassadorintake",
            name="onboarding_note",
            field=models.CharField(blank=True, help_text='e.g. "Onboarding is this Saturday at 5pm on Google Meet."', max_length=300),
        ),
        migrations.AddField(
            model_name="ambassadorapplication",
            name="review_label",
            field=models.CharField(blank=True, choices=[("qualified", "Qualified"), ("maybe", "Maybe"), ("unqualified", "Unqualified")], db_index=True, max_length=20),
        ),
        migrations.AddField(
            model_name="ambassadorapplication",
            name="decision_sent_label",
            field=models.CharField(blank=True, choices=[("qualified", "Qualified"), ("maybe", "Maybe"), ("unqualified", "Unqualified")], max_length=20),
        ),
        migrations.AddField(
            model_name="ambassadorapplication",
            name="decision_sent_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
