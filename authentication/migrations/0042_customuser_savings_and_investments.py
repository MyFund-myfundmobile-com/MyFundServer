# Generated by Django 4.2.5 on 2023-10-27 11:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0041_monthlysavings_created_at_alter_monthlysavings_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='savings_and_investments',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=11),
        ),
    ]
