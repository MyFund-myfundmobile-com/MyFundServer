# Generated by Django 4.2.5 on 2023-11-02 21:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0055_customuser_total_savings_and_investments_this_month'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='monthlysavings',
            name='total_savings_and_investments',
        ),
    ]
