# Generated by Django 4.2.3 on 2023-08-23 20:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0007_bankaccount_account_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bankaccount',
            name='account_number',
            field=models.CharField(max_length=20, unique=True),
        ),
    ]
