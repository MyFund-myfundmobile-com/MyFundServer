# Generated by Django 4.2.5 on 2023-10-12 05:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0033_transaction_property_name_transaction_property_value_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='date',
            field=models.DateTimeField(auto_now_add=True),
        ),
        migrations.AlterField(
            model_name='transaction',
            name='time',
            field=models.TimeField(auto_now_add=True),
        ),
    ]
