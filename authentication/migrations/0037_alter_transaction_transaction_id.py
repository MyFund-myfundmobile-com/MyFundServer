# Generated by Django 4.2.5 on 2023-10-16 00:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0036_alter_transaction_transaction_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='transaction_id',
            field=models.CharField(default='', max_length=255, unique=True),
        ),
    ]
