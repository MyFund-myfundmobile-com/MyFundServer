# Generated by Django 4.2.5 on 2023-11-08 22:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0062_alter_transaction_transaction_type_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='banktransferrequest',
            name='transaction_id',
            field=models.CharField(default='', max_length=10),
        ),
        migrations.AlterField(
            model_name='transaction',
            name='transaction_id',
            field=models.CharField(default='', max_length=25, unique=True),
        ),
    ]
