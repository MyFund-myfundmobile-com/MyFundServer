# Generated by Django 4.2.3 on 2023-09-07 22:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0017_remove_transaction_transaction_id_accountbalance'),
    ]

    operations = [
        migrations.AddField(
            model_name='transaction',
            name='transaction_id',
            field=models.CharField(default='', max_length=255),
        ),
    ]
