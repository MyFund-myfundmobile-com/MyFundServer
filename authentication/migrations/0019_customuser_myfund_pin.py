# Generated by Django 4.2.5 on 2023-09-20 17:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0018_transaction_transaction_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='myfund_pin',
            field=models.CharField(blank=True, max_length=4, null=True),
        ),
    ]
