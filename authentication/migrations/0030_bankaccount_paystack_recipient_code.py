# Generated by Django 4.2.5 on 2023-10-07 17:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0029_transaction_service_charge_transaction_total_amount'),
    ]

    operations = [
        migrations.AddField(
            model_name='bankaccount',
            name='paystack_recipient_code',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]