# Generated by Django 5.0 on 2024-12-05 10:59

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0091_remove_withdrawalrequest_failure_reason_and_more'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='WithdrawalRequest',
            new_name='PendingWithdrawals',
        ),
    ]