# Generated by Django 5.0 on 2024-05-03 13:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0073_alter_customuser_profile_picture'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='transaction_type',
            field=models.CharField(choices=[('credit', 'Credit'), ('debit', 'Debit'), ('pending', 'Pending'), ('confirmed', 'Confirmed'), ('failed', 'Failed')], max_length=10),
        ),
    ]