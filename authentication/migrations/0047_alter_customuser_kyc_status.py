# Generated by Django 4.2.5 on 2023-10-30 01:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0046_alter_customuser_address_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='kyc_status',
            field=models.CharField(max_length=10, null=True),
        ),
    ]
