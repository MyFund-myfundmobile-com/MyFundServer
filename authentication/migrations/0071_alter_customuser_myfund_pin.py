# Generated by Django 5.0 on 2024-03-17 18:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0070_alter_customuser_myfund_pin'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='myfund_pin',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
