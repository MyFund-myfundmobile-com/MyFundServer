# Generated by Django 5.0 on 2024-03-27 00:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0071_alter_customuser_myfund_pin'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='profile_picture',
            field=models.URLField(blank=True, null=True),
        ),
    ]