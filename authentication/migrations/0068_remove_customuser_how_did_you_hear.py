# Generated by Django 4.2.5 on 2024-02-19 19:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0067_customuser_how_did_you_hear'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='how_did_you_hear',
        ),
    ]
