# Generated by Django 4.2.5 on 2023-09-24 08:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0021_autosave_transaction_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='autosave',
            name='transaction_id',
        ),
        migrations.AddField(
            model_name='autosave',
            name='active',
            field=models.BooleanField(default=True),
        ),
    ]
