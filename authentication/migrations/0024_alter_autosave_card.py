# Generated by Django 4.2.5 on 2023-09-24 18:19

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0023_alter_autosave_amount'),
    ]

    operations = [
        migrations.AlterField(
            model_name='autosave',
            name='card',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='authentication.card'),
        ),
    ]
