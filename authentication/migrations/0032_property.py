# Generated by Django 4.2.5 on 2023-10-11 21:08

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0031_bankaccount_bank_code'),
    ]

    operations = [
        migrations.CreateModel(
            name='Property',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('price', models.DecimalField(decimal_places=2, max_digits=11)),
                ('rent_reward', models.DecimalField(decimal_places=2, max_digits=11)),
                ('units_available', models.PositiveIntegerField()),
                ('owner', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='owned_properties', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
