# Generated by Django 5.0 on 2024-10-24 10:43

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0085_remove_autosave_card_remove_autosave_user_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='AutoInvest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('frequency', models.CharField(choices=[('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], max_length=10)),
                ('active', models.BooleanField(default=True)),
                ('paystack_sub_id', models.CharField(blank=True, max_length=255, null=True)),
                ('paystack_sub_code', models.CharField(blank=True, max_length=255, null=True)),
                ('paystack_sub_token', models.CharField(blank=True, max_length=255, null=True)),
                ('card', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='authentication.card')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='AutoSave',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('frequency', models.CharField(choices=[('hourly', 'Hourly'), ('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')], max_length=10)),
                ('active', models.BooleanField(default=True)),
                ('paystack_sub_id', models.CharField(blank=True, max_length=255, null=True)),
                ('paystack_sub_code', models.CharField(blank=True, max_length=255, null=True)),
                ('paystack_sub_token', models.CharField(blank=True, max_length=255, null=True)),
                ('card', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='authentication.card')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
