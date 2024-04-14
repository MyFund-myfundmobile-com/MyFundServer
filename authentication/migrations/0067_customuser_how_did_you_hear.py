# Generated by Django 4.2.5 on 2024-02-19 19:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0066_alter_transaction_transaction_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='how_did_you_hear',
            field=models.CharField(choices=[('SM', 'Social Media - Facebook, Instagram, etc.'), ('IMs', 'Instant Messaging - Whatsapp, Telegram, etc.'), ('FF', 'Family and Friend'), ('GS', 'Google Search'), ('REC', 'Recommended'), ('CFG', 'Cashflow Game'), ('OTHER', 'Other')], default='OTHER', max_length=50),
        ),
    ]
