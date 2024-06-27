# Generated by Django 4.2.5 on 2023-11-02 20:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0052_monthlysavings_investment_monthlysavings_savings'),
    ]

    operations = [
        migrations.AlterField(
            model_name='monthlysavings',
            name='total_savings_and_investments',
            field=models.DecimalField(decimal_places=2, default=0, max_digits=10),
        ),
    ]
