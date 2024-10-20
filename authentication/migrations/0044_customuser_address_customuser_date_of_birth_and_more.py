# Generated by Django 4.2.5 on 2023-10-28 23:46

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0043_customuser_top_saver_percentage'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='address',
            field=models.TextField(default='13, Gbajabiamila Str, Ayobo, Lagos, Nigeria'),
        ),
        migrations.AddField(
            model_name='customuser',
            name='date_of_birth',
            field=models.DateField(default=datetime.date(1990, 1, 1)),
        ),
        migrations.AddField(
            model_name='customuser',
            name='employment_status',
            field=models.CharField(choices=[('Unemployed', 'Unemployed'), ('Employed', 'Employed'), ('Self-employed', 'Self-employed'), ('Business', 'Business'), ('Retired', 'Retired')], default='Unemployed', max_length=20),
        ),
        migrations.AddField(
            model_name='customuser',
            name='gender',
            field=models.CharField(choices=[('Male', 'Male'), ('Female', 'Female'), ('Non-binary', 'Non-binary')], default='Male', max_length=10),
        ),
        migrations.AddField(
            model_name='customuser',
            name='id_upload',
            field=models.ImageField(default='kyc_documents/placeholder.png', upload_to='kyc_documents/'),
        ),
        migrations.AddField(
            model_name='customuser',
            name='identification_type',
            field=models.CharField(choices=[('International Passport', 'International Passport'), ("Driver's License", "Driver's License"), ('National ID Card (NIN)', 'National ID Card (NIN)'), ("Permanent Voter's Card", "Permanent Voter's Card")], default='International Passport', max_length=50),
        ),
        migrations.AddField(
            model_name='customuser',
            name='kyc_updated',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='customuser',
            name='mothers_maiden_name',
            field=models.CharField(default='Jane Doe', max_length=100),
        ),
        migrations.AddField(
            model_name='customuser',
            name='next_of_kin_name',
            field=models.CharField(default='John Doe', max_length=100),
        ),
        migrations.AddField(
            model_name='customuser',
            name='next_of_kin_phone_number',
            field=models.CharField(default='08033924595', max_length=15),
        ),
        migrations.AddField(
            model_name='customuser',
            name='relationship_status',
            field=models.CharField(choices=[('Single', 'Single'), ('Married', 'Married'), ('Divorced', 'Divorced'), ('Separated', 'Separated'), ('Remarried', 'Remarried')], default='Single', max_length=20),
        ),
        migrations.AddField(
            model_name='customuser',
            name='relationship_with_next_of_kin',
            field=models.CharField(choices=[('Brother', 'Brother'), ('Sister', 'Sister'), ('Spouse', 'Spouse'), ('Father', 'Father'), ('Mother', 'Mother'), ('Daughter', 'Daughter'), ('Son', 'Son'), ('Friend', 'Friend'), ('Relative', 'Relative')], default='Brother', max_length=20),
        ),
        migrations.AddField(
            model_name='customuser',
            name='yearly_income',
            field=models.CharField(choices=[('Less than N200,000', 'Less than N200,000'), ('N200001 - N500000', 'N200001 - N500000'), ('N500000 - N1million', 'N500000 - N1million'), ('N1million - N5million', 'N1million - N5million'), ('N5million - N10million', 'N5million - N10million'), ('N10million - N20 million', 'N10million - N20 million'), ('Above N20million', 'Above N20million')], default='Less than N200,000', max_length=30),
        ),
    ]
