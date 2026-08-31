# Renames CustomUser.is_hired_referrer to is_influencer - this app's own
# "hired referrer" users are what the business actually calls influencers,
# and the mismatched name was causing confusion. RenameField preserves the
# column's existing data (ALTER TABLE ... RENAME COLUMN), unlike a
# remove+add pair which would drop it.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0086_add_resale_listing_fields_to_groupownership'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='is_hired_referrer',
            new_name='is_influencer',
        ),
    ]
