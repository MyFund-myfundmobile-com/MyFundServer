from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0053_alter_ambassadorpointconfig_coursera_points_and_more"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                ALTER TABLE authentication_card
                DROP CONSTRAINT IF EXISTS authentication_card_signature_key;

                ALTER TABLE authentication_card
                DROP CONSTRAINT IF EXISTS authentication_card_authorization_code_key;

                UPDATE authentication_card
                SET card_owner_name = ''
                WHERE card_owner_name IS NULL;
            """,
            reverse_sql="""
                -- no reverse
            """,
        ),
    ]
