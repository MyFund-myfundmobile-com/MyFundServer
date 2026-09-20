from django.db import migrations


def clear_placeholder(apps, schema_editor):
    # id_upload just moved from an ImageField (default
    # "kyc_documents/placeholder.png") to a plain CharField. Anyone who
    # never actually uploaded an ID still has that literal string baked
    # into their row from record creation - clear it to null now so
    # get_user_profile's completion check doesn't credit them with an ID
    # upload they never provided.
    CustomUser = apps.get_model("authentication", "CustomUser")
    CustomUser.objects.filter(id_upload="kyc_documents/placeholder.png").update(
        id_upload=None
    )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0102_alter_customuser_id_upload"),
    ]

    operations = [
        migrations.RunPython(clear_placeholder, noop_reverse),
    ]
