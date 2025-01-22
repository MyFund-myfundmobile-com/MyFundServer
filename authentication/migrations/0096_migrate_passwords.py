from django.db import migrations


def migrate_passwords(apps, schema_editor):
    CustomUser = apps.get_model("authentication", "CustomUser")
    UserPassword = apps.get_model("authentication", "UserPassword")

    for user in CustomUser.objects.all():
        if user.password:
            UserPassword.objects.create(user=user, password=user.password)


def reverse_migration(apps, schema_editor):
    UserPassword = apps.get_model("authentication", "UserPassword")
    UserPassword.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0095_userpassword_customuser_password_record"),
    ]

    operations = [
        migrations.RunPython(migrate_passwords, reverse_migration),
    ]
