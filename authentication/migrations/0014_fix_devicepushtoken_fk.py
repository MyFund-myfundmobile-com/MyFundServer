# authentication/migrations/0014_fix_devicepushtoken_fk.py
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0013_merge_20250820_1104"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
-- Drop the old constraint if it exists (uses the constraint name from your error; no-op if missing)
ALTER TABLE authentication_devicepushtoken
  DROP CONSTRAINT IF EXISTS authentication_devic_user_id_31b30459_fk_authentic;

-- Add a new FK constraint that references authentication_customuser(id) with ON DELETE CASCADE
ALTER TABLE authentication_devicepushtoken
  ADD CONSTRAINT authentication_devicepushtoken_user_id_fk
  FOREIGN KEY (user_id)
  REFERENCES authentication_customuser(id)
  ON DELETE CASCADE;
            """,
            reverse_sql="""
-- Reverse: drop the cascade FK if applied (this only removes the FK; doesn't recreate previous exact constraint)
ALTER TABLE authentication_devicepushtoken
  DROP CONSTRAINT IF EXISTS authentication_devicepushtoken_user_id_fk;
            """,
        )
    ]
