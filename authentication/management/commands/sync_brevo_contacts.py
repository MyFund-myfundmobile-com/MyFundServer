from django.core.management.base import BaseCommand
from django.db import connection

from authentication.models import CustomUser
from authentication.services.brevo_service import sync_contact_to_brevo

PROGRESS_FILE = "brevo_sync_progress.txt"


class Command(BaseCommand):

    help = "Sync MyFund users to Brevo with safe resume support"

    def handle(self, *args, **kwargs):

        # =====================================
        # LOAD LAST SUCCESSFUL USER ID
        # =====================================

        last_synced_id = 0

        try:

            with open(PROGRESS_FILE, "r") as f:
                last_synced_id = int(f.read().strip())

            self.stdout.write(
                self.style.WARNING(f"Resuming from user ID: {last_synced_id}")
            )

        except FileNotFoundError:

            self.stdout.write(self.style.WARNING("Starting fresh sync"))

        success = 0
        failed = 0

        # =====================================
        # PROCESS USERS IN SMALL BATCHES
        # =====================================

        while True:

            users = list(
                CustomUser.objects.filter(
                    id__gt=last_synced_id,
                    email__isnull=False,
                    is_deleted=False,
                    is_banned=False,
                )
                .exclude(email="")
                .order_by("id")[:50]
            )

            if not users:

                break

            self.stdout.write(
                self.style.WARNING(f"Processing batch of {len(users)} users...")
            )

            for user in users:

                try:

                    result = sync_contact_to_brevo(user)

                    if result is not None:

                        success += 1

                        # Save checkpoint immediately
                        last_synced_id = user.id

                        with open(PROGRESS_FILE, "w") as f:
                            f.write(str(last_synced_id))

                        self.stdout.write(self.style.SUCCESS(f"✅ Synced {user.email}"))

                    else:

                        failed += 1

                        self.stdout.write(self.style.ERROR(f"❌ Failed {user.email}"))

                except Exception as e:

                    failed += 1

                    self.stdout.write(self.style.ERROR(f"❌ Failed {user.email}: {e}"))

            # =====================================
            # RESET DB CONNECTION AFTER EACH BATCH
            # =====================================

            connection.close()

        self.stdout.write(self.style.SUCCESS(f"""
================================

Brevo Sync Completed

Successful: {success}
Failed: {failed}

Last synced user ID:
{last_synced_id}

================================
"""))
