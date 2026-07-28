from django.core.management.base import BaseCommand
from django.db.models import F

from authentication.models import Group


class Command(BaseCommand):
    help = (
        "Targeted fix for GroupBuys stuck showing 'active' with zero "
        "contributors (e.g. records created before leave_groupbuy started "
        "auto-deactivating on last exit). Only touches groups with "
        "status='active' AND no contributors - real active groups with "
        "participants are left untouched, unlike reset_all_groupbuys which "
        "wipes everything."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be fixed without saving anything",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")

        stale_groups = [
            g
            for g in Group.objects.select_related("property").filter(status__iexact="active")
            if not g.contributors.exists()
        ]

        if not stale_groups:
            self.stdout.write(self.style.SUCCESS("No stale active GroupBuys found - nothing to fix."))
            return

        for group in stale_groups:
            self.stdout.write(
                f"{'[DRY RUN] Would deactivate' if dry_run else 'Deactivating'} "
                f"{group.property.name} (group {group.id}) - 0 contributors, was active"
            )
            if not dry_run:
                group.status = "failed"
                group.save(update_fields=["status"])
                type(group.property).objects.filter(id=group.property_id).update(
                    units_available=F("units_available") + 1
                )

        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(
            self.style.SUCCESS(f"Stale GroupBuys fixed: {len(stale_groups)}")
        )
        if dry_run:
            self.stdout.write(
                self.style.WARNING("This was a DRY RUN. No changes were saved.")
            )
