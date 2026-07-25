from django.core.management.base import BaseCommand
from django.db.models import F

from authentication.models import Group, Contribution, Property
from authentication.utils import create_transaction


class Command(BaseCommand):
    help = (
        "Full reset: removes every Group (any status, any property) so the "
        "catalog goes back to a pristine 'nothing started yet' state. Every "
        "confirmed contributor is refunded in full (no service charge - this "
        "is a reset, not an expiry), then each affected property's "
        "units_available is restored by the number of groups removed against "
        "it, and the groups (plus their Contributions/GroupOwnership/"
        "GroupDeparture, via cascade) are deleted."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be refunded/restored/deleted without saving anything",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")

        groups = list(Group.objects.select_related("property").all())
        if not groups:
            self.stdout.write(self.style.WARNING("No GroupBuys found - already clean."))
            return

        total_refunded = 0
        units_to_restore = {}  # property_id -> count of groups removed

        for group in groups:
            self.stdout.write(f"\n--- {group.property.name} (group {group.id}, status={group.status}) ---")

            contributions = Contribution.objects.filter(
                group=group, payment_status="Confirmed"
            ).select_related("user")

            for contribution in contributions:
                self.stdout.write(
                    f"  Refunding {contribution.user.email}: "
                    f"₦{contribution.amount:,.2f} ({contribution.source})"
                )
                if not dry_run:
                    create_transaction(
                        user=contribution.user,
                        amount=contribution.amount,
                        transaction_type="credit",
                        credited_to=contribution.source.upper(),
                        status="confirmed",
                        description=f"Refund - GroupBuy reset for {group.property.name}",
                    )
                total_refunded += contribution.amount

            units_to_restore[group.property_id] = units_to_restore.get(group.property_id, 0) + 1

        group_count = len(groups)
        property_count = len(units_to_restore)

        self.stdout.write(
            f"\n{'[DRY RUN] Would restore' if dry_run else 'Restoring'} "
            f"units_available on {property_count} propert{'y' if property_count == 1 else 'ies'}"
        )
        if not dry_run:
            for property_id, count in units_to_restore.items():
                Property.objects.filter(id=property_id).update(
                    units_available=F("units_available") + count
                )

        self.stdout.write(
            f"{'[DRY RUN] Would delete' if dry_run else 'Deleting'} {group_count} group(s)"
        )
        if not dry_run:
            Group.objects.filter(id__in=[g.id for g in groups]).delete()

        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(
            self.style.SUCCESS(
                f"Groups removed: {group_count} | Properties reset: {property_count} | "
                f"Total refunded: ₦{total_refunded:,.2f}"
            )
        )
        if dry_run:
            self.stdout.write(
                self.style.WARNING("This was a DRY RUN. No changes were saved.")
            )
