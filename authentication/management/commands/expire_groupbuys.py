from django.core.management.base import BaseCommand

from authentication.utils import expire_overdue_groupbuys


class Command(BaseCommand):
    help = (
        "Sweeps GroupBuys past their deadline that never reached 100% "
        "funding: refunds every confirmed contributor (minus a 1% service "
        "charge), marks the group failed, and releases the property's unit "
        "so a new GroupBuy can be started against it. Meant to be run "
        "periodically (cron / Koyeb scheduled job) - safe to re-run since "
        "already-expired groups are no longer 'active' and won't match again."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be refunded without saving anything",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")

        result = expire_overdue_groupbuys(dry_run=dry_run)

        if result["expired_count"] == 0:
            self.stdout.write(self.style.WARNING("No overdue, under-funded GroupBuys found."))
            return

        for group in result["groups"]:
            self.stdout.write(
                f"\n--- {group['property']} (group {group['group_id']}) ---"
            )
            for c in group["contributors"]:
                self.stdout.write(
                    f"  {c['email']}: refund ₦{c['refund_amount']:,.2f} "
                    f"(₦{c['service_charge']:,.2f} service charge on ₦{c['amount']:,.2f}, "
                    f"from {c['source']})"
                )

        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(
            self.style.SUCCESS(
                f"Expired GroupBuys: {result['expired_count']} | "
                f"Total refunded: ₦{result['total_refunded']:,.2f} | "
                f"Total service charge collected: ₦{result['total_service_charge']:,.2f}"
            )
        )
        if dry_run:
            self.stdout.write(
                self.style.WARNING("This was a DRY RUN. No changes were saved.")
            )
