import re

from django.core.management.base import BaseCommand

from authentication.models import Property, Contribution
from authentication.utils import create_transaction

DEFAULT_TARGET_NAMES = ["Test", "FUNAAB R/P 01", "FUNAAB R/P 02"]

# What a "clean" seeded property name looks like - anything else is a stray.
CLEAN_NAME_PATTERN = re.compile(r"^FUNAAB (Selfcon|Room & Parlour) \d{2}$")


class Command(BaseCommand):
    help = (
        "Removes stray/leftover Property rows (and their Groups, Contributions, "
        "GroupOwnership, GroupDeparture records via cascade) that don't belong "
        "in the clean seeded catalog - e.g. old test properties from before "
        "seed_funaab_properties. Confirmed contributors are refunded in full "
        "(no service charge - this is cleanup, not an expiry) before deletion "
        "so no test balance is silently lost."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--names",
            nargs="+",
            default=DEFAULT_TARGET_NAMES,
            help=f"Exact property names to remove (default: {DEFAULT_TARGET_NAMES})",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be refunded/deleted without saving anything",
        )
        parser.add_argument(
            "--list-all",
            action="store_true",
            help=(
                "Read-only: list every property, flagging any whose name doesn't "
                "match the clean seeded pattern (FUNAAB Selfcon/Room & Parlour NN). "
                "Does not refund or delete anything - use this to find the exact "
                "name of a stray property before passing it to --names."
            ),
        )

    def handle(self, *args, **options):
        if options.get("list_all"):
            for prop in Property.objects.all().order_by("id"):
                marker = "" if CLEAN_NAME_PATTERN.match(prop.name) else "  <-- STRAY"
                self.stdout.write(f"{prop.id}: {prop.name!r}{marker}")
            return

        names = options["names"]
        dry_run = options.get("dry_run")

        properties = Property.objects.filter(name__in=names)
        if not properties.exists():
            self.stdout.write(self.style.WARNING(f"No properties found matching: {names}"))
            return

        total_refunded = 0

        for prop in properties:
            self.stdout.write(f"\n--- {prop.name} (id={prop.id}) ---")
            groups = prop.group_set.all()

            for group in groups:
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
                            description=f"Refund - {prop.name} removed during cleanup",
                        )
                    total_refunded += contribution.amount

            self.stdout.write(
                f"  {'[DRY RUN] Would delete' if dry_run else 'Deleting'} "
                f"property and {groups.count()} associated group(s)"
            )
            if not dry_run:
                prop.delete()

        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(
            self.style.SUCCESS(
                f"Properties processed: {properties.count()} | "
                f"Total refunded: ₦{total_refunded:,.2f}"
            )
        )
        if dry_run:
            self.stdout.write(
                self.style.WARNING("This was a DRY RUN. No changes were saved.")
            )
