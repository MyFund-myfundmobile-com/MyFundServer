from django.core.management.base import BaseCommand

from authentication.models import Property

SELFCON_COUNT = 26
SELFCON_PRICE = 5_000_000
SELFCON_ANNUAL_RENT = 500_000  # ~₦41,667/month (rent_reward is stored as an annual figure)

ROOM_PARLOUR_COUNT = 14
ROOM_PARLOUR_PRICE = 8_500_000
ROOM_PARLOUR_ANNUAL_RENT = 1_000_000  # ~₦83,333/month

SELFCON_DESCRIPTION = (
    "Self-contained unit at Harmony Estate, opp DPO house, FUNAAB, Abeokuta. "
    "Private bathroom, kitchenette, wardrobe, water heater, 24/7 power backup, "
    "and gated security."
)
ROOM_PARLOUR_DESCRIPTION = (
    "One-bedroom Room & Parlour unit at Harmony Estate, opp DPO house, FUNAAB, "
    "Abeokuta. Separate bedroom and living room, private bathroom, kitchenette, "
    "24/7 power backup, and gated security."
)


class Command(BaseCommand):
    help = (
        "Seeds the FUNAAB Harmony Estate property catalog: 26 Selfcon units and "
        "14 Room & Parlour units, each as its own listable Property (one "
        "GroupBuy-able unit each). Safe to re-run - existing properties "
        "(matched by name) are left untouched."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be created without saving anything",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")
        created = 0
        skipped = 0

        def seed_batch(prefix, count, price, annual_rent, description):
            nonlocal created, skipped
            for i in range(1, count + 1):
                name = f"FUNAAB {prefix} {i:02d}"
                if Property.objects.filter(name=name).exists():
                    self.stdout.write(f"  - Skipping (already exists): {name}")
                    skipped += 1
                    continue

                self.stdout.write(
                    f"  + {'[DRY RUN] Would create' if dry_run else 'Creating'}: "
                    f"{name} - price ₦{price:,} - rent ₦{annual_rent:,}/yr"
                )
                if not dry_run:
                    Property.objects.create(
                        name=name,
                        description=description,
                        price=price,
                        rent_reward=annual_rent,
                        units_available=1,
                    )
                created += 1

        self.stdout.write("Seeding Selfcon units...")
        seed_batch(
            "Selfcon", SELFCON_COUNT, SELFCON_PRICE, SELFCON_ANNUAL_RENT, SELFCON_DESCRIPTION
        )

        self.stdout.write("\nSeeding Room & Parlour units...")
        seed_batch(
            "Room & Parlour",
            ROOM_PARLOUR_COUNT,
            ROOM_PARLOUR_PRICE,
            ROOM_PARLOUR_ANNUAL_RENT,
            ROOM_PARLOUR_DESCRIPTION,
        )

        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(
            self.style.SUCCESS(f"Done. Created: {created}, Skipped: {skipped}")
        )
        if dry_run:
            self.stdout.write(
                self.style.WARNING("This was a DRY RUN. No changes were saved.")
            )
