from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction

from authentication.models import CustomUser, Transaction


# The 14 scheduled-withdrawal wallet credits that fired via Celery at
# 2026-08-26 17:00-17:01 UTC, right after the queue-routing fix deployed
# (see migration 0084 / the queue="default" change on
# process_due_scheduled_withdrawals). These were already manually credited
# to the affected users earlier by an admin, so this automated run
# double-credited them. Reversing here books an explicit, auditable
# offsetting debit transaction rather than editing/deleting the original
# credit record, so the ledger keeps a full trail of both the mistaken
# double-credit and its correction.
#
# oluwatosinadediran3@gmail.com (BBU8PTZHUQ9RLXLSYVOK, N163,000) is
# deliberately excluded - their wallet balance has already dropped to
# ~N0.28 since the credit landed, so a straight reversal would take them
# to roughly -N162,999.72. That one needs an explicit decision from an
# admin (write off, recover another way, etc.) rather than an automatic
# debit into a negative balance.
CREDITS_TO_REVERSE = [
    ("MGAWDBS01X6BRYDISISI", "onipedesammy@gmail.com", Decimal("100000.00")),
    ("ZE1QWKSH5U86SZ7FCCX6", "ebunoluwaaiyeola01@gmail.com", Decimal("1000.00")),
    ("2WVO5K24WQJX6YXDINHR", "company@myfundmobile.com", Decimal("2000.00")),
    ("I8MTXDJ9COSODB75Z196", "company@myfundmobile.com", Decimal("2000.00")),
    ("MKTQLG2CN6VKBCQC7DRE", "company@myfundmobile.com", Decimal("5000.00")),
    ("ELE46TRP4NDHU1A7337Y", "company@myfundmobile.com", Decimal("2000.00")),
    ("SKDQYCPAZLDK0FJHIEQM", "company@myfundmobile.com", Decimal("2500.00")),
    ("3HBN034F533RSLAWZZ96", "company@myfundmobile.com", Decimal("1000.00")),
    ("D338E5XH0JZ0O1M2ZR25", "company@myfundmobile.com", Decimal("500.00")),
    ("FBAG4Y40CEISJK1Z8FDL", "company@myfundmobile.com", Decimal("1500.00")),
    ("SGJLDNV1N7RSED2ZNHCQ", "company@myfundmobile.com", Decimal("2000.00")),
    ("8QOW1J63TRWZINBFY0W2", "company@myfundmobile.com", Decimal("1000.00")),
    ("Y61S5C5P4A0AYQG3HXPC", "company@myfundmobile.com", Decimal("2000.00")),
]


class Command(BaseCommand):
    help = (
        "Reverses the 13 scheduled-withdrawal wallet credits that were "
        "double-paid by the 2026-08-26 17:00-17:01 UTC Celery run, after "
        "having already been manually credited earlier. Excludes "
        "oluwatosinadediran3@gmail.com's N163,000 credit on purpose - see "
        "module docstring."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without saving anything",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")
        total = Decimal("0")

        for original_tid, email, amount in CREDITS_TO_REVERSE:
            credit_tid = f"SWC-{original_tid}"
            reversal_tid = f"REV-{credit_tid}"

            original = Transaction.objects.filter(transaction_id=credit_tid).first()
            if not original:
                self.stdout.write(self.style.ERROR(f"❌ {credit_tid} not found - skipping"))
                continue

            if Transaction.objects.filter(transaction_id=reversal_tid).exists():
                self.stdout.write(self.style.WARNING(f"✓ {reversal_tid} already exists - skipping"))
                continue

            user = original.user
            if user.email != email:
                self.stdout.write(
                    self.style.ERROR(
                        f"❌ {credit_tid} user mismatch (expected {email}, found {user.email}) - skipping"
                    )
                )
                continue

            if user.wallet < amount:
                self.stdout.write(
                    self.style.ERROR(
                        f"❌ {email}: wallet ({user.wallet}) < reversal amount ({amount}) - "
                        f"would go negative, skipping. Handle manually."
                    )
                )
                continue

            if dry_run:
                self.stdout.write(
                    f"[DRY RUN] Would reverse {amount} from {email} "
                    f"(wallet {user.wallet} -> {user.wallet - amount})"
                )
                total += amount
                continue

            with transaction.atomic():
                user = CustomUser.objects.select_for_update().get(pk=user.pk)
                previous_wallet = user.wallet
                user.wallet = previous_wallet - amount
                user.save(update_fields=["wallet"])

                Transaction.objects.create(
                    user=user,
                    transaction_type="debit",
                    status="confirmed",
                    amount=amount,
                    total_amount=amount,
                    source="SCHEDULED_WITHDRAWAL",
                    credited_to="WALLET",
                    description=(
                        "Reversal of duplicate scheduled withdrawal credit "
                        "(already manually credited by admin before the "
                        "2026-08-26 automated run)"
                    ),
                    balance_before=previous_wallet,
                    balance_after=user.wallet,
                    transaction_id=reversal_tid,
                )

            self.stdout.write(
                self.style.SUCCESS(f"✅ Reversed {amount} from {email} (new wallet: {user.wallet})")
            )
            total += amount

        self.stdout.write("\n===== SUMMARY =====")
        self.stdout.write(f"{'Would reverse' if dry_run else 'Reversed'}: {total}")
        if dry_run:
            self.stdout.write(self.style.WARNING("This was a DRY RUN. No changes were saved."))
