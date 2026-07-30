from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import WithdrawalsRequestToAdmin, Transaction


class Command(BaseCommand):
    help = "Fix scheduled withdrawals that are processed but transactions not confirmed"

    def add_arguments(self, parser):
        parser.add_argument(
            "--user-email",
            type=str,
            help="Fix only for a specific user email",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without actually saving",
        )

    def handle(self, *args, **options):
        user_email = options.get("user_email")
        dry_run = options.get("dry_run")

        withdrawals = WithdrawalsRequestToAdmin.objects.filter(is_processed=True)

        if user_email:
            withdrawals = withdrawals.filter(user__email=user_email)
            self.stdout.write(f"Filtering for user: {user_email}")

        total_withdrawals = withdrawals.count()
        self.stdout.write(f"Found {total_withdrawals} processed withdrawal(s)")

        if total_withdrawals == 0:
            self.stdout.write(self.style.WARNING("No withdrawals to process"))
            return

        fixed_count = 0
        already_confirmed_count = 0
        not_found_count = 0

        for w in withdrawals:
            try:
                with transaction.atomic():
                    tx = Transaction.objects.get(
                        user=w.user, transaction_id=w.transaction_id
                    )

                    if tx.status != "confirmed":
                        if dry_run:
                            self.stdout.write(
                                f"[DRY RUN] Would fix: {tx.transaction_id} - user: {w.user.email}"
                            )
                            fixed_count += 1
                        else:
                            tx.status = "confirmed"
                            tx.save()
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"✅ Fixed: {tx.transaction_id} - user: {w.user.email}"
                                )
                            )
                            fixed_count += 1
                    else:
                        self.stdout.write(
                            f"✓ Already confirmed: {tx.transaction_id} - user: {w.user.email}"
                        )
                        already_confirmed_count += 1

            except Transaction.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(
                        f"❌ Transaction not found: {w.transaction_id} - user: {w.user.email}"
                    )
                )
                not_found_count += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"❌ Error fixing {w.transaction_id}: {e}")
                )
                not_found_count += 1

        self.stdout.write("\n===== SUMMARY =====")
        self.stdout.write(f"✅ Fixed: {fixed_count} transaction(s)")
        self.stdout.write(
            f"✓ Already confirmed: {already_confirmed_count} transaction(s)"
        )
        self.stdout.write(f"❌ Not found/Error: {not_found_count} transaction(s)")
        self.stdout.write(f"Total processed withdrawals: {total_withdrawals}")

        if dry_run:
            self.stdout.write(
                self.style.WARNING("\n⚠️ This was a DRY RUN. No changes were saved.")
            )
        else:
            self.stdout.write(self.style.SUCCESS("\n✅ Fix completed successfully!"))
