# authentication/management/commands/fix_all_stuck_withdrawals.py
from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import WithdrawalsRequestToAdmin, Transaction


class Command(BaseCommand):
    help = "Fix ALL stuck scheduled withdrawals across all users"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without actually saving",
        )
        parser.add_argument(
            "--delete-orphaned",
            action="store_true",
            help="Also delete orphaned withdrawal records (no matching transaction)",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")
        delete_orphaned = options.get("delete_orphaned")

        # Get all processed withdrawals
        withdrawals = WithdrawalsRequestToAdmin.objects.filter(is_processed=True)
        total_withdrawals = withdrawals.count()

        self.stdout.write(
            f"Found {total_withdrawals} processed withdrawal(s) across all users"
        )

        if total_withdrawals == 0:
            self.stdout.write(self.style.WARNING("No withdrawals to process"))
            return

        fixed_count = 0
        already_confirmed_count = 0
        not_found_count = 0
        deleted_count = 0

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

                # Optionally delete orphaned records
                if delete_orphaned and not dry_run:
                    w.delete()
                    deleted_count += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f"   🗑️ Deleted orphaned withdrawal: {w.transaction_id}"
                        )
                    )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"❌ Error fixing {w.transaction_id}: {e}")
                )
                not_found_count += 1

        # Summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write("SUMMARY")
        self.stdout.write("=" * 50)
        self.stdout.write(f"✅ Fixed (status changed to confirmed): {fixed_count}")
        self.stdout.write(f"✓ Already confirmed: {already_confirmed_count}")
        self.stdout.write(f"❌ Orphaned (no transaction): {not_found_count}")
        if delete_orphaned and not dry_run:
            self.stdout.write(f"🗑️ Deleted orphaned records: {deleted_count}")
        self.stdout.write(f"📊 Total processed withdrawals: {total_withdrawals}")

        if dry_run:
            self.stdout.write(
                self.style.WARNING("\n⚠️ This was a DRY RUN. No changes were saved.")
            )
            self.stdout.write("   Run without --dry-run to apply fixes.")
        else:
            self.stdout.write(self.style.SUCCESS("\n✅ Fix completed successfully!"))
