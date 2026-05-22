from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from authentication.models import WithdrawalsRequestToAdmin, Transaction
from authentication.utils import send_push_notification


class Command(BaseCommand):
    help = "Fix ONLY overdue scheduled withdrawals (past scheduled date)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without actually saving",
        )
        parser.add_argument(
            "--user-email",
            type=str,
            help="Fix only for a specific user email",
        )

    def handle(self, *args, **options):
        dry_run = options.get("dry_run")
        user_email = options.get("user_email")

        # Get only OVERDUE withdrawals (scheduled date in past, not processed)
        today = timezone.now().date()

        overdue_withdrawals = WithdrawalsRequestToAdmin.objects.filter(
            scheduled_processing_date__lt=today,  # Past due date
            is_processed=False,  # Not processed yet
        )

        if user_email:
            overdue_withdrawals = overdue_withdrawals.filter(user__email=user_email)
            self.stdout.write(f"Filtering for user: {user_email}")

        total_overdue = overdue_withdrawals.count()
        self.stdout.write(f"Found {total_overdue} OVERDUE withdrawal(s)")

        if total_overdue == 0:
            self.stdout.write(self.style.WARNING("No overdue withdrawals to process"))
            return

        fixed_count = 0
        skipped_count = 0

        for w in overdue_withdrawals:
            self.stdout.write(f"\n--- Processing: {w.transaction_id} ---")
            self.stdout.write(f"  User: {w.user.email}")
            self.stdout.write(f"  Amount: ₦{w.total_amount}")
            self.stdout.write(
                f"  Scheduled date: {w.scheduled_processing_date} (OVERDUE)"
            )

            if dry_run:
                self.stdout.write(
                    self.style.WARNING(f"  [DRY RUN] Would fix this overdue withdrawal")
                )
                fixed_count += 1
                continue

            try:
                with transaction.atomic():
                    user = w.user
                    amount = w.total_amount

                    # Credit wallet
                    balance_before = user.wallet
                    user.wallet += amount
                    user.save()
                    balance_after = user.wallet

                    # Update or create transaction
                    try:
                        tx = Transaction.objects.get(
                            user=user, transaction_id=w.transaction_id
                        )
                        tx.status = "confirmed"
                        tx.transaction_type = "credit"
                        tx.is_processed = True
                        tx.balance_before = balance_before
                        tx.balance_after = balance_after
                        tx.description = f"Scheduled Withdrawal Credited to Wallet (Original: {w.source_account.capitalize()})"
                        tx.save()
                    except Transaction.DoesNotExist:
                        tx = Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status="confirmed",
                            is_processed=True,
                            amount=amount,
                            total_amount=amount,
                            source="WALLET",
                            credited_to="WALLET",
                            description=f"Credit Scheduled Withdrawal from {w.source_account.capitalize()}",
                            transaction_id=w.transaction_id,
                            balance_before=balance_before,
                            balance_after=balance_after,
                        )

                    # Mark withdrawal as processed
                    w.is_processed = True
                    w.is_approved = True
                    w.withdrawal_type = "immediate"
                    w.scheduled_processing_date = None
                    w.status = "completed"
                    w.save()

                    # Send notification
                    try:
                        send_push_notification(
                            user=user,
                            title="✅ Overdue Withdrawal Credited",
                            message=f"Your overdue scheduled withdrawal of ₦{amount:,.2f} has been credited to your wallet.",
                            data={"amount": str(amount), "status": "confirmed"},
                            notif_type="CREDIT",
                        )
                    except:
                        pass

                    self.stdout.write(
                        self.style.SUCCESS(f"  ✅ Fixed overdue withdrawal")
                    )
                    fixed_count += 1

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  ❌ Error: {e}"))
                skipped_count += 1

        # Summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write("OVERDUE WITHDRAWALS FIX SUMMARY")
        self.stdout.write("=" * 50)
        self.stdout.write(f"✅ Fixed: {fixed_count}")
        self.stdout.write(f"❌ Skipped/Error: {skipped_count}")
        self.stdout.write(f"📊 Total overdue found: {total_overdue}")

        if dry_run:
            self.stdout.write(
                self.style.WARNING("\n⚠️ This was a DRY RUN. No changes were saved.")
            )
