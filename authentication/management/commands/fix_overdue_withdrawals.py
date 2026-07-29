from django.core.management.base import BaseCommand
from django.utils import timezone
from authentication.models import WithdrawalsRequestToAdmin
from authentication.utils import process_scheduled_withdrawal


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
                # Delegate to the single source-of-truth crediting function
                # instead of duplicating it inline - that inline version
                # had no select_for_update() locking (a real race risk
                # against the Celery task picking up the same row
                # concurrently) and mutated the original *debit*
                # Transaction into a credit record in place, destroying the
                # debit history, instead of creating a separate SWC-{id}
                # credit row the way every other path does.
                result = process_scheduled_withdrawal(w, triggered_by="management_command")

                if result in ("processed", "already_credited"):
                    self.stdout.write(
                        self.style.SUCCESS(f"  ✅ {result}: {w.transaction_id}")
                    )
                    fixed_count += 1
                else:
                    self.stdout.write(
                        self.style.WARNING(f"  ⚠️ {result}: {w.transaction_id}")
                    )
                    skipped_count += 1

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
