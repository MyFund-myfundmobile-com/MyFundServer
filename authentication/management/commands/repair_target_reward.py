from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from authentication.models import CustomUser, TargetSavings, TargetSavingsCompletion, Transaction


class Command(BaseCommand):
    help = "Preview a missing late-completion reward; use --apply to credit only the reward, never the principal."

    def add_arguments(self, parser):
        parser.add_argument("target_id", type=int)
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        with transaction.atomic():
            try:
                target = TargetSavings.objects.select_for_update().get(pk=options["target_id"])
                completion = TargetSavingsCompletion.objects.select_for_update().get(target_savings=target)
            except (TargetSavings.DoesNotExist, TargetSavingsCompletion.DoesNotExist):
                raise CommandError("Target or completion record not found.")
            if target.is_active or target.is_cancelled or completion.status != "SUCCESS" or completion.completed_amount < target.target_amount:
                raise CommandError("Only fully funded, successful closed targets qualify.")
            if completion.was_on_time or completion.completed_date <= target.end_date:
                raise CommandError("This tool is restricted to missing late-completion rewards.")
            if completion.bonus_amount != 0:
                self.stdout.write("Already has a reward; no changes made.")
                return
            bonus = target.completion_bonus(completion.completed_amount)
            self.stdout.write(f"Target {target.pk}: missing reward ₦{bonus:,.2f}; principal will not be credited again.")
            if not options["apply"]:
                self.stdout.write("DRY RUN: no changes made. Review before using --apply.")
                return
            user = CustomUser.objects.select_for_update().get(pk=completion.user_id)
            credit_id = f"TARGET-{target.pk}-LATE-REWARD-REPAIR"
            if Transaction.objects.filter(transaction_id=credit_id).exists():
                raise CommandError("Repair credit already exists; review the completion record manually.")
            user.wallet += bonus
            user.save(update_fields=["wallet"])
            completion.bonus_amount = bonus
            completion.total_amount = completion.completed_amount + bonus
            completion.save(update_fields=["bonus_amount", "total_amount"])
            Transaction.objects.create(user=user, transaction_type="credit", status="confirmed", amount=bonus, total_amount=bonus, service_charge=0, source="WALLET", description=f"{target.name} completion reward correction", transaction_id=credit_id)
            self.stdout.write(self.style.SUCCESS(f"Credited reward only: ₦{bonus:,.2f}."))
