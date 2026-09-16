from datetime import date
from decimal import Decimal
from django.db import transaction
from django.test import TestCase
from authentication.models import CustomUser, TargetSavings, TargetSavingsCompletion, Transaction


class TargetRewardTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(email="reward@example.com", password="test", phone_number="09000000001", wallet=Decimal("100"))
        self.target = TargetSavings.objects.create(user=self.user, name="Car", target_amount=Decimal("5000"), current_amount=Decimal("5000"), end_date=date(2026, 9, 5), category="CAR")
        TargetSavings.objects.filter(pk=self.target.pk).update(start_date=date(2026, 8, 5))
        self.target.refresh_from_db()

    def complete(self):
        with transaction.atomic():
            target = TargetSavings.objects.select_for_update().get(pk=self.target.pk)
            user = CustomUser.objects.select_for_update().get(pk=self.user.pk)
            return target._complete_target(user)

    def test_late_completion_gets_bonus_and_is_idempotent(self):
        from unittest.mock import patch
        from datetime import datetime, timezone
        with patch("authentication.models.timezone.now", return_value=datetime(2026, 9, 15, tzinfo=timezone.utc)):
            self.assertTrue(self.complete())
            self.assertFalse(self.complete())
        completion = TargetSavingsCompletion.objects.get(target_savings=self.target)
        self.assertEqual(completion.bonus_amount, Decimal("62.50"))
        self.assertEqual(completion.total_amount, Decimal("5062.50"))
        self.assertFalse(completion.was_on_time)
        self.user.refresh_from_db()
        self.assertEqual(self.user.wallet, Decimal("5162.50"))
        self.assertEqual(Transaction.objects.filter(user=self.user).count(), 2)

    def test_cancelled_target_does_not_pay(self):
        TargetSavings.objects.filter(pk=self.target.pk).update(is_cancelled=True)
        self.assertFalse(self.complete())
        self.assertFalse(TargetSavingsCompletion.objects.exists())

    def test_underfunded_target_does_not_pay(self):
        TargetSavings.objects.filter(pk=self.target.pk).update(current_amount=Decimal("4999"))
        self.assertFalse(self.complete())
        self.assertFalse(TargetSavingsCompletion.objects.exists())

    def test_planned_term_not_lateness_controls_reward(self):
        self.target.end_date = date(2027, 8, 5)
        self.assertEqual(self.target.completion_bonus(), Decimal("750.00"))

    def test_rounds_to_kobo(self):
        self.assertEqual(self.target.completion_bonus(Decimal("1234")), Decimal("15.43"))

    def test_repair_dry_run_and_apply_are_safe(self):
        from django.core.management import call_command
        from io import StringIO
        TargetSavings.objects.filter(pk=self.target.pk).update(is_active=False, current_amount=0)
        completion = TargetSavingsCompletion.objects.create(user=self.user, target_savings=self.target, completed_amount=5000, total_amount=5000, completed_date=date(2026, 9, 15), was_on_time=False)
        call_command("repair_target_reward", self.target.pk, stdout=StringIO())
        self.user.refresh_from_db()
        self.assertEqual(self.user.wallet, Decimal("100"))
        call_command("repair_target_reward", self.target.pk, apply=True, stdout=StringIO())
        call_command("repair_target_reward", self.target.pk, apply=True, stdout=StringIO())
        self.user.refresh_from_db()
        completion.refresh_from_db()
        self.assertEqual(self.user.wallet, Decimal("162.50"))
        self.assertEqual(completion.total_amount, Decimal("5062.50"))
        self.assertEqual(Transaction.objects.filter(user=self.user).count(), 1)
