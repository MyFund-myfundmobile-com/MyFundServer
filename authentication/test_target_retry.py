from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from .models import CustomUser, TargetSavings
from .tasks import process_target_savings_deductions


@patch("authentication.models.TargetSavings.send_failed_deduction_email", lambda *a, **k: None)
@patch("authentication.utils.send_push_notification", lambda *a, **k: {})
class HourlySweepRespectsRetryScheduleTest(TestCase):
    """A failed MONTHLY deduction must wait for next_retry (4 days), not be
    retried by every hourly sweep until the plan is cancelled (target 612,
    Sep 30 2026: 4 attempts in ~4 hours, then a 1% refund charge)."""

    def test_failed_deduction_is_not_retried_on_the_next_hourly_run(self):
        user = CustomUser.objects.create_user(
            email="saver@example.com", password="x", first_name="S",
            last_name="V", phone_number="08000000001",
        )
        target = TargetSavings.objects.create(
            user=user, name="My Life", target_amount=Decimal("300000"),
            current_amount=Decimal("50000"), end_date=date(2027, 1, 31),
            monthly_payment=Decimal("50000"), funding_source="SAVINGS",
            frequency="MONTHLY", next_deduction=timezone.now() - timedelta(minutes=5),
        )

        for _ in range(4):  # four hourly sweeps, no funds in savings
            with self.captureOnCommitCallbacks(execute=True):
                process_target_savings_deductions()

        target.refresh_from_db()
        self.assertEqual(target.deduction_attempts, 1)
        self.assertTrue(target.is_active)
        self.assertFalse(target.is_cancelled)
        self.assertEqual(target.current_amount, Decimal("50000"))
        self.assertGreater(target.next_retry, timezone.now() + timedelta(days=3, hours=23))


@patch("authentication.models.TargetSavings.send_failed_deduction_email", lambda *a, **k: None)
@patch("authentication.utils.send_push_notification", lambda *a, **k: {})
class RetryScheduleAndRetryNowTest(TestCase):
    def setUp(self):
        from rest_framework.test import APIClient

        self.user = CustomUser.objects.create_user(
            email="retry@example.com", password="x", first_name="R",
            last_name="N", phone_number="08000000002",
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def make_target(self, frequency="MONTHLY", attempts=1):
        return TargetSavings.objects.create(
            user=self.user, name="Plan", target_amount=Decimal("300000"),
            current_amount=Decimal("50000"), end_date=date(2027, 1, 31),
            monthly_payment=Decimal("50000"), funding_source="SAVINGS",
            frequency=frequency, deduction_attempts=attempts,
            next_deduction=timezone.now() - timedelta(days=1),
            next_retry=timezone.now() + timedelta(days=3),
        )

    def test_retry_intervals(self):
        for frequency, gap in [("DAILY", timedelta(hours=4)), ("WEEKLY", timedelta(days=2)), ("MONTHLY", timedelta(days=4))]:
            target = self.make_target(frequency)
            before = timezone.now()
            target.schedule_retry()
            self.assertAlmostEqual((target.next_retry - before).total_seconds(), gap.total_seconds(), delta=5)

    def test_retry_now_without_enough_funds_does_not_use_up_a_retry(self):
        target = self.make_target()
        res = self.client.post(f"/api/target-savings/{target.id}/retry/")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.data["required_amount"], "50000.00")
        target.refresh_from_db()
        self.assertEqual(target.deduction_attempts, 1)

    def test_retry_now_after_top_up_saves_and_clears_retry(self):
        target = self.make_target()
        self.user.savings = Decimal("60000")
        self.user.save(update_fields=["savings"])
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(f"/api/target-savings/{target.id}/retry/")
        self.assertEqual(res.status_code, 200, res.data)
        target.refresh_from_db(); self.user.refresh_from_db()
        self.assertEqual(target.current_amount, Decimal("100000"))
        self.assertEqual(target.deduction_attempts, 0)
        self.assertIsNone(target.next_retry)
        self.assertEqual(self.user.savings, Decimal("10000"))
        self.assertEqual(res.data["target"]["deduction_attempts"], 0)

    def test_retry_now_rejects_plans_not_in_retry_and_other_users_plans(self):
        healthy = self.make_target(attempts=0)
        self.assertEqual(self.client.post(f"/api/target-savings/{healthy.id}/retry/").status_code, 400)
        other = CustomUser.objects.create_user(
            email="other@example.com", password="x", first_name="O",
            last_name="U", phone_number="08000000003",
        )
        theirs = TargetSavings.objects.create(
            user=other, name="Theirs", target_amount=Decimal("1000"), end_date=date(2027, 1, 31),
            monthly_payment=Decimal("100"), funding_source="SAVINGS", frequency="DAILY", deduction_attempts=1,
        )
        self.assertEqual(self.client.post(f"/api/target-savings/{theirs.id}/retry/").status_code, 404)
