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
    """A failed MONTHLY deduction must wait for next_retry (5 days), not be
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
        self.assertGreater(target.next_retry, timezone.now() + timedelta(days=4))
