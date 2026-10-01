from datetime import date
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from .models import CustomUser, ROITransaction, Transaction
from .tasks import apply_withholding_tax, release_quarterly_roi

# Freeze "today" to the Oct 1 2026 run so get_previous_quarter() -> Q3 2026.
FROZEN_TODAY = date(2026, 10, 1)


class _FrozenDate(date):
    @classmethod
    def today(cls):
        return FROZEN_TODAY


def make_user(email, wallet, roi=Decimal("1000.00"), paid=False):
    user = CustomUser.objects.create_user(
        email=email,
        password="x",
        first_name="T",
        last_name="U",
        phone_number=email[:11],
    )
    user.wallet = wallet
    user.save(update_fields=["wallet"])
    ROITransaction.objects.create(
        user=user, amount=roi, roi_type="SAVINGS", accrued_date=date(2026, 8, 15),
        is_paid_out=paid,
    )
    return user


@patch("authentication.tasks.date", _FrozenDate)
class ApplyWithholdingTaxTest(TestCase):
    """Catch-up run for a quarter that was already paid out gross."""

    def test_full_balance_is_charged(self):
        user = make_user("full@example.com", Decimal("5000.00"), paid=True)
        result = apply_withholding_tax(test_mode=False)
        user.refresh_from_db()
        self.assertEqual(result["quarter"], "Q3 2026")
        self.assertEqual(user.wallet, Decimal("4900.00"))
        self.assertEqual(result["shortfalls"], [])

    def test_low_balance_charges_what_is_left_and_reports_rest(self):
        user = make_user("low@example.com", Decimal("30.00"), paid=True)
        result = apply_withholding_tax(test_mode=False)
        user.refresh_from_db()
        self.assertEqual(user.wallet, Decimal("0.00"))
        self.assertEqual(result["total_shortfall"], "70.00")
        self.assertEqual(result["shortfalls"][0]["charged"], "30.00")

    def test_dry_run_writes_nothing(self):
        user = make_user("dry@example.com", Decimal("5000.00"), paid=True)
        result = apply_withholding_tax(test_mode=False, dry_run=True)
        user.refresh_from_db()
        self.assertEqual(user.wallet, Decimal("5000.00"))
        self.assertEqual(result["total_charged"], "100.00")
        self.assertFalse(Transaction.objects.filter(description__startswith="WHT|").exists())

    def test_second_run_is_a_no_op(self):
        user = make_user("twice@example.com", Decimal("5000.00"), paid=True)
        apply_withholding_tax(test_mode=False)
        result = apply_withholding_tax(test_mode=False)
        user.refresh_from_db()
        self.assertEqual(user.wallet, Decimal("4900.00"))
        self.assertEqual(result["processed"], 0)


@patch("authentication.tasks.send_generic_email")
@patch("authentication.tasks.send_push_notification")
@patch("authentication.tasks.date", _FrozenDate)
class ReleaseQuarterlyRoiWhtTest(TestCase):
    """From Jan 2027 the payout itself deducts WHT."""

    @patch("authentication.utils.send_push_notification", create=True)
    def test_payout_credits_net_and_records_wht(self, *_):
        user = make_user("payout@example.com", Decimal("0.00"))
        release_quarterly_roi(test_mode=False)
        user.refresh_from_db()
        self.assertEqual(user.wallet, Decimal("900.00"))
        self.assertTrue(
            Transaction.objects.filter(user=user, description="WHT|Q3 2026|10%").exists()
        )
        # A later catch-up run must not charge WHT a second time.
        apply_withholding_tax(test_mode=False)
        user.refresh_from_db()
        self.assertEqual(user.wallet, Decimal("900.00"))
