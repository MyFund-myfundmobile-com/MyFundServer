from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from .models import CustomUser, Employee, PayrollEntry, Transaction
from .payroll import create_draft_entries, send_pending_entries


@patch("authentication.payroll.send_push_notification")
@patch("authentication.payroll.send_generic_email")
class PayrollDoublePayTest(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email="staff@example.com", password="x", first_name="S",
            last_name="T", phone_number="08000000000",
        )
        self.emp = Employee.objects.create(
            name="Staff", email="staff@example.com", monthly_amount=Decimal("10000.00")
        )

    def _credits(self):
        return Transaction.objects.filter(
            user=self.user, transaction_type="credit", description="October 2026 Allowance"
        ).count()

    def test_sending_live_twice_pays_once(self, *_):
        run = create_draft_entries(Employee.objects.all(), "October 2026")
        send_pending_entries(run.entries.all(), test=False)
        send_pending_entries(run.entries.all(), test=False)
        self.user.refresh_from_db()
        self.assertEqual(self._credits(), 1)
        self.assertEqual(self.user.wallet, Decimal("10000.00"))

    def test_repeat_pay_click_does_not_create_second_entry(self, *_):
        run1 = create_draft_entries(Employee.objects.all(), "October 2026")
        send_pending_entries(run1.entries.all(), test=False)
        run2 = create_draft_entries(Employee.objects.all(), "October 2026")
        self.assertEqual(run2.entries.count(), 0)
        self.assertEqual(self._credits(), 1)

    def test_test_send_does_not_credit(self, *_):
        run = create_draft_entries(Employee.objects.all(), "October 2026")
        send_pending_entries(run.entries.all(), test=True)
        self.user.refresh_from_db()
        self.assertEqual(self._credits(), 0)
        self.assertEqual(PayrollEntry.objects.get().status, "test_run")
