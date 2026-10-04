from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from .models import CustomUser, Transaction, WithdrawalsRequestToAdmin
from .views import paystack_webhook_processing

REF = "withdrawal-y3d14gjjay6gkpkd3_n2"


def failed_event(kind="transfer.failed"):
    return {"event": kind, "data": {
        "amount": 242000, "reason": "Could not credit account", "transfer_code": "TRF_test123",
        "reference": REF, "recipient": {"details": {"account_number": "0000000959", "bank_code": "221"}},
    }}


@patch("authentication.views.send_push_notification")
@patch("authentication.views.send_transactional_email")
@patch("authentication.utils.send_push_notification")
@patch("authentication.utils.send_transactional_email")
class FailedWithdrawalRefundTest(TestCase):
    """A transfer Paystack accepted but later failed is refunded to the
    balance it came from - exactly once, and never if already paid by hand."""

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email="saver@example.com", password="x", first_name="Mary",
            last_name="O", phone_number="08030000099",
        )
        self.user.wallet = Decimal("0.23")
        self.user.save(update_fields=["wallet"])
        Transaction.objects.create(
            user=self.user, transaction_type="debit", status="confirmed", amount=Decimal("2420"),
            service_charge=Decimal("0"), source="WALLET", description="Wallet > Bank . . .",
            transaction_id=REF, balance_before=Decimal("2420.23"), balance_after=Decimal("0.23"),
        )
        WithdrawalsRequestToAdmin.objects.create(user=self.user, amount=Decimal("2420"), transaction_id="TRF_test123")

    def run_webhook(self, kind="transfer.failed"):
        with self.captureOnCommitCallbacks(execute=True):
            paystack_webhook_processing(failed_event(kind), "1.2.3.4", True, {})
        self.user.refresh_from_db()

    def test_failed_transfer_refunds_wallet_once_and_closes_request(self, *_):
        self.run_webhook()
        self.assertEqual(self.user.wallet, Decimal("2420.23"))
        self.assertEqual(Transaction.objects.get(transaction_id=REF).status, "failed")
        self.assertTrue(Transaction.objects.filter(transaction_id=f"refund-{REF}").exists())
        self.assertEqual(WithdrawalsRequestToAdmin.objects.get(transaction_id="TRF_test123").status, "cancelled")

        self.run_webhook()  # Paystack retries webhooks - must not refund twice
        self.run_webhook("transfer.reversed")
        self.assertEqual(self.user.wallet, Decimal("2420.23"))
        self.assertEqual(Transaction.objects.filter(transaction_id__startswith="refund-").count(), 1)

    def test_no_refund_when_admin_already_paid_it_out(self, *_):
        WithdrawalsRequestToAdmin.objects.filter(transaction_id="TRF_test123").update(status="completed")
        self.run_webhook()
        self.assertEqual(self.user.wallet, Decimal("0.23"))
        self.assertFalse(Transaction.objects.filter(transaction_id=f"refund-{REF}").exists())

    def test_refund_includes_service_charge_and_goes_back_to_savings(self, *_):
        Transaction.objects.filter(transaction_id=REF).update(
            source="SAVINGS", amount=Decimal("9000"), service_charge=Decimal("1000"),
            balance_before=Decimal("15000"), balance_after=Decimal("5000"),
        )
        self.user.savings = Decimal("5000")
        self.user.save(update_fields=["savings"])
        self.run_webhook()
        self.assertEqual(self.user.savings, Decimal("15000"))
        self.assertEqual(self.user.wallet, Decimal("0.23"))
