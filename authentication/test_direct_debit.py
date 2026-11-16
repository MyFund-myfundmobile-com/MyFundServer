"""AutoSave from a bank account (Paystack Direct Debit) - see direct_debit.py.
Paystack is mocked; nothing here touches the network."""
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .direct_debit_models import BankMandate
from .models import AutoSave, BankAccount, Card, CustomUser, Transaction

BANKS = [{"code": "999992", "name": "OPay Digital Services Limited (OPay)"},
         {"code": "057", "name": "Zenith Bank"}]


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body, self.status_code = body, status_code
        self.ok = status_code < 400
        self.content = b"x"
        self.text = str(body)

    def json(self):
        return self._body

    def raise_for_status(self):
        if not self.ok:
            import requests
            raise requests.HTTPError(str(self.status_code))


SENT = []


def fake_post(url, json=None, **kw):
    SENT.append((url, json))
    if url.endswith("/transaction/initialize"):
        return FakeResponse({"status": True, "data": {
            "authorization_url": "https://checkout.paystack.com/abc123",
            "access_code": "abc123", "reference": json["reference"]}})
    if url.endswith("/customer/authorization/initialize"):
        return FakeResponse({"status": True, "data": {
            "reference": json["reference"], "mandate": {"id": 3315722, "status": "pending"},
            "transferDetails": {"amount": "50.00", "account_number": "9880218357",
                                "account_name": "NIBSS DIRECT DEBIT", "bank_name": "Paystack-Titan"},
            "status": "pending_bank_transfer"}})
    if url.endswith("/plan"):
        return FakeResponse({"status": True, "data": {"plan_code": "PLN_bank1"}})
    if url.endswith("/subscription"):
        return FakeResponse({"status": True, "data": {"id": 77, "subscription_code": "SUB_x",
                                                      "email_token": "tok", "reference": "ref1"}})
    if url.endswith("/transaction/charge_authorization"):
        return FakeResponse({"status": True, "data": {"status": "processing", "reference": json["reference"]}})
    if url.endswith("/customer/authorization/deactivate"):
        return FakeResponse({"status": True})
    if url.endswith("/subscription/disable"):
        return FakeResponse({"status": True})
    raise AssertionError(f"unexpected POST {url}")


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
@mock.patch("authentication.direct_debit.send_push_notification")
@mock.patch("authentication.direct_debit.send_transactional_email")
@mock.patch("authentication.direct_debit.supported_banks", return_value=BANKS)
@mock.patch("authentication.direct_debit.requests.post", side_effect=fake_post)
@mock.patch.dict("os.environ", {"DIRECT_DEBIT_MODE": "on"})
class DirectDebitTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = CustomUser.objects.create_user(
            email="saver@example.com", phone_number="08000000001", password="x",
            first_name="Ada", last_name="Obi")
        self.opay = BankAccount.objects.create(user=self.user, bank_name="OPay", account_number="8123454821",
                                               account_name="ADA OBI", bank_code="999992")
        self.gtb = BankAccount.objects.create(user=self.user, bank_name="Guaranty Trust Bank",
                                              account_number="0123456789", account_name="ADA OBI",
                                              bank_code="058")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def start(self, **over):
        body = {"bank_account_id": self.opay.id, "amount": "5,000", "frequency": "weekly",
                "street": "1 Allen Avenue", "city": "Ikeja", "state": "Lagos", **over}
        return self.client.post("/api/direct-debit/autosave/", body, format="json")

    def test_hidden_when_off(self, *_):
        with mock.patch.dict("os.environ", {"DIRECT_DEBIT_MODE": "off"}):
            self.assertEqual(self.client.get("/api/direct-debit/").data, {"enabled": False})
            self.assertEqual(self.start().status_code, 403)

    def test_staff_mode_is_team_only(self, *_):
        with mock.patch.dict("os.environ", {"DIRECT_DEBIT_MODE": "staff"}):
            self.assertFalse(self.client.get("/api/direct-debit/").data["enabled"])
            CustomUser.objects.filter(pk=self.user.pk).update(is_staff=True)
            self.user.refresh_from_db()
            self.client.force_authenticate(self.user)
            self.assertTrue(self.client.get("/api/direct-debit/").data["enabled"])

    def test_overview_marks_supported_accounts(self, *_):
        accounts = {a["bank_name"]: a["supported"] for a in self.client.get("/api/direct-debit/").data["accounts"]}
        self.assertEqual(accounts, {"OPay": True, "Guaranty Trust Bank": False})

    def test_unsupported_bank_and_hourly_refused(self, *_):
        self.assertEqual(self.start(bank_account_id=self.gtb.id).status_code, 400)
        self.assertEqual(self.start(frequency="hourly").status_code, 400)
        self.assertEqual(self.start(amount="100").status_code, 400)
        self.assertFalse(BankMandate.objects.exists())

    def test_link_opens_bank_checkout_with_recurring_filter(self, *_):
        SENT.clear()
        res = self.start()
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["authorization_url"], "https://checkout.paystack.com/abc123")
        url, body = SENT[-1]
        self.assertTrue(url.endswith("/transaction/initialize"))
        self.assertEqual(body["channels"], ["bank"])
        self.assertEqual(body["metadata"]["custom_filters"], {"recurring": True})
        self.assertEqual(body["amount"], 10000)
        m = BankMandate.objects.get()
        self.assertEqual((m.pending_amount, m.status, m.reference), (5000, "pending", body["reference"]))
        self.assertEqual(res.data["mandate"]["checkout_url"], "https://checkout.paystack.com/abc123")
        tx = Transaction.objects.get(transaction_id=body["reference"])
        self.assertEqual((tx.amount, tx.status, tx.description), (100, "pending", "QuickSave (Bank setup)"))

    def test_abandoned_checkout_is_replaced_but_approved_one_kept(self, *_):
        self.start()
        self.start(amount="7000", frequency="monthly")
        self.assertEqual(BankMandate.objects.filter(status="pending").count(), 1)
        self.assertEqual(BankMandate.objects.filter(status="inactive").count(), 1)
        m = BankMandate.objects.get(status="pending")
        m.authorization_code = "AUTH_dd1"
        m.save()
        again = self.start(amount="9000", frequency="daily")
        self.assertEqual(again.status_code, 200)
        m.refresh_from_db()
        self.assertEqual((m.pending_amount, m.pending_frequency), (9000, "daily"))
        self.assertEqual(BankMandate.objects.filter(status="pending").count(), 1)

    def webhook(self, name, **data):
        from .views import paystack_webhook_processing
        with mock.patch("authentication.views.send_transactional_email"):
            paystack_webhook_processing({"event": name, "data": data}, "1.1.1.1", True, {})

    def test_checkout_payment_then_active_mandate_starts_autosave(self, *_):
        ref = self.start().data["mandate"]
        m = BankMandate.objects.get()
        cust = {"email": self.user.email}
        # The N100 at Checkout is credited to savings; no card is saved.
        with mock.patch("authentication.views.send_push_notification"):
            self.webhook("charge.success", reference=m.reference, channel="bank", amount=10000,
                         customer=cust, authorization={"authorization_code": "AUTH_dd1",
                                                       "channel": "direct_debit", "last4": "4821"})
        tx = Transaction.objects.get(transaction_id=m.reference)
        self.user.refresh_from_db()
        self.assertEqual((tx.status, tx.description, self.user.savings), ("confirmed", "QuickSave (Bank setup)", 100))
        self.assertFalse(Card.all_objects.filter(user=self.user).exists())
        m.refresh_from_db()
        self.assertEqual(m.authorization_code, "AUTH_dd1")
        self.assertFalse(AutoSave.objects.exists())
        # Bank confirms: AutoSave starts, with no second N100 debit.
        self.webhook("direct_debit.authorization.active", authorization_code="AUTH_dd1",
                     active=True, customer=cust)
        m.refresh_from_db()
        self.assertEqual(m.status, "active")
        auto = AutoSave.objects.get()
        self.assertEqual((auto.mandate_id, auto.amount, auto.frequency), (m.id, 5000, "weekly"))
        self.assertFalse(Transaction.objects.filter(description="QuickSave (Bank verification)").exists())
        self.webhook("direct_debit.authorization.active", authorization_code="AUTH_dd1", customer=cust)
        self.assertEqual(AutoSave.objects.count(), 1)

    def test_checkout_with_another_account_records_that_account(self, *_):
        self.start()
        cust = {"email": self.user.email}
        self.webhook("direct_debit.authorization.created", authorization_code="AUTH_dd2", active=False,
                     last4="7777", bank="Access Bank", account_name="ADA OBI", customer=cust)
        m = BankMandate.objects.get()
        self.assertEqual((m.authorization_code, m.bank_name, m.account_number[-4:], m.bank_account_id),
                         ("AUTH_dd2", "Access Bank", "7777", None))

    def test_linked_account_starts_immediately(self, *_):
        BankMandate.objects.create(user=self.user, bank_account=self.opay, bank_name="OPay",
                                   bank_code="999992", account_number="8123454821", reference="r1",
                                   status="active", authorization_code="AUTH_dd1")
        res = self.start(frequency="daily")
        self.assertEqual(res.data["status"], "active")
        self.assertEqual(AutoSave.objects.get().frequency, "daily")

    def test_bank_debit_is_credited_but_never_saved_as_card(self, *_):
        m = BankMandate.objects.create(user=self.user, bank_account=self.opay, bank_name="OPay",
                                       bank_code="999992", account_number="8123454821", reference="r1",
                                       status="active", authorization_code="AUTH_dd1")
        AutoSave.objects.create(user=self.user, frequency="weekly", amount=5000, active=True,
                                mandate=m, paystack_plan_code="PLN_bank1")
        auth = {"authorization_code": "AUTH_dd1", "channel": "direct_debit", "reusable": True,
                "bank": "OPay", "card_type": None}
        charge = dict(reference="dd-charge-1", channel="direct_debit", amount=500000,
                      customer={"email": self.user.email}, authorization=auth,
                      plan={"plan_code": "PLN_bank1"})
        with mock.patch("authentication.views.send_push_notification"):
            self.webhook("charge.success", **charge)
        tx = Transaction.objects.get(user=self.user)
        self.assertEqual((tx.amount, tx.source_channel, tx.status), (5000, "direct_debit", "confirmed"))
        self.assertFalse(Card.all_objects.filter(user=self.user).exists())

    def test_bank_charge_without_plan_is_not_credited(self, *_):
        charge = dict(reference="dd-check", channel="direct_debit", amount=5000,
                      customer={"email": self.user.email},
                      authorization={"authorization_code": "AUTH_dd1", "channel": "direct_debit"})
        self.webhook("charge.success", **charge)
        self.assertFalse(Transaction.objects.filter(user=self.user).exists())
        self.assertFalse(Card.all_objects.filter(user=self.user).exists())

    def test_unlink_stops_autosave_and_mandate(self, *_):
        m = BankMandate.objects.create(user=self.user, bank_account=self.opay, bank_name="OPay",
                                       bank_code="999992", account_number="8123454821", reference="r1",
                                       status="active", authorization_code="AUTH_dd1")
        AutoSave.objects.create(user=self.user, frequency="weekly", amount=5000, active=True, mandate=m,
                                paystack_sub_code="SUB_x", paystack_sub_token="tok")
        with mock.patch("authentication.views.send_transactional_email"), \
                mock.patch("authentication.views.send_push_notification"), \
                mock.patch("authentication.views.requests.post", side_effect=fake_post):
            res = self.client.post(f"/api/direct-debit/mandates/{m.id}/cancel/")
        self.assertEqual(res.status_code, 200, res.data)
        m.refresh_from_db()
        self.assertEqual(m.status, "inactive")
        self.assertFalse(AutoSave.objects.filter(active=True).exists())
