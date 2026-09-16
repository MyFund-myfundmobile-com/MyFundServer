from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from authentication.models import CustomUser, BankTransferRequest, InvestTransferRequest, WithdrawalsRequestToAdmin, Transaction


class MobileRequestTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.founder = CustomUser.objects.create_user(email="tolulopeahmed@gmail.com", password="test", phone_number="09000000001", is_staff=True)
        self.owner = CustomUser.objects.create_user(email="owner@example.com", password="test", phone_number="09000000002", kyc_status="submitted")
        self.client.force_authenticate(self.founder)
        self.transfer = BankTransferRequest.objects.create(user=self.owner, amount=100, transaction_id="REQUEST-TEST")
        self.tx = Transaction.objects.create(user=self.owner, transaction_id="REQUEST-TEST", transaction_type="credit", status="pending", amount=100)

    def action(self, kind, pk, action, **extra):
        return self.client.post(f"/api/admin/requests/{kind}/{pk}/action/", {"action": action, **extra}, format="json")

    def test_cx_and_regular_staff_cannot_read_or_act(self):
        for index, email in enumerate(["valueplusrecords@gmail.com", "josephgideon95@gmail.com", "company@myfundmobile.com"]):
            staff = CustomUser.objects.create_user(email=email, password="test", phone_number=f"0910000000{index}", is_staff=True)
            self.client.force_authenticate(staff)
            self.assertEqual(self.client.get("/api/admin/requests/").status_code, 403)
            self.assertEqual(self.action("quicksave", self.transfer.pk, "approve").status_code, 403)
            self.assertEqual(self.client.post("/api/admin-action/approve-bank-transfer/", {"transaction_id": "REQUEST-TEST"}).status_code, 403)

    def test_all_types_newest_first_across_statuses_and_pages(self):
        now = timezone.now()
        BankTransferRequest.objects.filter(pk=self.transfer.pk).update(created_at=now - timedelta(days=120), is_approved=True)
        CustomUser.objects.filter(pk=self.owner.pk).update(updated_at=now - timedelta(days=1))
        for index in range(22):
            InvestTransferRequest.objects.create(user=self.owner, amount=200, is_approved=True, transaction_id=f"SORT-{index}")
        for scope in ["all", "resolved", "pending"]:
            response = self.client.get("/api/admin/requests/", {"kind": "all", "scope": scope})
            self.assertEqual(response.status_code, 200)
            dates = [item["created_at"] for item in response.data["results"]]
            self.assertEqual(dates, sorted(dates, reverse=True))
        first = self.client.get("/api/admin/requests/", {"kind": "all", "scope": "all"}).data["results"]
        second = self.client.get("/api/admin/requests/", {"kind": "all", "scope": "all", "offset": 20}).data["results"]
        self.assertEqual(first[0]["kind"], "quickinvest")
        self.assertEqual(second[-1]["kind"], "quicksave")
        self.assertGreaterEqual(first[-1]["created_at"], second[0]["created_at"])

    def test_sort_preferences(self):
        old = timezone.now() - timedelta(days=90)
        BankTransferRequest.objects.filter(pk=self.transfer.pk).update(created_at=old, is_approved=True)
        InvestTransferRequest.objects.create(user=self.owner, amount=500, is_approved=True, transaction_id="SORT-HIGH")
        for sort, expected in [("newest", "quickinvest"), ("oldest", "quicksave"), ("amount_high", "quickinvest"), ("amount_low", "quicksave")]:
            response = self.client.get("/api/admin/requests/", {"kind": "all", "scope": "all", "sort": sort})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data["results"][0]["kind"], expected)
            if sort.startswith("amount"):
                self.assertEqual(response.data["results"][-1]["kind"], "kyc")
        self.assertEqual(self.client.get("/api/admin/requests/", {"sort": "invalid"}).status_code, 400)

    def test_janet_can_read(self):
        janet = CustomUser.objects.create_user(email="janet.adegbenro@gmail.com", password="test", phone_number="09200000001", is_staff=True)
        self.client.force_authenticate(janet)
        self.assertEqual(self.client.get("/api/admin/requests/").status_code, 200)

    def test_founder_email_without_staff_is_not_enough(self):
        self.founder.is_staff = False
        self.founder.save(update_fields=["is_staff"])
        self.assertEqual(self.client.get("/api/admin/requests/").status_code, 403)

    def test_queue_serializes_and_removes_abandoned_transfers(self):
        response = self.client.get("/api/admin/requests/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertIn("avatar", response.data["results"][0])
        self.assertEqual(self.action("quicksave", self.transfer.pk, "abandon").status_code, 200)
        self.assertEqual(self.client.get("/api/admin/requests/").data["count"], 0)

    @patch("authentication.request_views.approve_quicksave_credit", return_value=(True, "OK"))
    def test_deposit_uses_shared_helper_and_cannot_approve_twice(self, helper):
        self.assertEqual(self.action("quicksave", self.transfer.pk, "approve").status_code, 200)
        self.assertEqual(self.action("quicksave", self.transfer.pk, "approve").status_code, 400)
        helper.assert_called_once()

    def test_kyc_requires_rejection_reason(self):
        self.assertEqual(self.action("kyc", self.owner.pk, "reject").status_code, 400)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.kyc_status, "submitted")

    def test_scheduled_withdrawal_cannot_be_credited_early(self):
        withdrawal = WithdrawalsRequestToAdmin.objects.create(user=self.owner, amount=100, total_amount=100, transaction_id="SCHEDULED-TEST", withdrawal_type="scheduled", scheduled_processing_date=timezone.localdate() + timedelta(days=1))
        with patch("authentication.request_views.process_scheduled_withdrawal") as helper:
            self.assertEqual(self.action("withdrawal", withdrawal.pk, "credit_wallet").status_code, 400)
            helper.assert_not_called()

    def test_bank_payout_requires_explicit_confirmation(self):
        withdrawal = WithdrawalsRequestToAdmin.objects.create(user=self.owner, amount=100, transaction_id="BANK-TEST")
        self.assertEqual(self.action("withdrawal", withdrawal.pk, "confirm_paid").status_code, 400)

    def test_pushes_target_mobile_requests(self):
        from authentication.push_deep_links import DeepLinks
        links = DeepLinks()
        for payload in [links.admin_bank_transfer("TEST"), links.admin_invest_transfer("TEST"), links.admin_withdrawal(1), links.admin_kyc_submitted()]:
            self.assertEqual(payload["deep_link"]["screen_params"]["screen"], "AdminRequestsTab")

    @patch("authentication.admin.send_transactional_email")
    @patch("authentication.admin.send_push_notification")
    def test_kyc_uses_django_transition_and_records_reason(self, push, email):
        response = self.action("kyc", self.owner.pk, "reject", reason="Please upload a clearer ID.")
        self.assertEqual(response.status_code, 200)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.kyc_status, "rejected")
        self.assertEqual(self.owner.kyc_rejection_reason, "Please upload a clearer ID.")
        self.assertIsNotNone(self.owner.kyc_reviewed_at)
        email.assert_called_once()

    @patch("authentication.admin.send_transactional_email")
    @patch("authentication.admin.send_push_notification")
    @patch.object(CustomUser, "update_total_savings_and_investment_this_month")
    def test_confirm_bank_payment_uses_django_action_without_new_payout(self, metrics, push, email):
        withdrawal = WithdrawalsRequestToAdmin.objects.create(user=self.owner, amount=100, total_amount=110, transaction_id="PAID-TEST", source_account="savings")
        Transaction.objects.create(user=self.owner, transaction_id="PAID-TEST", transaction_type="debit", status="pending", amount=100)
        balance = self.owner.savings
        self.assertEqual(self.action("withdrawal", withdrawal.pk, "confirm_paid", bank_payment_confirmed=True).status_code, 200)
        self.assertEqual(self.action("withdrawal", withdrawal.pk, "confirm_paid", bank_payment_confirmed=True).status_code, 400)
        withdrawal.refresh_from_db()
        self.owner.refresh_from_db()
        self.assertEqual(withdrawal.status, "completed")
        self.assertEqual(self.owner.savings, balance)

    @patch("authentication.utils.send_generic_email")
    @patch("authentication.utils.send_push_notification")
    @patch.object(CustomUser, "update_total_savings_and_investment_this_month")
    def test_due_scheduled_withdrawal_credits_once(self, metrics, push, email):
        withdrawal = WithdrawalsRequestToAdmin.objects.create(user=self.owner, amount=100, total_amount=100, transaction_id="DUE-TEST", withdrawal_type="scheduled", scheduled_processing_date=timezone.localdate())
        balance = self.owner.wallet
        self.assertEqual(self.action("withdrawal", withdrawal.pk, "credit_wallet").status_code, 200)
        self.assertEqual(self.action("withdrawal", withdrawal.pk, "credit_wallet").status_code, 400)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.wallet, balance + 100)
