"""
Tests for the Admin Transactions Management endpoints
(authentication/admin_views.py: all_transactions_list, admin_transactions_summary).
"""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from rest_framework import status
from rest_framework.test import APIClient

from .models import CustomUser, Transaction


def _make_user(email, phone, **extra):
    extra.setdefault("first_name", "Test")
    extra.setdefault("last_name", "User")
    return CustomUser.objects.create_user(
        email=email,
        password="testpass123",
        phone_number=phone,
        **extra,
    )


def _make_transaction(user, **extra):
    extra.setdefault("transaction_type", "credit")
    extra.setdefault("status", "confirmed")
    extra.setdefault("amount", 1000)
    return Transaction.objects.create(user=user, **extra)


class AdminTransactionsPermissionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.regular_user = _make_user("txnregular@example.com", "95000000001")

    def test_non_staff_rejected(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(reverse("admin_all_transactions_list"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class AdminTransactionsListTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("txnstaff@example.com", "95000000002", is_staff=True)
        self.client.force_authenticate(user=self.staff)

        self.jane = _make_user(
            "jane.txn@example.com", "95000000003", first_name="Jane", last_name="Txn"
        )
        self.john = _make_user(
            "john.txn@example.com", "95000000004", first_name="John", last_name="Txn"
        )

        self.credit_confirmed = _make_transaction(
            self.jane,
            transaction_type="credit",
            status="confirmed",
            source="WALLET",
            credited_to="SAVINGS",
            amount=5000,
            description="Wallet top-up",
        )
        self.debit_pending = _make_transaction(
            self.john,
            transaction_type="debit",
            status="pending",
            source="SAVINGS",
            amount=2000,
            description="Withdrawal request",
        )

    def test_search_matches_user_name_email_and_description(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"), {"search": "Jane"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [t["id"] for t in response.data["data"]]
        self.assertEqual(ids, [self.credit_confirmed.id])

        response = self.client.get(
            reverse("admin_all_transactions_list"), {"search": "Withdrawal"}
        )
        ids = [t["id"] for t in response.data["data"]]
        self.assertEqual(ids, [self.debit_pending.id])

    def test_transaction_type_filter(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"), {"transaction_type": "debit"}
        )
        ids = [t["id"] for t in response.data["data"]]
        self.assertEqual(ids, [self.debit_pending.id])

    def test_status_filter(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"), {"status": "confirmed"}
        )
        ids = [t["id"] for t in response.data["data"]]
        self.assertEqual(ids, [self.credit_confirmed.id])

    def test_credited_to_filter(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"), {"credited_to": "SAVINGS"}
        )
        ids = [t["id"] for t in response.data["data"]]
        self.assertEqual(ids, [self.credit_confirmed.id])

    def test_pagination(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"), {"page": 1, "limit": 1}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["total_count"], 2)
        self.assertEqual(response.data["total_pages"], 2)

    def test_user_identity_nested_in_response(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"), {"search": "Jane"}
        )
        row = response.data["data"][0]
        self.assertEqual(row["user_email"], "jane.txn@example.com")
        self.assertEqual(row["user_name"], "Jane Txn")

    def test_invalid_page_and_limit_dont_500(self):
        response = self.client.get(
            reverse("admin_all_transactions_list"),
            {"page": "not-a-number", "limit": "9999"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["page"], 1)
        self.assertEqual(response.data["limit"], 200)


def _set_transaction_date(transaction, when):
    # date is auto_now_add=True, so it can't be set via .create() /
    # .save() - bypass it with a direct queryset update, same trick used
    # elsewhere in this codebase for backdating test fixtures.
    Transaction.objects.filter(pk=transaction.pk).update(date=when)
    transaction.refresh_from_db()


class AdminTransactionsSummaryTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("txnsummarystaff@example.com", "95000000005", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.user = _make_user("txnsummaryuser@example.com", "95000000006")

        now = timezone.now()

        # Confirmed, today - should count in every range.
        self.credit_today = _make_transaction(
            self.user, transaction_type="credit", status="confirmed", amount=5000,
        )
        self.debit_today = _make_transaction(
            self.user, transaction_type="debit", status="confirmed", amount=2000,
        )

        # Confirmed, but 2 months back - excluded from "today"/"month",
        # included from "3months" onward.
        self.credit_2mo = _make_transaction(
            self.user, transaction_type="credit", status="confirmed", amount=1000,
        )
        _set_transaction_date(self.credit_2mo, now - relativedelta(months=2))

        # Confirmed, but over a year back - only "all" should include it.
        self.credit_2yr = _make_transaction(
            self.user, transaction_type="credit", status="confirmed", amount=7000,
        )
        _set_transaction_date(self.credit_2yr, now - relativedelta(years=2))

        # Pending today - must never count, regardless of range.
        self.pending_today = _make_transaction(
            self.user, transaction_type="credit", status="pending", amount=999999,
        )

    def test_non_staff_rejected(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(reverse("admin_transactions_summary"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_today_range_excludes_older_and_pending(self):
        response = self.client.get(
            reverse("admin_transactions_summary"), {"range": "today"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_credits"], 5000)
        self.assertEqual(response.data["total_debits"], 2000)
        self.assertEqual(response.data["net"], 3000)
        self.assertEqual(response.data["credit_count"], 1)
        self.assertEqual(response.data["debit_count"], 1)

    def test_3months_range_includes_2mo_old_excludes_2yr_old(self):
        response = self.client.get(
            reverse("admin_transactions_summary"), {"range": "3months"}
        )
        self.assertEqual(response.data["total_credits"], 6000)  # 5000 + 1000
        self.assertEqual(response.data["total_debits"], 2000)

    def test_all_range_includes_everything_confirmed(self):
        response = self.client.get(
            reverse("admin_transactions_summary"), {"range": "all"}
        )
        self.assertEqual(response.data["total_credits"], 13000)  # 5000+1000+7000
        self.assertEqual(response.data["total_debits"], 2000)
        self.assertEqual(response.data["net"], 11000)

    def test_default_range_is_today(self):
        response = self.client.get(reverse("admin_transactions_summary"))
        self.assertEqual(response.data["range"], "today")
        self.assertEqual(response.data["total_credits"], 5000)

    def test_invalid_range_returns_400(self):
        response = self.client.get(
            reverse("admin_transactions_summary"), {"range": "yesterday"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
