"""
Tests for the new Admin Metrics Dashboard endpoints (authentication/admin_views.py,
the "ADMIN METRICS DASHBOARD (mobile app - 7-category overview)" section).

CustomUser.date_joined and Transaction.date both use auto_now_add=True, so they
can't be set at creation time - tests that need a specific date create the row
first, then override the field via a queryset .update() call, which bypasses
auto_now_add/auto_now handling.
"""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework.test import APIClient

from .models import (
    CustomUser,
    Transaction,
    TargetSavings,
    TargetSavingsCompletion,
    WithdrawalsRequestToAdmin,
    Property,
)

ADMIN_METRIC_URL_NAMES = [
    "admin_signup_metrics",
    "admin_cashflow_summary",
    "admin_target_savings_breakdown",
    "admin_user_activity_segments",
    "admin_transaction_type_breakdown",
    "admin_property_inventory",
    "admin_withdrawals_trend_chart",
]


class AdminMetricsPermissionTest(TestCase):
    """A non-staff user must be rejected by every new endpoint."""

    def setUp(self):
        self.client = APIClient()
        self.regular_user = CustomUser.objects.create_user(
            email="regular@example.com",
            password="testpass123",
            first_name="Reg",
            last_name="User",
            phone_number="10000000001",
        )

    def test_non_staff_gets_403_on_every_endpoint(self):
        self.client.force_authenticate(user=self.regular_user)
        for name in ADMIN_METRIC_URL_NAMES:
            response = self.client.get(reverse(name))
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN,
                f"{name} should 403 a non-staff user",
            )


def _make_user(email, phone, **extra):
    return CustomUser.objects.create_user(
        email=email,
        password="testpass123",
        first_name="Test",
        last_name="User",
        phone_number=phone,
        **extra,
    )


def _set_date_joined(user, when):
    CustomUser.objects.filter(pk=user.pk).update(date_joined=when)


def _make_transaction(user, transaction_type, source, amount, status_="confirmed", service_charge=0, when=None):
    tx = Transaction.objects.create(
        user=user,
        transaction_type=transaction_type,
        source=source,
        amount=amount,
        service_charge=service_charge,
        status=status_,
    )
    if when is not None:
        Transaction.objects.filter(pk=tx.pk).update(date=when)
    return tx


class TargetSavingsBreakdownTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff1@example.com", "20000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

        owner = _make_user("owner1@example.com", "20000000002")

        def make_target(name, is_active, is_cancelled):
            return TargetSavings.objects.create(
                user=owner,
                name=name,
                target_amount=10000,
                current_amount=1000,
                end_date=timezone.now().date() + timedelta(days=30),
                category="OTHERS",
                is_active=is_active,
                is_cancelled=is_cancelled,
            )

        # 2 still in progress
        for i in range(2):
            make_target(f"in-progress-{i}", is_active=True, is_cancelled=False)

        # 1 completed, 1 failed, 1 cancelled (via TargetSavingsCompletion,
        # the authoritative outcome record)
        completed_target = make_target("completed", is_active=False, is_cancelled=False)
        TargetSavingsCompletion.objects.create(
            user=owner, target_savings=completed_target,
            completed_amount=10000, total_amount=10000,
            completed_date=timezone.now().date(), status="SUCCESS",
        )

        failed_target = make_target("failed", is_active=False, is_cancelled=False)
        TargetSavingsCompletion.objects.create(
            user=owner, target_savings=failed_target,
            completed_amount=2000, total_amount=2000,
            completed_date=timezone.now().date(), status="FAILED",
        )

        cancelled_target = make_target("cancelled", is_active=False, is_cancelled=True)
        TargetSavingsCompletion.objects.create(
            user=owner, target_savings=cancelled_target,
            completed_amount=500, total_amount=500,
            completed_date=timezone.now().date(), status="CANCELLED",
        )

    def test_breakdown_counts(self):
        response = self.client.get(reverse("admin_target_savings_breakdown"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["in_progress"], 2)
        self.assertEqual(data["completed"], 1)
        self.assertEqual(data["failed"], 1)
        self.assertEqual(data["cancelled"], 1)
        self.assertEqual(data["total"], 5)


class UserActivitySegmentsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff2@example.com", "30000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.now = timezone.now()

        # Active: confirmed transaction 10 days ago
        self.active_user = _make_user("active@example.com", "30000000002")
        _make_transaction(
            self.active_user, "credit", "SAVINGS", 5000,
            when=self.now - timedelta(days=10),
        )

        # Just inside the 30-day window (not exactly 30 days ago - the view
        # computes its own timezone.now() independently of this test's, so
        # racing an exact instant match is flaky by design; a healthy
        # margin still exercises "close to the boundary, correctly active").
        self.boundary_user = _make_user("boundary@example.com", "30000000003")
        _make_transaction(
            self.boundary_user, "credit", "SAVINGS", 5000,
            when=self.now - timedelta(days=29, hours=23),
        )

        # Dormant via balance: no recent transaction, but a non-zero balance
        self.dormant_balance_user = _make_user(
            "dormantbal@example.com", "30000000004", savings=15000
        )

        # Dormant via history: zero balance, but transacted long ago
        self.dormant_history_user = _make_user("dormanthist@example.com", "30000000005")
        _make_transaction(
            self.dormant_history_user, "credit", "SAVINGS", 3000,
            when=self.now - timedelta(days=200),
        )

        # Inactive: zero balance, never transacted
        self.inactive_user = _make_user("inactive@example.com", "30000000006")

        # A failed (not confirmed) recent transaction should NOT count
        # toward "active" - this user should be inactive.
        self.failed_tx_user = _make_user("failedtx@example.com", "30000000007")
        _make_transaction(
            self.failed_tx_user, "credit", "SAVINGS", 5000,
            status_="failed", when=self.now - timedelta(days=1),
        )

    def test_segmentation(self):
        response = self.client.get(reverse("admin_user_activity_segments"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data

        # +1 for the staff user itself, who has no transactions/balance
        # (inactive) - accounted for below.
        self.assertEqual(data["active"]["this_month"], 2)  # active_user + boundary_user
        self.assertEqual(data["dormant"]["this_month"], 2)  # dormant_balance_user + dormant_history_user
        self.assertEqual(data["inactive"]["this_month"], 3)  # inactive_user + failed_tx_user + staff
        self.assertEqual(data["total_users"], 7)


class TransactionTypeBreakdownTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff3@example.com", "40000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        user = _make_user("txuser@example.com", "40000000002")

        now = timezone.now()
        _make_transaction(user, "credit", "SAVINGS", 1000, when=now)
        _make_transaction(user, "credit", "INVESTMENT", 2000, service_charge=50, when=now)
        _make_transaction(user, "debit", "SAVINGS", 500, when=now)
        # Outside the current-month window - should be excluded.
        _make_transaction(user, "credit", "SAVINGS", 9999, when=now - timedelta(days=45))
        # Not confirmed - should be excluded.
        _make_transaction(user, "credit", "SAVINGS", 9999, status_="pending", when=now)

    def test_breakdown_current_month(self):
        response = self.client.get(reverse("admin_transaction_type_breakdown"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["credit"]["count"], 2)
        self.assertEqual(data["credit"]["total_amount"], 3000.0)
        self.assertEqual(data["debit"]["count"], 1)
        self.assertEqual(data["debit"]["total_amount"], 500.0)
        self.assertEqual(data["with_charges"]["count"], 1)
        self.assertEqual(data["with_charges"]["total_service_charge"], 50.0)


class PropertyInventoryTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff4@example.com", "50000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

        _make_user("buyer1@example.com", "50000000002", properties=2)
        _make_user("buyer2@example.com", "50000000003", properties=1)
        _make_user("nonbuyer@example.com", "50000000004", properties=0)

        Property.objects.create(
            name="Prop A", description="d", price=1000000, rent_reward=1000, units_available=3
        )
        Property.objects.create(
            name="Prop B", description="d", price=2000000, rent_reward=2000, units_available=0
        )

    def test_inventory_counts(self):
        response = self.client.get(reverse("admin_property_inventory"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["total_properties_bought"], 3)  # 2 + 1 + 0
        self.assertEqual(data["total_units_available"], 3)  # 3 + 0
        self.assertEqual(data["listings_with_availability"], 1)  # only Prop A
        self.assertEqual(data["total_listings"], 2)


class CashflowSummaryTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff5@example.com", "60000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        user = _make_user("cashflowuser@example.com", "60000000002")

        now = timezone.now()
        this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_point = this_month_start - timedelta(days=15)

        _make_transaction(user, "credit", "SAVINGS", 4000, when=now)
        _make_transaction(user, "credit", "SAVINGS", 2000, when=last_month_point)
        _make_transaction(user, "credit", "INVESTMENT", 1000, when=now)
        _make_transaction(user, "debit", "SAVINGS", 300, when=now)

        wr = WithdrawalsRequestToAdmin.objects.create(
            user=user, amount=950, total_amount=1000, withdrawal_type="scheduled", status="pending",
        )
        wr2 = WithdrawalsRequestToAdmin.objects.create(
            user=user, amount=475, total_amount=500, withdrawal_type="scheduled", status="processing",
        )
        # Immediate withdrawal - should not count toward "scheduled".
        WithdrawalsRequestToAdmin.objects.create(
            user=user, amount=100, total_amount=100, withdrawal_type="immediate", status="pending",
        )

    def test_summary(self):
        response = self.client.get(reverse("admin_cashflow_summary"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["total_saved"]["this_month"], 4000.0)
        self.assertEqual(data["total_saved"]["last_month"], 2000.0)
        self.assertEqual(data["total_invested"]["this_month"], 1000.0)
        self.assertEqual(data["total_withdrawals"]["this_month"], 300.0)
        self.assertEqual(data["scheduled_withdrawals"]["count"], 2)
        self.assertEqual(data["scheduled_withdrawals"]["total_amount"], 1500.0)
        self.assertEqual(data["scheduled_withdrawals"]["pending_count"], 1)
        self.assertEqual(data["scheduled_withdrawals"]["processing_count"], 1)


class SignupMetricsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff6@example.com", "70000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

        now = timezone.now()
        this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        # Pin the staff user's own signup to day 1 (week 1) so this test's
        # weekly-bucket assertions don't depend on which day of the month
        # it happens to run on.
        _set_date_joined(self.staff, this_month_start)

        # Week 1 signup (day 3), who also started saving.
        w1_user = _make_user("w1@example.com", "70000000002")
        _set_date_joined(w1_user, this_month_start + timedelta(days=2))
        _make_transaction(w1_user, "credit", "SAVINGS", 1000, when=now)

        # Week 2 signup (day 10), who has NOT started saving.
        w2_user = _make_user("w2@example.com", "70000000003")
        _set_date_joined(w2_user, this_month_start + timedelta(days=9))

        # Last month signup - should not count toward this month's total.
        last_month_user = _make_user("lastmonth@example.com", "70000000004")
        _set_date_joined(last_month_user, this_month_start - timedelta(days=5))

    def test_signup_breakdown(self):
        response = self.client.get(reverse("admin_signup_metrics"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["this_month_total"], 3)  # staff + w1 + w2
        self.assertEqual(data["last_month_total"], 1)
        self.assertEqual(data["weekly_breakdown"][0]["count"], 2)  # staff (day 1) + w1 (day 3)
        self.assertEqual(data["weekly_breakdown"][1]["count"], 1)  # w2 (day 10)
        self.assertEqual(data["activated_count"], 1)
        self.assertEqual(data["not_yet_saved_count"], 2)


class WithdrawalsTrendChartTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff7@example.com", "80000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        user = _make_user("trenduser@example.com", "80000000002")

        now = timezone.now()
        this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_point = this_month_start - timedelta(days=15)

        _make_transaction(user, "debit", "SAVINGS", 1000, when=now)
        _make_transaction(user, "debit", "INVESTMENT", 500, when=now)
        _make_transaction(user, "debit", "SAVINGS", 2000, when=last_month_point)
        # Wrong type/source - should be excluded from the trend.
        _make_transaction(user, "credit", "SAVINGS", 9999, when=now)
        _make_transaction(user, "debit", "WALLET", 9999, when=now)

    def test_withdrawals_trend(self):
        response = self.client.get(
            reverse("admin_withdrawals_trend_chart"), {"period": "6months"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["period"], "6months")
        self.assertEqual(len(data["data"]), 2)  # this month + last month
        # Grouped by (year, month) ascending, so last month sorts first.
        self.assertEqual(data["data"][0]["amount"], 2000.0)
        self.assertEqual(data["data"][-1]["amount"], 1500.0)  # 1000 + 500
        self.assertEqual(data["summary"]["total"], 3500.0)
