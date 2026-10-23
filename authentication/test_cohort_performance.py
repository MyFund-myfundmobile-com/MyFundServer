from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import AmbassadorCohort, AmbassadorMonthlyReport, CustomUser


class CohortPerformanceTest(TestCase):
    """Performance report is scoped to the current cohort and live for the
    month in progress."""

    def setUp(self):
        today = timezone.localdate()
        self.this_key = today.strftime("%Y-%m")
        self.cohort = AmbassadorCohort.objects.create(cohort_number=4, start_date=today.replace(day=1), status="active")
        n = iter(range(100))
        mk = lambda email, **extra: CustomUser.objects.create_user(email=email, password="x", first_name="A", last_name="B",
                                                                    phone_number=f"0804100{next(n):04d}", **extra)
        self.me = mk("me@example.com", is_ambassador=True)
        self.other = mk("other@example.com", is_ambassador=True)
        self.idle = mk("idle@example.com", is_ambassador=True)
        for u in (self.me, self.other, self.idle):
            u.ambassador_cohort = self.cohort
            u.save()
        # Old points from an earlier cohort must not count.
        old = (today.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
        AmbassadorMonthlyReport.objects.create(user=self.idle, month=old, total_points_awarded=Decimal("99"))
        # This month: me has 2 sign-ups, one confirmed.
        mk("f1@example.com", referral=self.me)
        f2 = mk("f2@example.com", referral=self.me)
        CustomUser.objects.filter(pk=f2.pk).update(referral_reward_granted=True, referral_reward_confirmed_at=timezone.now())
        mk("f3@example.com", referral=self.other)

    def test_live_month_rank_and_summary(self):
        client = APIClient()
        client.force_authenticate(self.me)
        data = client.get("/api/ambassador/performance-report/").data
        row = data["months"][-1]
        self.assertEqual((row["signups"], row["confirmed"], row["estimated"]), (2, 1, True))
        self.assertEqual(Decimal(row["points"]), Decimal("11.00"))  # 2 x 0.5 + 1 x 10
        self.assertEqual(data["rank"]["total_ambassadors"], 3)      # all members, not just reporters
        self.assertEqual(data["rank"]["position"], 1)                # the 99 old points don't count
        s = data["month_summary"]
        self.assertEqual((s["signups"], s["confirmed"], s["month_position"]), (2, 1, 1))
        self.assertEqual(Decimal(s["stipend_estimate"]), Decimal("1100.00"))
        self.assertIsNone(data["certificate"])
        self.assertTrue(all(m["month"] >= self.this_key for m in data["months"]))

    def test_batch_ranking_matches_existing_scores_with_fixed_query_count(self):
        from .models import AmbassadorPointConfig
        from .views import _cohort_points_batch, _cohort_month_points
        members = [self.me, self.other, self.idle]
        config = AmbassadorPointConfig.get_active()
        expected = {u.id: _cohort_month_points(u, [self.this_key], config) for u in members}
        with self.assertNumQueries(5):
            scores = _cohort_points_batch(members, [self.this_key], config)
        self.assertEqual({uid: values[self.this_key] for uid, values in scores.items()}, expected)


class FirstDepositPointsTest(TestCase):
    """A referral's first deposit of at least the configured minimum earns
    the ambassador first_deposit_points once, in the month it happened."""

    def setUp(self):
        from .models import AmbassadorPointConfig, Transaction
        self.Transaction = Transaction
        self.config = AmbassadorPointConfig.get_active()  # defaults: 10 points, ₦2,000
        self.this_key = timezone.localdate().strftime("%Y-%m")
        n = iter(range(100))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="A", last_name="B",
            phone_number=f"0804200{next(n):04d}", **extra)
        self.me = self.mk("amb@example.com", is_ambassador=True)

    def deposit(self, user, amount, when=None, status="confirmed", description="QuickSave (Card)"):
        t = self.Transaction.objects.create(user=user, amount=Decimal(amount), transaction_type="credit",
                                            status=status, description=description)
        if when:
            self.Transaction.objects.filter(pk=t.pk).update(date=when)

    def test_counts_each_referral_once_at_the_minimum(self):
        from .models import first_deposit_referral_counts
        a = self.mk("a@example.com", referral=self.me)
        b = self.mk("b@example.com", referral=self.me)
        c = self.mk("c@example.com", referral=self.me)
        self.deposit(a, "2000")
        self.deposit(a, "5000")                        # second deposit: no extra count
        self.deposit(b, "1999.99")                     # below the minimum
        self.deposit(c, "3000", status="pending")      # not confirmed
        self.deposit(self.mk("x@example.com"), "9000")  # not this ambassador's referral
        counts = first_deposit_referral_counts([self.me.id], self.this_key, Decimal("2000"))
        self.assertEqual(counts, {self.me.id: 1})

    def test_earlier_qualifying_deposit_is_not_counted_again(self):
        from .models import first_deposit_referral_counts
        a = self.mk("a@example.com", referral=self.me)
        last_month = timezone.now().replace(day=1) - timedelta(days=1)
        self.deposit(a, "2500", when=last_month)
        self.deposit(a, "2500")
        self.assertEqual(first_deposit_referral_counts([self.me.id], self.this_key, Decimal("2000")), {})
        self.assertEqual(first_deposit_referral_counts(
            [self.me.id], last_month.strftime("%Y-%m"), Decimal("2000")), {self.me.id: 1})

    def test_live_points_and_report_include_first_deposits(self):
        from .views import _live_ambassador_month
        a = self.mk("a@example.com", referral=self.me)
        self.deposit(a, "7000")
        signups, confirmed, attendance, points, first_deposits = _live_ambassador_month(
            self.me, self.this_key, self.config)
        self.assertEqual((signups, first_deposits), (1, 1))
        self.assertEqual(points, Decimal("10.50"))  # 1 x 0.5 sign-up + 1 x 10 first deposit

        report = AmbassadorMonthlyReport(user=self.me, month=self.this_key, signups_submitted=1)
        report.copy_submitted_to_approved_defaults()
        report.recalculate_points()
        self.assertEqual(report.first_deposits_approved, 1)
        self.assertEqual(report.first_deposit_points_awarded, Decimal("10.00"))
        self.assertEqual(report.total_points_awarded, Decimal("10.50"))
