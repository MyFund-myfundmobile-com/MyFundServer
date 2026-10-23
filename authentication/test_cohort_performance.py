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
        # This month: me has 2 sign-ups, one confirmed today (still inside its savings hold).
        mk("f1@example.com", referral=self.me)
        f2 = mk("f2@example.com", referral=self.me)
        CustomUser.objects.filter(pk=f2.pk).update(referral_reward_granted=True, referral_reward_confirmed_at=timezone.now())
        mk("f3@example.com", referral=self.other)

    def test_live_month_rank_and_summary(self):
        client = APIClient()
        client.force_authenticate(self.me)
        data = client.get("/api/ambassador/performance-report/").data
        row = data["months"][-1]
        self.assertEqual((row["signups"], row["confirmed"], row["estimated"]), (2, 0, True))
        self.assertEqual(Decimal(row["points"]), Decimal("1.00"))  # 2 x 0.5; the confirmation is on hold
        self.assertEqual(data["rank"]["total_ambassadors"], 3)      # all members, not just reporters
        self.assertEqual(data["rank"]["position"], 1)                # the 99 old points don't count
        s = data["month_summary"]
        self.assertEqual((s["signups"], s["confirmed"], s["confirmed_pending"], s["month_position"]), (2, 0, 1, 1))
        self.assertEqual(Decimal(s["stipend_estimate"]), Decimal("100.00"))
        self.assertIsNone(data["certificate"])
        self.assertTrue(all(m["month"] >= self.this_key for m in data["months"]))

    def test_batch_ranking_matches_existing_scores_with_fixed_query_count(self):
        from .models import AmbassadorPointConfig
        from .views import _cohort_points_batch, _cohort_month_points
        members = [self.me, self.other, self.idle]
        config = AmbassadorPointConfig.get_active()
        expected = {u.id: _cohort_month_points(u, [self.this_key], config) for u in members}
        with self.assertNumQueries(5):  # held confirmations: 1 query when none are due
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


class HeldConfirmedReferralTest(TestCase):
    """A confirmed referral earns the ambassador points only after its
    savings stayed at ₦10,000+ at every daily snapshot for the hold."""

    def setUp(self):
        from datetime import datetime
        n = iter(range(100))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="A", last_name="B",
            phone_number=f"0804400{next(n):04d}", **extra)
        self.me = self.mk("amb@example.com", is_ambassador=True)
        self.confirmed_at = timezone.make_aware(datetime(2026, 9, 10, 10, 0))
        self.now = timezone.make_aware(datetime(2026, 10, 20, 9, 0))  # hold ended 10 Oct

    def referral(self, email, confirmed_at=None):
        r = self.mk(email, referral=self.me)
        CustomUser.objects.filter(pk=r.pk).update(
            referral_reward_granted=True, referral_reward_confirmed_at=confirmed_at or self.confirmed_at)
        return r

    def snapshots(self, user, savings="10000", skip=(), low=(), target="0"):
        from .models import DailyROIAccrual
        for i in range(1, 31):
            day = self.confirmed_at.date() + timedelta(days=i)
            if i in skip:
                continue
            DailyROIAccrual.objects.create(user=user, date=day, target_savings_balance=Decimal(target),
                                           savings_balance=Decimal("4000" if i in low else savings))

    def held(self, month="2026-10"):
        from .models import held_confirmed_referral_counts
        return held_confirmed_referral_counts([self.me.id], month, 30, now=self.now)

    def test_counts_in_the_month_the_hold_ends_when_savings_stayed(self):
        self.snapshots(self.referral("kept@example.com"))
        self.assertEqual(self.held(), {self.me.id: 1})
        self.assertEqual(self.held("2026-09"), {})  # not the month of confirmation

    def test_dipping_below_the_threshold_never_counts(self):
        self.snapshots(self.referral("dipped@example.com"), low=(12,))
        self.assertEqual(self.held(), {})

    def test_money_moved_into_target_savings_still_counts(self):
        self.snapshots(self.referral("goal@example.com"), low=(12,), target="6000")  # 4,000 + 6,000
        self.assertEqual(self.held(), {self.me.id: 1})

    def test_a_day_with_no_snapshot_while_the_job_ran_means_zero_balance(self):
        withdrew = self.referral("withdrew@example.com")
        self.snapshots(withdrew, skip=(20,))
        self.snapshots(self.mk("someone@example.com"))  # the job did run that day
        self.assertEqual(self.held(), {})

    def test_still_inside_the_hold_is_pending_not_counted(self):
        from .models import pending_confirmed_referral_counts
        self.referral("new@example.com", confirmed_at=self.now - timedelta(days=5))
        self.assertEqual(self.held(), {})
        self.assertEqual(pending_confirmed_referral_counts([self.me.id], 30, now=self.now), {self.me.id: 1})


class AutosubmitNotificationTest(TestCase):
    def test_ambassador_gets_email_and_push_when_report_is_autosubmitted(self):
        from .utils import autosubmit_missing_ambassador_reports_for_previous_month
        amb = CustomUser.objects.create_user(email="amb@example.com", password="x", first_name="Eni",
                                             last_name="B", phone_number="08045000001", is_ambassador=True)
        with patch("authentication.utils.send_transactional_email") as email, \
                patch("authentication.utils.send_push_notification") as push, \
                self.captureOnCommitCallbacks(execute=True):
            result = autosubmit_missing_ambassador_reports_for_previous_month()
        self.assertEqual(result["created"], 1)
        self.assertEqual(email.call_args.kwargs["recipient_list"], [amb.email])
        self.assertIn("submitted it for you", email.call_args.kwargs["message"])
        self.assertEqual(push.call_args.kwargs["user"], amb)
        self.assertEqual(push.call_args.kwargs["data"]["type"], "AMBASSADOR_REPORT_AUTOSUBMITTED")


class DailySnapshotTargetSavingsTest(TestCase):
    def test_target_savings_only_user_gets_a_snapshot_with_its_balance(self):
        from .models import DailyROIAccrual, TargetSavings
        from .tasks import calculate_daily_roi_task
        u = CustomUser.objects.create_user(email="goal@example.com", password="x", first_name="G",
                                           last_name="B", phone_number="08046000001")
        TargetSavings.objects.create(user=u, name="Rent", target_amount=Decimal("50000"),
                                     current_amount=Decimal("12000"), end_date=date.today() + timedelta(days=90))
        with patch("authentication.tasks.send_batch_roi_notifications", return_value={"sent": 0, "failed": 0}):
            calculate_daily_roi_task()
        row = DailyROIAccrual.objects.get(user=u)
        self.assertEqual((row.savings_balance, row.target_savings_balance), (Decimal("0"), Decimal("12000")))


class ReferralFlagsAdminTest(TestCase):
    def test_flags_shared_surnames_and_confirmations_at_the_threshold(self):
        from django.contrib.admin.sites import site
        n = iter(range(100))
        mk = lambda email, last, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="A", last_name=last,
            phone_number=f"0804700{next(n):04d}", **extra)
        amb = mk("amb@example.com", "Ibhawoh", is_ambassador=True)
        mk("a@example.com", "Ibhawoh", referral=amb)
        mk("b@example.com", "Okafor", referral=amb)
        mk("c@example.com", "Okafor", referral=amb)
        d = mk("d@example.com", "Bello", referral=amb)
        CustomUser.objects.filter(pk=d.pk).update(savings=Decimal("10000"), referral_reward_granted=True,
                                                  referral_reward_confirmed_at=timezone.now())
        report = AmbassadorMonthlyReport.objects.create(user=amb, month=timezone.localdate().strftime("%Y-%m"))
        flags = site._registry[AmbassadorMonthlyReport].referral_flags(report)
        self.assertEqual(flags, "⚠️ 3 share a surname · 1 confirmed at just ₦10k")
