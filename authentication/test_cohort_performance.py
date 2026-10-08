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
