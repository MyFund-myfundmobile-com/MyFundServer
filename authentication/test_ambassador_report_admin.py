from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from authentication.models import AmbassadorCohort, AmbassadorMonthlyReport, CustomUser

URL = "/admin/authentication/ambassadormonthlyreport/"


class ReportPayoutListTests(TestCase):
    """The payout view: one month, one cohort, highest points first, and a
    warning for anyone in the cohort with no report that month."""

    def setUp(self):
        n = iter(range(100))
        mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name=email.split("@")[0], last_name="B",
            phone_number=f"0803900{next(n):04d}", **extra)
        self.admin = mk("boss@example.com", is_staff=True, is_superuser=True)
        self.c3 = AmbassadorCohort.objects.create(cohort_number=3, status="ended")
        self.c4 = AmbassadorCohort.objects.create(cohort_number=4, status="active")
        self.month = (timezone.localdate().replace(day=1) - timezone.timedelta(days=1)).strftime("%Y-%m")
        for email, cohort, points in [("low@x.com", self.c4, "2"), ("top@x.com", self.c4, "20"),
                                      ("old@x.com", self.c3, "50")]:
            user = mk(email, is_ambassador=True, ambassador_cohort=cohort)
            AmbassadorMonthlyReport.objects.create(
                user=user, month=self.month, total_points_awarded=Decimal(points),
                stipend_amount=Decimal(points) * 100)
        mk("silent@x.com", is_ambassador=True, ambassador_cohort=self.c4)
        self.client.force_login(self.admin)

    def test_last_month_in_one_cohort_ranks_by_points_and_flags_missing(self):
        res = self.client.get(URL, {"month": self.month, "user__ambassador_cohort__id__exact": self.c4.pk})
        self.assertEqual(res.status_code, 200)
        rows = list(res.context["cl"].result_list)
        self.assertEqual([r.user.email for r in rows], ["top@x.com", "low@x.com"])
        admin = res.context["cl"].model_admin
        self.assertEqual([admin.rank(r) for r in rows], ["1st", "2nd"])
        warnings = [str(m) for m in res.context["messages"]]
        self.assertTrue(any("silent" in w and "1 ambassador" in w for w in warnings), warnings)

    def test_leftover_submission_date_params_are_dropped(self):
        res = self.client.get(URL, {"month": self.month, "submitted_at__year": "2026",
                                    "submitted_at__month": "10"})
        self.assertEqual(res.status_code, 302)
        self.assertNotIn("submitted_at", res["Location"])
        self.assertIn(f"month={self.month}", res["Location"])

    def test_last_month_is_the_first_month_choice(self):
        res = self.client.get(URL)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Last month (")
