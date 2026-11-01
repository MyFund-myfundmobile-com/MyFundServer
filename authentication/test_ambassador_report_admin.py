from decimal import Decimal
from unittest.mock import patch

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
        self.assertEqual([admin.month_rank(r) for r in rows], ["2nd", "3rd"])
        self.assertEqual(admin.cohort(rows[0]), 4)
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

    def test_ties_list_in_rank_order_when_sorted_by_points(self):
        # Equal points with stipends a few kobo apart, plus an extra sort on
        # name left over from an earlier click: the list still follows rank.
        for i, (name, stipend) in enumerate([("Zed", "600.00"), ("Amy", "600.50"), ("Bo", "599.00")]):
            user = CustomUser.objects.create_user(
                email=f"tie{i}@x.com", password="x", first_name=name, phone_number=f"0803911{i:04d}",
                is_ambassador=True, ambassador_cohort=self.c4)
            AmbassadorMonthlyReport.objects.create(
                user=user, month=self.month, total_points_awarded=Decimal("6"), stipend_amount=Decimal(stipend))
        res = self.client.get(URL, {"month": self.month, "user__ambassador_cohort__id__exact": self.c4.pk,
                                    "o": "-8.7"})  # Points (after the checkbox) high-low, then Name
        rows = list(res.context["cl"].result_list)
        admin = res.context["cl"].model_admin
        self.assertEqual([r.user.first_name for r in rows], ["top", "Zed", "Amy", "Bo", "low"])
        self.assertEqual([admin.rank(r) for r in rows], ["1st", "2nd", "3rd", "4th", "5th"])

    def test_company_account_is_hidden_and_not_ranked(self):
        company = CustomUser.objects.create_user(
            email="company@myfundmobile.com", password="x", first_name="Christine", phone_number="08039119999",
            is_ambassador=True, ambassador_cohort=self.c4)
        report = AmbassadorMonthlyReport.objects.create(
            user=company, month=self.month, total_points_awarded=Decimal("99"), stipend_amount=Decimal("9900"))
        res = self.client.get(URL, {"month": self.month, "user__ambassador_cohort__id__exact": self.c4.pk})
        rows = list(res.context["cl"].result_list)
        admin = res.context["cl"].model_admin
        self.assertNotIn("company@myfundmobile.com", [r.user.email for r in rows])
        self.assertEqual(admin.rank(rows[0]), "1st")
        self.assertEqual(admin.month_rank(rows[0]), "2nd")  # Cohort 3's 50 points still outranks
        self.assertEqual(self.client.get(f"{URL}{report.pk}/change/").status_code, 200)


@patch("authentication.admin.send_push_notification")
@patch("authentication.admin.send_transactional_email")
class ApprovePayoutTests(TestCase):
    def setUp(self):
        self.admin = CustomUser.objects.create_user(
            email="boss@example.com", password="x", phone_number="08039000900", is_staff=True, is_superuser=True)
        self.client.force_login(self.admin)
        self.reports = {}
        for i, (name, signups) in enumerate([("zero", 0), ("paid", 3)]):
            user = CustomUser.objects.create_user(
                email=f"{name}@x.com", password="x", first_name=name, phone_number=f"0803900{i:04d}",
                is_ambassador=True, wallet=Decimal("0"))
            report = AmbassadorMonthlyReport(user=user, month="2026-10", signups_submitted=signups)
            report.copy_submitted_to_approved_defaults()
            report.recalculate_points()
            report.save()
            self.reports[name] = report

    def approve_all(self):
        return self.client.post(URL, {"action": "approve_reports",
                                      "_selected_action": [r.pk for r in self.reports.values()]})

    def test_zero_is_marked_paid_and_rerun_sends_nothing_twice(self, email, push):
        self.approve_all()
        zero, paid = (AmbassadorMonthlyReport.objects.get(pk=r.pk) for r in self.reports.values())
        self.assertEqual((zero.status, zero.stipend_paid), ("approved", True))
        self.assertEqual(zero.user.wallet, Decimal("0"))
        self.assertTrue(paid.stipend_paid)
        self.assertEqual(paid.user.wallet, paid.stipend_amount)
        sent = (email.call_count, push.call_count)
        self.assertEqual(sent, (2, 2))

        self.approve_all()
        self.assertEqual((email.call_count, push.call_count), sent)
        self.assertEqual(CustomUser.objects.get(pk=paid.user_id).wallet, paid.stipend_amount)
