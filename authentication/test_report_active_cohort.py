from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from authentication.models import AmbassadorCohort, AmbassadorMonthlyReport, CustomUser
from authentication.utils import autosubmit_missing_ambassador_reports_for_previous_month


class ActiveCohortReportTests(TestCase):
    """Only the active cohort submits monthly reports; graduated cohorts
    can't submit and aren't auto-submitted. Influencers are unaffected."""

    def setUp(self):
        n = iter(range(100))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="Ada", last_name="B",
            phone_number=f"0803700{next(n):04d}", **extra)
        self.active = AmbassadorCohort.objects.create(cohort_number=4, status="active")
        self.ended = AmbassadorCohort.objects.create(cohort_number=3, status="ended")
        self.current = self.mk("c4@example.com", is_ambassador=True, ambassador_cohort=self.active)
        self.graduated = self.mk("c3@example.com", is_ambassador=True, ambassador_cohort=self.ended)

    def submit(self, user):
        client = APIClient()
        client.force_authenticate(user)
        with patch("authentication.views.send_ambassador_report_notifications_task"):
            return client.post("/api/ambassador-report/", {"month": "2026-10"}, format="multipart")

    def test_active_cohort_submits_and_graduated_cohort_cannot(self):
        self.assertEqual(self.submit(self.current).status_code, 201)
        res = self.submit(self.graduated)
        self.assertEqual(res.status_code, 400)
        self.assertIn("graduated", str(res.data))

    def test_influencers_still_submit(self):
        self.assertEqual(self.submit(self.mk("inf@example.com", is_influencer=True)).status_code, 201)

    @patch("authentication.utils.notify_ambassador_report_autosubmitted")
    def test_autosubmit_skips_graduated_cohorts(self, _notify):
        autosubmit_missing_ambassador_reports_for_previous_month()
        self.assertEqual(
            set(AmbassadorMonthlyReport.objects.values_list("user__email", flat=True)), {"c4@example.com"})
