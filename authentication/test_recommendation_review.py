from datetime import date
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from authentication.models import (
    AmbassadorAttendanceSubmission,
    CustomUser,
    CxWeeklyReport,
    Employee,
)


class RecommendationReviewTests(TestCase):
    """Resolving a recommendation thanks its giver by push; deleting one
    removes only the recommendation, never the report or attendance."""

    def setUp(self):
        n = iter(range(100))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="Ada", last_name="B",
            phone_number=f"0803200{next(n):04d}", **extra)
        self.founder = self.mk("tolulopeahmed@gmail.com", is_staff=True)
        self.lioness = self.mk("lioness@myfundmobile.com")
        self.cx = self.mk("cx@example.com", is_staff=True)
        self.report = CxWeeklyReport.objects.create(
            submitted_by=self.cx, report="Busy week", recommendation="Add live chat")
        amb = self.mk("amb@example.com", is_ambassador=True)
        self.attendance = AmbassadorAttendanceSubmission.objects.create(
            user=amb, email=amb.email, attendance_date=date(2026, 10, 24), takeaway="Great",
            recommendation="Record the sessions", month="2026-10", week_key="2026-10-24")

    def post(self, user, url):
        client = APIClient()
        client.force_authenticate(user)
        return client.post(url)

    @patch("authentication.utils.send_push_notification")
    def test_resolving_a_team_recommendation_pushes_a_thank_you(self, push):
        res = self.post(self.founder, f"/api/admin/recommendations/team/{self.report.pk}/resolve/")
        self.assertEqual(res.status_code, 200)
        self.report.refresh_from_db()
        self.assertIsNotNone(self.report.recommendation_resolved_at)
        self.assertEqual(self.report.recommendation_resolved_by, self.founder)
        self.assertEqual(push.call_args.args[0], self.cx)
        self.assertIn("Add live chat", push.call_args.args[2])

    @patch("authentication.utils.send_push_notification")
    def test_ambassador_feedback_is_resolved_by_the_report_viewers(self, push):
        res = self.post(self.lioness, f"/api/admin/recommendations/ambassador/{self.attendance.pk}/resolve/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(push.call_args.args[0], self.attendance.user)

    def test_others_cannot_act(self):
        self.assertEqual(self.post(self.cx, f"/api/admin/recommendations/team/{self.report.pk}/resolve/").status_code, 403)
        self.assertEqual(self.post(self.cx, f"/api/admin/recommendations/ambassador/{self.attendance.pk}/delete/").status_code, 403)

    def test_delete_keeps_the_report_and_the_attendance(self):
        self.assertEqual(self.post(self.founder, f"/api/admin/recommendations/team/{self.report.pk}/delete/").status_code, 204)
        self.report.refresh_from_db()
        self.assertEqual((self.report.report, self.report.recommendation), ("Busy week", ""))

        self.assertEqual(self.post(self.lioness, f"/api/admin/recommendations/ambassador/{self.attendance.pk}/delete/").status_code, 204)
        self.attendance.refresh_from_db()
        self.assertEqual((self.attendance.takeaway, self.attendance.recommendation), ("Great", ""))


class MediaReportTests(TestCase):
    def test_media_team_submits_and_founders_list_media_reports(self):
        n = iter(range(100))
        mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="Sam", last_name="O",
            phone_number=f"0803300{next(n):04d}", **extra)
        samuel = mk("media@example.com", is_staff=True)
        Employee.objects.create(name="Samuel", email=samuel.email, monthly_amount=0,
                                department="Media and Communications", is_active=True)
        founder = mk("tolulopeahmed@gmail.com", is_staff=True)
        client = APIClient()
        client.force_authenticate(samuel)
        with patch("authentication.admin_views.send_admin_push_notification", create=True):
            res = client.post("/api/admin/media/weekly-reports/create/", {
                "report": "3 videos", "recommendation": "Weekly reels", "week_start": "2026-10-19",
            }, format="json")
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["department"], "Media")
        self.assertEqual(len(client.get("/api/admin/media/weekly-reports/mine/").data), 1)

        client.force_authenticate(founder)
        self.assertEqual(len(client.get("/api/admin/media/weekly-reports/").data), 1)
        self.assertEqual(len(client.get("/api/admin/engagement/weekly-reports/").data), 0)
