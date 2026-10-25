from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from authentication.models import AmbassadorAttendanceSubmission, CustomUser
from authentication.serializers import AmbassadorAttendanceSubmissionSerializer


def this_weeks_saturday():
    """The meeting whose week is open now (Saturday through Friday)."""
    today = timezone.localdate()
    return today - timedelta(days=(today.weekday() - 5) % 7)


class AmbassadorAttendanceWeekTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email="ambassador@example.com",
            password="Secret#123",
            first_name="Ada",
            last_name="Ambassador",
            phone_number="08030000001",
            is_ambassador=True,
        )
        self.saturday = this_weeks_saturday()

    def payload(self, attendance_date):
        return {
            "email": self.user.email,
            "attendance_date": attendance_date.isoformat(),
            "takeaway": "Useful session.",
            "recommendation": "Keep the weekly meetings going.",
        }

    def test_this_weeks_meeting_is_accepted_after_last_weeks_report(self):
        # A legacy mid-week report from the previous week must not block
        # this Saturday's meeting.
        AmbassadorAttendanceSubmission.objects.create(
            user=self.user,
            email=self.user.email,
            attendance_date=self.saturday - timedelta(days=5),
            takeaway="Monday report",
            recommendation="None",
            month="2026-10",
            week_key="legacy",
        )

        serializer = AmbassadorAttendanceSubmissionSerializer(data=self.payload(self.saturday))

        self.assertTrue(serializer.is_valid(), serializer.errors)
        submission = serializer.save()
        self.assertEqual(submission.week_key, self.saturday.isoformat())

    def test_second_submission_for_the_same_week_is_rejected(self):
        AmbassadorAttendanceSubmission.objects.create(
            user=self.user,
            email=self.user.email,
            attendance_date=self.saturday,
            takeaway="Saturday report",
            recommendation="None",
            month=self.saturday.strftime("%Y-%m"),
            week_key=self.saturday.isoformat(),
        )

        serializer = AmbassadorAttendanceSubmissionSerializer(data=self.payload(self.saturday))

        self.assertFalse(serializer.is_valid())
        self.assertIn("message", serializer.errors)

    def test_only_saturdays_are_accepted(self):
        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(self.saturday - timedelta(days=3))  # a Wednesday
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("attendance_date", serializer.errors)

    def test_future_saturdays_are_rejected(self):
        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(self.saturday + timedelta(days=7))
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("attendance_date", serializer.errors)

    def test_a_missed_past_week_cannot_be_backfilled(self):
        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(self.saturday - timedelta(days=7))
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("closed", str(serializer.errors["attendance_date"]))


class AttendanceSubmitResponseTests(TestCase):
    def test_response_reports_points_earned_and_month_total(self):
        from decimal import Decimal
        from rest_framework.test import APIClient
        from authentication.models import AmbassadorPointConfig

        user = CustomUser.objects.create_user(
            email="amb2@example.com", password="Secret#123", first_name="Eni",
            last_name="A", phone_number="08030000002", is_ambassador=True,
        )
        config = AmbassadorPointConfig.get_active()
        saturday = this_weeks_saturday()
        res = APIClient().post("/api/attendance/submit/", {
            "email": user.email, "attendance_date": saturday.isoformat(),
            "takeaway": "Great session.", "recommendation": "More Q&A.",
        }, format="json")
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["first_name"], "Eni")
        self.assertEqual(Decimal(res.data["points_for_this_attendance"]), config.attendance_points)
        self.assertEqual(res.data["month_label"], saturday.strftime("%B %Y"))
        self.assertEqual(Decimal(res.data["month_points"]), config.attendance_points)  # their only activity


class AmbassadorFeedbackReportTests(TestCase):
    URL = "/api/admin/ambassadors/attendance-feedback/"

    def setUp(self):
        n = iter(range(100))
        mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="Secret#123", first_name="A", last_name="B",
            phone_number=f"0803100{next(n):04d}", **extra)
        self.lioness = mk("lioness@myfundmobile.com")  # not staff
        self.staff = mk("someadmin@example.com", is_staff=True)
        amb = mk("amb@example.com", is_ambassador=True)
        saturday = this_weeks_saturday()
        for d, text in ((saturday, "Loved the session"), (saturday + timedelta(days=7), "pre-submitted")):
            AmbassadorAttendanceSubmission.objects.create(
                user=amb, email=amb.email, attendance_date=d, takeaway=text,
                recommendation="More Q&A", month=d.strftime("%Y-%m"), week_key=d.isoformat())

    def get(self, user):
        from rest_framework.test import APIClient
        client = APIClient()
        client.force_authenticate(user)
        return client.get(self.URL)

    def test_listed_user_sees_feedback_without_future_rows(self):
        res = self.get(self.lioness)
        self.assertEqual(res.status_code, 200)
        self.assertEqual([r["takeaway"] for r in res.data], ["Loved the session"])
        self.assertEqual(res.data[0]["recommendation"], "More Q&A")

    def test_other_users_even_staff_are_refused(self):
        self.assertEqual(self.get(self.staff).status_code, 403)
