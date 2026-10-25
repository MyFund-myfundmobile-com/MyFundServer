from datetime import date, timedelta

from django.test import TestCase
from django.utils import timezone

from authentication.models import AmbassadorAttendanceSubmission, CustomUser
from authentication.serializers import AmbassadorAttendanceSubmissionSerializer


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

    def payload(self, attendance_date):
        return {
            "email": self.user.email,
            "attendance_date": attendance_date.isoformat(),
            "takeaway": "Useful session.",
            "recommendation": "Keep the weekly meetings going.",
        }

    def test_saturday_starts_a_new_ambassador_attendance_week(self):
        # This legacy Sunday-to-Saturday key represents a Monday report.
        # It must not prevent attendance for the following Saturday meeting.
        AmbassadorAttendanceSubmission.objects.create(
            user=self.user,
            email=self.user.email,
            attendance_date=date(2026, 10, 19),
            takeaway="Monday report",
            recommendation="None",
            month="2026-10",
            week_key="2026-W42",
        )

        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(date(2026, 10, 24))
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        submission = serializer.save()
        self.assertEqual(submission.week_key, "2026-10-24")

    def test_second_submission_in_same_saturday_to_friday_week_is_rejected(self):
        # A legacy mid-week report (Monday 19 Oct) already covers the week
        # that started Saturday 17 Oct.
        AmbassadorAttendanceSubmission.objects.create(
            user=self.user,
            email=self.user.email,
            attendance_date=date(2026, 10, 19),
            takeaway="Monday report",
            recommendation="None",
            month="2026-10",
            week_key="2026-10-17",
        )

        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(date(2026, 10, 17))
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("message", serializer.errors)

    def test_only_saturdays_are_accepted(self):
        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(date(2026, 10, 21))  # a Wednesday
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("attendance_date", serializer.errors)

    def test_future_saturdays_are_rejected(self):
        today = timezone.localdate()
        next_saturday = today + timedelta(days=(5 - today.weekday()) % 7 or 7)
        serializer = AmbassadorAttendanceSubmissionSerializer(
            data=self.payload(next_saturday)
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("attendance_date", serializer.errors)


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
        res = APIClient().post("/api/attendance/submit/", {
            "email": user.email, "attendance_date": "2026-10-24",
            "takeaway": "Great session.", "recommendation": "More Q&A.",
        }, format="json")
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["first_name"], "Eni")
        self.assertEqual(Decimal(res.data["points_for_this_attendance"]), config.attendance_points)
        self.assertEqual(res.data["month_label"], "October 2026")
        self.assertEqual(Decimal(res.data["month_points"]), config.attendance_points)  # their only activity
