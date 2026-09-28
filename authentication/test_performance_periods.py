from datetime import date
from unittest.mock import patch
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIRequestFactory, force_authenticate
from .performance_periods import performance_months
from .models import CustomUser
from .views import AmbassadorPerformanceReportView


class CalendarWindowsTest(SimpleTestCase):
    def test_windows_across_year_boundary(self):
        today = date(2026, 1, 15)
        earliest = date(2024, 11, 2)
        self.assertEqual(performance_months("this_month", earliest, today), ["2026-01"])
        self.assertEqual(performance_months("last_month", earliest, today), ["2025-12"])
        self.assertEqual(performance_months("last_6_months", earliest, today),
                         ["2025-08", "2025-09", "2025-10", "2025-11", "2025-12", "2026-01"])
        self.assertEqual(performance_months("last_year", earliest, today),
                         [f"2025-{month:02}" for month in range(1, 13)])
        all_time = performance_months("all_time", earliest, today)
        self.assertEqual((all_time[0], all_time[-1], len(all_time)), ("2024-11", "2026-01", 15))

    def test_invalid_period(self):
        with self.assertRaises(ValueError):
            performance_months("bad", date(2024, 1, 1))


class PerformanceFiltersTest(TestCase):
    def test_shared_endpoint_defaults_and_filters_for_both_roles(self):
        for index, role in enumerate(["is_ambassador", "is_influencer"]):
            user = CustomUser.objects.create_user(email=f"role{index}@example.com",
                phone_number=f"1000000000{index}", password="testpass", **{role: True})
            for period, count in [(None, 1), ("last_month", 1), ("last_6_months", 6), ("last_year", 12), ("all_time", 1)]:
                request = APIRequestFactory().get("/", {"period": period} if period else {})
                force_authenticate(request, user=user)
                response = AmbassadorPerformanceReportView.as_view()(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(response.data["months"]), count)
                self.assertEqual(response.data["period"], period or "this_month")
            request = APIRequestFactory().get("/", {"period": "bad"})
            force_authenticate(request, user=user)
            self.assertEqual(AmbassadorPerformanceReportView.as_view()(request).status_code, 400)
