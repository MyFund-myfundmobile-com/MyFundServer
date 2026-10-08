from datetime import date
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from .models import AmbassadorCohort, CustomUser


@patch("authentication.views.send_transactional_email")
@patch("authentication.utils.send_push_notification")
class CohortLeaderboardTest(TestCase):
    """Ambassadors see only their own cohort on the referral leaderboard."""

    def setUp(self):
        self.c3 = AmbassadorCohort.objects.create(cohort_number=3, start_date=date(2026, 4, 1), status="active")
        self.c4 = AmbassadorCohort.objects.create(cohort_number=4, start_date=date(2026, 10, 1), status="active")
        n = iter(range(100))
        def amb(email, cohort):
            u = CustomUser.objects.create_user(email=email, password="x", first_name=email[:3], last_name="A",
                                               phone_number=f"0803900{next(n):04d}", is_ambassador=True)
            u.ambassador_cohort = cohort
            u.save()
            CustomUser.objects.create_user(email=f"friend.{email}", password="x", first_name="F", last_name="R",
                                           phone_number=f"0803900{next(n):04d}", referral=u)
            return u
        self.a3 = amb("three@example.com", self.c3)
        self.a4 = amb("four@example.com", self.c4)
        self.b4 = amb("fourb@example.com", self.c4)

    def emails(self, user):
        client = APIClient()
        client.force_authenticate(user)
        res = client.get("/api/top-referrals/")
        self.assertEqual(res.status_code, 200, res.data)
        return sorted(r["email"] for r in res.data["top_referrers"])

    def test_each_cohort_sees_only_itself(self, *_):
        self.assertEqual(self.emails(self.a4), ["four@example.com", "fourb@example.com"])
        self.assertEqual(self.emails(self.a3), ["three@example.com"])
