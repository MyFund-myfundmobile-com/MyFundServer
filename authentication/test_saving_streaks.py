from decimal import Decimal

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.active_saver_views import saving_summaries
from authentication.models import CustomUser, TopSaverHistory


class SavingStreakTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.n = iter(range(100))

    def user(self, email, **extra):
        return CustomUser.objects.create_user(email=email, password="x", first_name="A", last_name="B",
                                              phone_number=f"0803500{next(self.n):04d}", **extra)

    def saved(self, user, back, rank=50):
        """Positive net saving `back` months ago (0 = this month)."""
        i = self.now.year * 12 + self.now.month - 1 - back
        TopSaverHistory.objects.create(user=user, month=i % 12 + 1, year=i // 12, rank=rank, total_savings=Decimal("1"))

    def test_streak_gap_and_top_saver_count(self):
        steady, lapsed, fresh, never = (self.user(e) for e in ("s@x.com", "l@x.com", "f@x.com", "n@x.com"))
        for back in (1, 2, 3):
            self.saved(steady, back, rank=back)       # last 3 finished months, Top 3 twice... rank 1,2,3 = 3 times
        self.saved(lapsed, 4)                          # last saved 4 months ago
        self.saved(fresh, 0)                           # saved this month only
        out = saving_summaries([steady.pk, lapsed.pk, fresh.pk, never.pk], self.now)
        self.assertEqual(out[steady.pk], {"streak_months": 3, "months_without_saving": None, "top_saver_times": 3})
        self.assertEqual(out[lapsed.pk], {"streak_months": 0, "months_without_saving": 3, "top_saver_times": 0})
        self.assertEqual(out[fresh.pk]["streak_months"], 1)  # this month counts once they've saved
        self.assertEqual(out[never.pk], {"streak_months": 0, "months_without_saving": None, "top_saver_times": 0})

    def test_admin_list_and_detail_include_it(self):
        admin = self.user("boss@x.com", is_staff=True, is_superuser=True)
        saver = self.user("saver@x.com")
        self.saved(saver, 1)
        client = APIClient()
        client.force_authenticate(admin)
        rows = client.get("/api/admin/users/list", {"search": "saver@x.com"}).data["data"]
        self.assertEqual(rows[0]["saving"]["streak_months"], 1)
        detail = client.get(f"/api/admin/users/{saver.pk}/").data
        self.assertEqual(detail["saving"]["streak_months"], 1)

    def test_saver_sees_only_their_own_streak(self):
        saver = self.user("own@x.com")
        self.saved(saver, 1)
        self.saved(saver, 2)
        client = APIClient()
        self.assertEqual(client.get("/api/saving-streak/").status_code, 401)
        client.force_authenticate(saver)
        data = client.get("/api/saving-streak/").data
        self.assertEqual(data["streak_months"], 2)
        states = [m["state"] for m in data["months"]]
        # Joined this month in the test, so only this month and the 3 ahead show.
        self.assertEqual(states, ["current", "future", "future", "future"])

    def test_calendar_states(self):
        from datetime import timedelta
        from authentication.active_saver_views import saving_calendar
        saver = self.user("cal@x.com")
        CustomUser.objects.filter(pk=saver.pk).update(date_joined=self.now - timedelta(days=150))
        saver.refresh_from_db()
        for back in (0, 1, 3):
            self.saved(saver, back)
        states = [m["state"] for m in saving_calendar(saver, self.now)]
        self.assertEqual(states[-4:], ["current_saved", "future", "future", "future"])
        self.assertEqual(states[-6:-4], ["missed", "saved"])  # 2 months ago missed, last month saved
