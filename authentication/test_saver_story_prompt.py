import datetime
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication import active_saver_views as views
from authentication.models import ActiveSaverInterview, CustomUser, TargetSavings, TopSaverHistory, Transaction

URL = "/api/saver-story/prompt/"


class PromptTests(TestCase):
    """The in-app story invite only shows at a milestone, at most every 90
    days, never after a "Not now" (60 days), a submitted story, or a
    failed payment / withdrawal."""

    def setUp(self):
        self.user = CustomUser.objects.create_user(email="ngozi@x.com", password="x", first_name="Ngozi",
                                                   last_name="A", phone_number="08036660001")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def goal(self, current, target="100000"):
        return TargetSavings.objects.create(user=self.user, name="Rent", target_amount=Decimal(target),
                                            current_amount=Decimal(current), category="RENT_ACCOMMODATION",
                                            end_date=datetime.date.today() + datetime.timedelta(days=90))

    def get(self):
        return self.client.get(URL).data

    def test_nothing_to_celebrate_means_no_prompt(self):
        self.assertEqual(self.get(), {"show": False})
        self.goal("10000")
        self.assertFalse(self.get()["show"])

    def test_goal_reached_prompts_once_then_waits_90_days(self):
        goal = self.goal("100000")
        data = self.get()
        self.assertTrue(data["show"])
        self.assertEqual(data["key"], f"goal100:{goal.pk}")
        self.assertIn("You reached your Rent goal", data["message"])
        self.assertIn("/activesaver/interview?token=", data["url"])
        self.client.post(URL, {"action": "shown", "key": data["key"]}, format="json")
        self.goal("60000")  # a new halfway goal - still inside the 90 days
        self.assertFalse(self.get()["show"])

    def test_dividend_and_streak_moments(self):
        Transaction.objects.create(user=self.user, transaction_type="credit", status="confirmed",
                                   amount=Decimal("2500"), description="Dividends: Q4 2026 ROI")
        data = self.get()
        self.assertEqual(data["key"], "dividend:Dividends: Q4 2026 ROI")
        self.assertIn("₦2,500 in dividends", data["message"])

        Transaction.objects.all().delete()
        month, year = views.previous_month()
        for back in range(4):
            i = year * 12 + month - 1 - back
            TopSaverHistory.objects.create(user=self.user, month=i % 12 + 1, year=i // 12, rank=20, total_savings=Decimal("1"))
        data = self.get()
        self.assertEqual(data["key"], "streak:3")
        self.assertIn("4 months in a row", data["title"])

    def test_not_now_submitted_and_bad_moments_stop_it(self):
        self.goal("100000")
        self.client.post(URL, {"action": "dismissed"}, format="json")
        self.assertFalse(self.get()["show"])  # paused 60 days

        self.user.saver_story_prompt.delete()
        Transaction.objects.create(user=self.user, transaction_type="credit", status="failed",
                                   amount=Decimal("500"), description="QuickSave (Card)")
        self.assertFalse(self.get()["show"])  # just had a failed payment

        Transaction.objects.all().delete()
        self.assertTrue(self.get()["show"])
        ActiveSaverInterview.objects.filter(user=self.user).update(status="submitted")
        self.assertFalse(self.get()["show"])  # already told their story

    def test_card_link_and_auth(self):
        self.assertEqual(APIClient().get(URL).status_code, 401)
        data = self.client.get("/api/saver-story/link/").data
        self.assertIn("/activesaver/interview?token=", data["url"])
        self.assertFalse(data["submitted"])
