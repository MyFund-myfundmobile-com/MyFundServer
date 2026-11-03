from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from authentication import active_saver_views as views
from authentication.models import ActiveSaverInterview, CustomUser, TopSaverHistory, Transaction

URL = "/api/active-saver/interview/"


def run_now(fn):
    fn()


def months_back(month, year, n):
    index = year * 12 + month - 1 - n
    return index % 12 + 1, index // 12


@patch("authentication.ambassador_application_views._run_in_background", run_now)
@patch("authentication.utils.send_transactional_email")
@patch("authentication.active_saver_views.send_push_notification")
class ActiveSaverTests(TestCase):
    def setUp(self):
        self.n = iter(range(1000))
        self.month, self.year = views.previous_month()
        self.boss = self.user("tolulopeahmed@gmail.com", is_staff=True)

    def user(self, email, **extra):
        return CustomUser.objects.create_user(email=email, password="x", first_name=email.split("@")[0].title(),
                                              last_name="Saver", phone_number=f"0803800{next(self.n):04d}", **extra)

    def board(self, user, streak, rank):
        """``user`` saved in each of the last ``streak`` months, at ``rank``."""
        for back in range(streak):
            m, y = months_back(self.month, self.year, back)
            TopSaverHistory.objects.create(user=user, month=m, year=y, rank=rank, total_savings=Decimal("5000"))

    def test_invites_consistent_savers_outside_top_3_once(self, push, email):
        steady = self.user("steady@x.com")
        self.board(steady, 4, rank=6)
        self.board(self.user("new@x.com"), 2, rank=7)          # streak too short
        self.board(self.user("winner@x.com"), 5, rank=2)       # Top 3: Top Saver form instead
        self.board(self.user("team@x.com", is_staff=True), 5, rank=8)
        recent = self.user("recent@x.com")
        self.board(recent, 5, rank=9)
        m, y = months_back(self.month, self.year, 2)
        ActiveSaverInterview.objects.create(user=recent, month=m, year=y, streak_months=3)

        self.assertEqual([(u.email, s, r) for u, s, r in views.candidates(self.month, self.year)], [("steady@x.com", 4, 6)])
        self.assertEqual(views.invite_month(self.month, self.year), 1)
        self.assertEqual(views.invite_month(self.month, self.year), 0)  # re-run never sends twice
        self.assertEqual(push.call_count, 1)
        self.assertIn("4 months in a row", email.call_args.kwargs["subject"])
        self.assertIn("/activesaver/interview?token=", email.call_args.kwargs["message"])

    def test_form_is_personal_and_alerts_on_start_and_submit(self, push, email):
        saver = self.user("ada@x.com")
        self.board(saver, 3, rank=12)
        m, y = months_back(self.month, self.year, 5)
        TopSaverHistory.objects.create(user=saver, month=m, year=y, rank=2, total_savings=Decimal("90000"))
        Transaction.objects.create(user=saver, transaction_type="credit", status="confirmed", amount=Decimal("1250"),
                                   description="Dividends: Q3 2026 ROI")
        interview = ActiveSaverInterview.objects.create(user=saver, month=self.month, year=self.year, streak_months=3, rank=12)
        client, url = APIClient(), f"{URL}?token={views._token(interview)}"

        data = client.get(url).data["interview"]
        texts = [h["text"] for h in data["highlights"]]
        self.assertIn("3 months in a row of growing your savings", texts)
        self.assertIn("₦1,250 earned in MyFund dividends so far", texts)
        self.assertEqual(data["past_top_saver"]["rank"], 2)
        self.assertIn("/topsaver/start?token=", data["past_top_saver"]["story_link"])  # story still untold

        with self.captureOnCommitCallbacks(execute=True):
            client.patch(url, {"answers": {"saving_for": "My shop"}}, format="json")
        interview.refresh_from_db()
        self.assertEqual(interview.status, "started")
        self.assertEqual(push.call_args.kwargs["data"]["type"], "ACTIVE_SAVER_STARTED")

        self.assertEqual(client.post(url, {"answers": {"saving_for": "My shop"}}, format="json").status_code, 400)
        answers = {"saving_for": "My shop", "impact": "I finally have a buffer.", "live_interview": "No",
                   "rating": 5, "challenges": "Withdrawals feel slow."}
        push.reset_mock()
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(client.post(url, {"answers": answers}, format="json").status_code, 200)
        interview.refresh_from_db()
        self.assertEqual(interview.status, "submitted")
        self.assertEqual({c.kwargs["data"]["type"] for c in push.call_args_list}, {"ACTIVE_SAVER_SUBMITTED"})
        self.assertIn("Withdrawals feel slow.", email.call_args.kwargs["message"])
        self.assertEqual(client.patch(url, {"answers": answers}, format="json").status_code, 409)

    def test_preview_saves_and_sends_nothing(self, push, email):
        saver = self.user("bola@x.com")
        self.board(saver, 4, rank=20)
        client, url = APIClient(), views.preview_link(saver).replace("https://www.myfundmobile.com/activesaver/interview", URL)

        data = client.get(url).data["interview"]
        self.assertTrue(data["preview"])
        self.assertEqual(data["streak_months"], 4)
        answers = {"saving_for": "Rent", "impact": "Calm", "live_interview": "No", "rating": 4}
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(client.post(url, {"answers": answers}, format="json").data["interview"]["status"], "submitted")
        self.assertFalse(ActiveSaverInterview.objects.exists())
        push.assert_not_called()
        email.assert_not_called()
        self.assertEqual(client.get(f"{URL}?preview=forged").status_code, 404)

    def test_admin_requests_queue_and_reminder(self, push, email):
        saver = self.user("chi@x.com")
        interview = ActiveSaverInterview.objects.create(user=saver, month=self.month, year=self.year, streak_months=5, rank=9)
        client = APIClient()
        client.force_authenticate(self.boss)

        res = client.get("/api/admin/requests/", {"kind": "active_saver", "scope": "pending"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual([(r["kind"], r["streak_months"]) for r in res.data["results"]], [("active_saver", 5)])
        self.assertEqual(res.data["counts"]["active_saver"], 1)
        self.assertIn("active_saver", {r["kind"] for r in client.get("/api/admin/requests/", {"kind": "all"}).data["results"]})

        res = client.post(f"/api/admin/requests/active_saver/{interview.pk}/action/", {"action": "remind"}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["reminder_count"], 1)
        self.assertIn("Finish My Story", email.call_args.kwargs["message"])
        res = client.post(f"/api/admin/requests/active_saver/{interview.pk}/action/", {"action": "remind"}, format="json")
        self.assertEqual(res.status_code, 400)  # 48 hours apart
