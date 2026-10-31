from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from authentication.models import CustomUser, Employee, TopSaverHistory, TopSaverRecognition
from authentication.tasks import reward_top_savers_of_month
from authentication.top_saver_views import recognition_token


def run_now(fn):
    fn()


class Base(TestCase):
    def setUp(self):
        n = iter(range(200))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name=email.split("@")[0].title(), last_name="S",
            phone_number=f"0807700{next(n):04d}", **extra)


@patch("authentication.top_saver_views.send_push_notification")
@patch("authentication.utils.send_transactional_email", return_value={"sent": 1})
class MonthlyTaskTests(Base):
    def test_first_timer_gets_tshirt_repeat_does_not_ranks_4_to_10_encouraged(self, email, push):
        from django.utils import timezone
        now = timezone.now()
        month, year = (12, now.year - 1) if now.month == 1 else (now.month - 1, now.year)
        old_month, old_year = (12, year - 1) if month == 1 else (month - 1, year)
        first, repeat, fourth = self.mk("first@example.com"), self.mk("repeat@example.com"), self.mk("fourth@example.com")
        TopSaverHistory.objects.create(user=repeat, month=old_month, year=old_year, rank=2, total_savings=1)
        TopSaverHistory.objects.create(user=first, month=month, year=year, rank=1, total_savings=3)
        TopSaverHistory.objects.create(user=repeat, month=month, year=year, rank=2, total_savings=2)
        TopSaverHistory.objects.create(user=fourth, month=month, year=year, rank=4, total_savings=1)

        reward_top_savers_of_month()
        sent = {c.kwargs["recipient_list"][0]: c.kwargs for c in email.call_args_list}
        self.assertIn("free MyFund T-shirt", sent["first@example.com"]["message"])
        self.assertIn("/topsaver/interview?token=", sent["first@example.com"]["message"])
        self.assertNotIn("T-shirt", sent["repeat@example.com"]["message"])
        self.assertIn("#4", sent["fourth@example.com"]["subject"])
        self.assertTrue(TopSaverRecognition.objects.get(user=first).first_time_winner)
        self.assertFalse(TopSaverRecognition.objects.get(user=repeat).first_time_winner)
        self.assertFalse(TopSaverRecognition.objects.filter(user=fourth).exists())
        tap = [c for c in push.call_args_list if c.args[0] == first][0].kwargs["data"]["deep_link"]["url"]
        self.assertIn("www.myfundmobile.com/topsaver/interview?token=", tap)
        first_push = [c for c in push.call_args_list if c.args[0] == first][0].kwargs["message"]
        self.assertTrue(first_push.endswith("Tap to view the details."))

        email.reset_mock()
        reward_top_savers_of_month()  # retry: no duplicates for the Top 3
        self.assertNotIn("first@example.com", [c.kwargs["recipient_list"][0] for c in email.call_args_list])


@patch("authentication.ambassador_application_views._run_in_background", run_now)
@patch("authentication.top_saver_views.send_push_notification")
class InterviewTests(Base):
    def setUp(self):
        super().setUp()
        self.winner = self.mk("winner@example.com")
        self.rec = TopSaverRecognition.objects.create(user=self.winner, month=9, year=2026, rank=1, first_time_winner=True)
        self.url = f"/api/top-saver/interview/?token={recognition_token(self.rec)}"
        self.client = APIClient()

    def test_form_has_the_google_form_questions(self, _push):
        keys = [q["key"] for q in self.client.get(self.url).data["questions"]]
        self.assertEqual(keys, ["motivation", "challenges", "word_for_others", "live_interview", "live_interview_contact", "rating", "feature_consent"])

    def test_yes_to_live_interview_alerts_cx_with_contact(self, push):
        cx = self.mk("cx@example.com", is_staff=True)
        Employee.objects.create(name="CX", email=cx.email, monthly_amount=0, department="CX", is_active=True)
        media = self.mk("media@example.com", is_staff=True)
        Employee.objects.create(name="M", email=media.email, monthly_amount=0, department="Media and Communications", is_active=True)
        TopSaverRecognition.objects.filter(pk=self.rec.pk).update(status="started", first_time_winner=False)
        answers = {"motivation": "x", "challenges": "none", "word_for_others": "start", "live_interview": "Yes",
                   "live_interview_contact": "0803 111 2222, evenings", "rating": 5}
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(self.url, {"answers": answers}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        live = [c for c in push.call_args_list if c.kwargs.get("title") == "📞 Top Saver wants a live interview"]
        self.assertEqual({c.args[0] for c in live}, {cx})
        self.assertIn("0803 111 2222", live[0].kwargs["message"])

    def test_contact_dropped_unless_yes(self, _push):
        res = self.client.patch(self.url, {"answers": {"live_interview": "No", "live_interview_contact": "0803"}}, format="json")
        self.assertNotIn("live_interview_contact", res.data["recognition"]["answers"])

    def test_first_save_alerts_team_once_and_submit_needs_tshirt_details(self, push):
        exec_ = self.mk("company@myfundmobile.com", is_staff=True)
        cx = self.mk("cx@example.com", is_staff=True)
        Employee.objects.create(name="CX", email=cx.email, monthly_amount=0, department="CX", is_active=True)
        with self.captureOnCommitCallbacks(execute=True):
            self.client.patch(self.url, {"answers": {"motivation": "My sister"}}, format="json")
        alerted = {c.args[0] for c in push.call_args_list}
        self.assertEqual(alerted, {exec_, cx})
        push.reset_mock()
        with self.captureOnCommitCallbacks(execute=True):
            self.client.patch(self.url, {"answers": {"motivation": "My sister and friends"}}, format="json")
        push.assert_not_called()

        answers = {"motivation": "x", "challenges": "none", "word_for_others": "start", "live_interview": "Yes", "rating": 5}
        res = self.client.post(self.url, {"answers": answers}, format="json")
        self.assertEqual(res.status_code, 400)
        self.assertIn("T-shirt size", res.data["error"])
        res = self.client.post(self.url, {"answers": answers, "shirt_size": "L", "delivery_address": "1 Allen Ave, Ikeja",
                                          "delivery_phone": "08030000000", "delivery_cost_acknowledged": True}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["recognition"]["status"], "submitted")

    def test_rejects_bad_answers_and_bad_tokens(self, _push):
        self.assertEqual(self.client.patch(self.url, {"answers": {"rating": 9}}, format="json").status_code, 400)
        self.assertEqual(self.client.patch(self.url, {"answers": {"invented": "x"}}, format="json").status_code, 400)
        self.assertEqual(self.client.get("/api/top-saver/interview/?token=nope").status_code, 404)


@patch("authentication.utils.send_transactional_email", return_value={"sent": 1})
class AdminRequestTests(Base):
    def setUp(self):
        super().setUp()
        self.admin = self.mk("tolulopeahmed@gmail.com", is_staff=True)
        self.winner = self.mk("winner@example.com")
        self.rec = TopSaverRecognition.objects.create(user=self.winner, month=9, year=2026, rank=2, status="started",
                                                      answers={"rating": 4, "motivation": "Friends"})
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def act(self, action):
        return self.client.post(f"/api/admin/requests/top_saver/{self.rec.pk}/action/", {"action": action}, format="json")

    def test_listed_with_labels_and_remind_is_rate_limited(self, email):
        res = self.client.get("/api/admin/requests/?kind=top_saver&scope=pending")
        row = res.data["results"][0]
        self.assertEqual(row["actions"], ["remind", "invite_video", "close"])
        self.assertIn({"label": "On a scale of 1 to 5, how would you rate your MyFund experience?", "value": "4 / 5"}, row["responses"])
        self.assertEqual(self.act("remind").status_code, 200)
        self.assertEqual(self.act("remind").status_code, 400)
        self.assertEqual(email.call_count, 1)

    def test_all_types_list_and_search_include_top_saver(self, _email):
        for params in ("kind=all&scope=all", "kind=all&scope=pending&sort=amount_high", "kind=top_saver&scope=all&q=winner"):
            res = self.client.get(f"/api/admin/requests/?{params}")
            self.assertEqual(res.status_code, 200, (params, res.data))
        self.assertTrue(any(r["kind"] == "top_saver" for r in self.client.get("/api/admin/requests/?kind=all&scope=all").data["results"]))

    def test_video_invite_after_submit(self, email):
        TopSaverRecognition.objects.filter(pk=self.rec.pk).update(status="submitted")
        self.assertEqual(self.act("invite_video").status_code, 200)
        self.assertIn("video interview", email.call_args.kwargs["message"])
        self.assertEqual(self.act("remind").status_code, 400)


@patch("authentication.ambassador_application_views._run_in_background", run_now)
@patch("authentication.utils.send_transactional_email", return_value={"sent": 1})
class ClaimAndStoriesTests(Base):
    def setUp(self):
        super().setUp()
        from django.core.cache import cache
        cache.clear()
        self.past = self.mk("past@example.com")
        TopSaverHistory.objects.create(user=self.past, month=3, year=2026, rank=2, total_savings=1)
        self.client = APIClient()

    def claim_token(self, email):
        import re
        self.client.post("/api/top-saver/claim/", {"email": "past@example.com"}, format="json")
        html = email.call_args.kwargs["message"]
        return re.search(r"topsaver/start\?token=([^\"]+)", html).group(1)

    def test_same_reply_for_anyone_and_email_only_for_past_top_savers(self, email):
        nobody = self.client.post("/api/top-saver/claim/", {"email": "nobody@example.com"}, format="json")
        past = self.client.post("/api/top-saver/claim/", {"email": "PAST@example.com"}, format="json")
        self.assertEqual(nobody.data, past.data)
        self.assertEqual([c.kwargs["recipient_list"] for c in email.call_args_list], [["past@example.com"]])

    def test_pick_month_opens_interview_only_no_tshirt(self, email):
        import re
        self.client.post("/api/top-saver/claim/", {"email": "past@example.com"}, format="json")
        token = re.search(r"topsaver/start\?token=([^\"]+)", email.call_args.kwargs["message"]).group(1)
        months = self.client.get(f"/api/top-saver/claim/start/?token={token}").data["months"]
        self.assertEqual([(m["month"], m["year"], m["rank"]) for m in months], [(3, 2026, 2)])
        self.assertEqual(self.client.post(f"/api/top-saver/claim/start/?token={token}", {"month": 4, "year": 2026}, format="json").status_code, 400)
        res = self.client.post(f"/api/top-saver/claim/start/?token={token}", {"month": 3, "year": 2026}, format="json")
        self.assertEqual(res.status_code, 200)
        rec = TopSaverRecognition.objects.get(user=self.past)
        self.assertFalse(rec.first_time_winner)
        form = self.client.get(f"/api/top-saver/interview/?token={res.data['token']}")
        self.assertFalse(form.data["recognition"]["first_time_winner"])

    def test_bad_claim_token(self, _email):
        self.assertEqual(self.client.get("/api/top-saver/claim/start/?token=nope").status_code, 404)

    def test_stories_only_with_consent_and_no_contact_details(self, _email):
        other = self.mk("other@example.com")
        TopSaverRecognition.objects.create(user=self.past, month=3, year=2026, rank=2, status="submitted",
                                           answers={"word_for_others": "Start small.", "feature_consent": True})
        TopSaverRecognition.objects.create(user=other, month=3, year=2026, rank=1, status="submitted",
                                           answers={"word_for_others": "Private.", "feature_consent": False})
        data = self.client.get("/api/top-saver/stories/").data
        self.assertEqual([s["quote"] for s in data["stories"]], ["Start small."])
        self.assertNotIn("email", str(data))
        self.assertEqual(data["recent_winners"][0]["month"], "March 2026")
