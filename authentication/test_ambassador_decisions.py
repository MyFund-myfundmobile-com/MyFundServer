from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.ambassador_decisions import score_application
from authentication.models import AmbassadorApplication, AmbassadorIntake, CustomUser

STRONG = {
    "full_name": "Ada Obi", "occupation": "Working Professional", "has_account": "Yes", "has_saved": "Yes",
    "saving_habits": "I save consistently every month", "communities": ["Church", "Workplace", "WhatsApp"],
    "weekly_reach": "300–1,000", "has_promoted": "Yes", "promotion_experience": "x" * 150,
    "motivation": "m" * 320, "growth_plan": "p" * 420, "products": ["Savings", "Investments"],
    "signup_target": "50", "six_months": "Yes", "weekly_meetings": "Yes", "monthly_targets": "Yes",
    "social_link": "https://instagram.com/ada", "follow_confirmed": True, "video_link": "https://youtu.be/x",
}


def run_now(fn):
    fn()


class ScoreTests(TestCase):
    def test_strong_applicant_is_qualified_leader(self):
        result = score_application(STRONG, has_video=True)
        self.assertEqual(result["label"], "qualified")
        self.assertGreaterEqual(result["score"], 90)
        self.assertTrue(result["leadership"])

    def test_no_commitment_is_unqualified_whatever_the_score(self):
        result = score_application({**STRONG, "weekly_meetings": "No"}, has_video=True)
        self.assertEqual(result["label"], "unqualified")
        self.assertIn("Can't commit to Saturday meetings", result["gaps"])

    def test_middling_applicant_is_maybe(self):
        middling = {**STRONG, "has_saved": "No", "saving_habits": "I am just starting", "weekly_reach": "50–100",
                    "has_promoted": "No", "growth_plan": "p" * 160, "motivation": "m" * 130,
                    "social_link": "", "follow_confirmed": False}
        result = score_application(middling, has_video=False)
        self.assertEqual(result["label"], "maybe", result)
        self.assertFalse(result["leadership"])

    def test_empty_answers_are_unqualified(self):
        self.assertEqual(score_application({})["label"], "unqualified")


@patch("authentication.ambassador_application_views._run_in_background", run_now)
@patch("authentication.utils.send_push_notification")
@patch("authentication.utils.send_transactional_email")
class DecisionTests(TestCase):
    def setUp(self):
        now = timezone.now()
        n = iter(range(100))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="Ada", last_name="B", phone_number=f"0803900{next(n):04d}", **extra)
        self.admin = self.mk("tolulopeahmed@gmail.com", is_staff=True)
        self.intake = AmbassadorIntake.objects.create(
            programme="ambassador", slug="c4", title="Cohort 4", group_link="https://chat.whatsapp.com/abc",
            onboarding_note="Onboarding is Saturday 5pm on Google Meet.",
            opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=30))
        self.applicant = self.mk("ada@example.com")
        self.app = AmbassadorApplication.objects.create(intake=self.intake, email="ada@example.com", status="submitted", answers=STRONG)
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def act(self, **data):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(f"/api/admin/requests/ambassador/{self.app.pk}/action/", data, format="json")

    def test_list_shows_suggestion_and_sorts_by_score(self, _email, _push):
        weak = AmbassadorApplication.objects.create(intake=self.intake, email="w@example.com", status="submitted", answers={"full_name": "W"})
        res = self.client.get("/api/admin/requests/?kind=ambassador&sort=score")
        ids = [r["id"] for r in res.data["results"]]
        self.assertEqual(ids, [str(self.app.pk), str(weak.pk)])
        self.assertEqual(res.data["results"][0]["suggestion"]["label"], "qualified")

    def test_label_only_sends_nothing_and_can_change(self, email, push):
        self.act(action="label", label="maybe")
        self.act(action="label", label="qualified")
        self.app.refresh_from_db()
        self.assertEqual((self.app.review_label, self.app.status), ("qualified", "submitted"))
        email.assert_not_called()
        push.assert_not_called()

    def test_send_qualified_emails_pushes_and_accepts(self, email, push):
        res = self.act(action="send", label="qualified")
        self.assertEqual(res.status_code, 200, res.data)
        self.app.refresh_from_db()
        self.assertEqual((self.app.status, self.app.decision_sent_label), ("accepted", "qualified"))
        html = email.call_args.kwargs["message"]
        self.assertIn("https://chat.whatsapp.com/abc", html)
        self.assertIn("Saturday 5pm", html)
        self.assertEqual(push.call_args.kwargs["user"], self.applicant)

    def test_maybe_can_later_be_promoted_but_not_resent(self, email, _push):
        self.act(action="send", label="maybe")
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, "shortlisted")
        self.assertEqual(self.act(action="send").status_code, 400)  # same label again
        self.assertEqual(self.act(action="send", label="qualified").status_code, 200)
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, "accepted")
        self.assertEqual(email.call_count, 2)
        self.assertEqual(self.act(action="label", label="maybe").status_code, 400)  # decided now

    def test_unqualified_sends_polite_decline(self, email, _push):
        self.act(action="send", label="unqualified")
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, "rejected")
        self.assertIn("apply again", email.call_args.kwargs["message"])

    def test_no_account_still_gets_email(self, email, push):
        self.app.email = "noacct@example.com"
        self.app.save()
        self.act(action="send", label="maybe")
        email.assert_called_once()
        push.assert_not_called()
