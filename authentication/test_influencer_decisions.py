from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.models import AmbassadorApplication, AmbassadorIntake, CustomUser


@patch("authentication.utils.send_push_notification")
@patch("authentication.utils.send_transactional_email")
class InfluencerDecisionTests(TestCase):
    """Admins approve or reject website Influencer Portal applications from
    Requests; approval switches on influencer access and tells the applicant."""

    def setUp(self):
        now = timezone.now()
        n = iter(range(100))
        self.mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name="Ada", last_name="B",
            phone_number=f"0803800{next(n):04d}", **extra)
        self.admin = self.mk("tolulopeahmed@gmail.com", is_staff=True)
        self.intake = AmbassadorIntake.objects.create(
            programme="influencer", slug="influencers", title="Influencers",
            opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=30))
        self.applicant = self.mk("ada@example.com", is_ambassador=True)
        self.app = AmbassadorApplication.objects.create(
            intake=self.intake, email="ada@example.com", status="submitted",
            answers={"full_name": "Ada B"})
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def act(self, action, reason="", app=None):
        app = app or self.app
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(f"/api/admin/requests/influencer_portal/{app.pk}/action/",
                                    {"action": action, "reason": reason}, format="json")

    def test_listed_with_approve_and_reject(self, _email, _push):
        res = self.client.get("/api/admin/requests/?kind=influencer_portal")
        self.assertEqual(res.data["results"][0]["actions"], ["approve", "reject"])

    def test_approve_switches_on_influencer_access_and_notifies(self, email, push):
        res = self.act("approve")
        self.assertEqual(res.status_code, 200, res.data)
        self.applicant.refresh_from_db()
        self.app.refresh_from_db()
        self.assertTrue(self.applicant.is_influencer)
        self.assertEqual((self.app.status, self.app.user), ("accepted", self.applicant))
        self.assertEqual(res.data["actions"], [])
        self.assertEqual(email.call_args.kwargs["recipient_list"], ["ada@example.com"])
        self.assertIn("approved", email.call_args.kwargs["message"])
        self.assertEqual(push.call_args.kwargs["user"], self.applicant)

    def test_reject_needs_a_reason_and_sends_it(self, email, push):
        self.assertEqual(self.act("reject").status_code, 400)
        res = self.act("reject", "Please grow your audience first")
        self.assertEqual(res.status_code, 200, res.data)
        self.applicant.refresh_from_db()
        self.assertFalse(self.applicant.is_influencer)
        self.assertIn("Please grow your audience first", email.call_args.kwargs["message"])
        self.assertEqual(self.act("approve").status_code, 400)  # already decided

    def test_approve_without_an_account_asks_them_to_sign_up(self, email, _push):
        app = AmbassadorApplication.objects.create(
            intake=self.intake, email="nobody@example.com", status="submitted")
        res = self.act("approve", app=app)
        self.assertEqual(res.status_code, 400)
        self.assertIn("sign up", str(res.data))
        email.assert_not_called()

    def test_ambassador_applications_are_sorted_not_approved(self, _email, _push):
        intake = AmbassadorIntake.objects.create(
            programme="ambassador", slug="amb", title="Ambassadors",
            opens_at=timezone.now(), closes_at=timezone.now() + timedelta(days=1))
        AmbassadorApplication.objects.create(intake=intake, email="x@example.com", status="submitted")
        res = self.client.get("/api/admin/requests/?kind=ambassador")
        self.assertEqual(res.data["results"][0]["actions"], ["label", "send"])
