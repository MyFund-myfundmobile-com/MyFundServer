from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from authentication.active_saver_views import _token
from authentication.models import ActiveSaverInterview, CustomUser, TopSaverRecognition
from authentication.top_saver_views import recognition_token


def run_now(fn):
    fn()


@patch("authentication.ambassador_application_views._run_in_background", run_now)
@patch("authentication.utils.send_transactional_email")
@patch("authentication.active_saver_views.send_push_notification")
@patch("authentication.top_saver_views.send_push_notification")
class StartAlertTests(TestCase):
    """Tolulope and Janet are pushed (and emailed) the moment anyone starts
    either form - Top Saver or Active Saver - with a tap through to that
    queue in Admin -> Requests."""

    def setUp(self):
        n = iter(range(100))
        mk = lambda email: CustomUser.objects.create_user(
            email=email, password="x", first_name=email.split("@")[0].split(".")[0].title(), last_name="B",
            phone_number=f"0803700{next(n):04d}")
        self.founders = {mk("tolulopeahmed@gmail.com").email, mk("janet.adegbenro@gmail.com").email}
        self.saver = mk("saver@x.com")

    def started(self, url, push, email, kind):
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(APIClient().patch(url, {"answers": {}}, format="json").status_code, 200)
        pushed = {c.args[0].email for c in push.call_args_list if c.kwargs["data"]["type"] == kind}
        self.assertTrue(self.founders <= pushed, pushed)
        emailed = {c.kwargs["recipient_list"][0] for c in email.call_args_list}
        self.assertTrue(self.founders <= emailed, emailed)
        screens = {c.kwargs["data"]["deep_link"]["screen_params"]["params"]["kind"]
                   for c in push.call_args_list if c.args[0].email in self.founders}
        return screens

    def test_top_saver_start_alerts_both(self, top_push, _active_push, email):
        rec = TopSaverRecognition.objects.create(user=self.saver, month=10, year=2026, rank=1)
        screens = self.started(f"/api/top-saver/interview/?token={recognition_token(rec)}", top_push, email,
                               "TOP_SAVER_INTERVIEW_STARTED")
        self.assertEqual(screens, {"top_saver"})

    def test_active_saver_start_alerts_both(self, _top_push, active_push, email):
        interview = ActiveSaverInterview.objects.create(user=self.saver, month=10, year=2026, streak_months=4)
        screens = self.started(f"/api/active-saver/interview/?token={_token(interview)}", active_push, email,
                               "ACTIVE_SAVER_STARTED")
        self.assertEqual(screens, {"active_saver"})
