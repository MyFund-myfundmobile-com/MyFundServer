from unittest.mock import MagicMock, patch

from django.test import TestCase
from rest_framework.test import APIClient

from authentication.models import AutoSave, CustomUser


def resp(status, data=None):
    r = MagicMock()
    r.status_code = status
    r.ok = 200 <= status < 300
    r.json.return_value = {"data": data or {}}
    r.raise_for_status.side_effect = None if r.ok else __import__("requests").HTTPError(f"{status}")
    return r


@patch("authentication.views.send_push_notification")
@patch("authentication.views.send_transactional_email")
class DeactivateAutoSaveTests(TestCase):
    """Turning AutoSave off must not get stuck."""

    def setUp(self):
        self.user = CustomUser.objects.create_user(email="m@example.com", password="x", first_name="M", last_name="I",
                                                   phone_number="08036660001")
        self.user.autosave_enabled = True
        self.user.save(update_fields=["autosave_enabled"])
        self.auto = AutoSave.objects.create(user=self.user, amount=1000, frequency="daily", active=True,
                                            paystack_sub_code="SUB_x", paystack_sub_token="tok", paystack_sub_id="1")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def off(self, frequency="daily"):
        return self.client.post("/api/deactivate-autosave/", {"frequency": frequency}, format="json")

    @patch("authentication.views.requests.post", return_value=resp(200))
    def test_normal_turn_off(self, _post, _email, _push):
        self.assertEqual(self.off().data["message"], "AutoSave deactivated")
        self.assertFalse(AutoSave.objects.filter(user=self.user, active=True).exists())

    @patch("authentication.views.requests.get", return_value=resp(200, {"status": "cancelled"}))
    @patch("authentication.views.requests.post", return_value=resp(400))
    def test_already_cancelled_on_paystack_still_turns_off(self, _post, _get, _email, _push):
        self.assertEqual(self.off().data["message"], "AutoSave deactivated")
        self.user.refresh_from_db()
        self.assertFalse(self.user.autosave_enabled)

    @patch("authentication.views.requests.get", return_value=resp(200, {"status": "active"}))
    @patch("authentication.views.requests.post", return_value=resp(500))
    def test_still_active_on_paystack_is_not_hidden(self, _post, _get, _email, _push):
        res = self.off()
        self.assertEqual(res.status_code, 502)
        self.assertTrue(AutoSave.objects.filter(user=self.user, active=True).exists())

    @patch("authentication.views.requests.post", return_value=resp(200))
    def test_blank_or_different_case_frequency_works(self, _post, _email, _push):
        self.assertEqual(self.off(frequency="").data["message"], "AutoSave deactivated")
        AutoSave.objects.create(user=self.user, amount=500, frequency="weekly", active=True)
        self.assertEqual(self.off(frequency="Weekly").data["message"], "AutoSave deactivated")

    @patch("authentication.views.requests.get", return_value=resp(500))
    def test_status_keeps_frequency_when_paystack_is_down(self, _get, _email, _push):
        AutoSave.objects.create(user=self.user, amount=500, frequency="weekly", active=True)  # two active rows
        res = self.client.get("/api/get-autosave-settings/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(res.data["autoSaveSettings"]["frequency"], ("daily", "weekly"))
