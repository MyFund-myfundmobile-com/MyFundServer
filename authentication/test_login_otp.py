from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.models import CustomUser


class UnverifiedLoginSendsOtpTests(TestCase):
    """Logging in to a not-yet-verified account sends a fresh code, since
    the app's code screen tells the user one was sent."""

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email="newbie@example.com", password="Secret#123", first_name="Sunday",
            last_name="S", phone_number="08034000001",
        )
        CustomUser.objects.filter(pk=self.user.pk).update(
            is_active=False, last_otp_sent_at=timezone.now() - timedelta(days=3))

    def login(self):
        return APIClient().post("/api/login/", {"username": self.user.email, "password": "Secret#123"}, format="json")

    @patch("authentication.views.send_otp_for_user")
    def test_login_sends_a_new_code_but_respects_the_cooldown(self, send):
        res = self.login()
        self.assertEqual((res.status_code, res.data["status"]), (403, "inactive"))
        send.assert_called_once()
        self.assertTrue(send.call_args.kwargs["send_sms"])

        CustomUser.objects.filter(pk=self.user.pk).update(last_otp_sent_at=timezone.now())
        self.login()
        send.assert_called_once()  # not again within 60s
