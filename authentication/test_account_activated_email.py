from unittest.mock import patch

from rest_framework.test import APITestCase

from .models import CustomUser


def run_now(fn):
    fn()


@patch("authentication.ambassador_application_views._run_in_background", run_now)
@patch("authentication.utils.send_transactional_email")
class AccountActivatedEmailTests(APITestCase):
    """Admin switching an inactive account on emails them how to log in."""

    def setUp(self):
        self.admin = CustomUser.objects.create(
            email="admin@example.com", first_name="A", last_name="D", phone_number="08030000001",
            is_staff=True, is_superuser=True, is_active=True,
        )
        self.client.force_authenticate(self.admin)

    def make_user(self, email, password=True, picture="", **extra):
        user = CustomUser.objects.create(
            email=email, first_name="Ada", last_name="U", phone_number=f"0805{CustomUser.objects.count():07d}",
            profile_picture=picture, is_active=False, **extra,
        )
        if password:
            user.set_password("pass-12345")
            user.save()
        return user

    def toggle(self, user, value=True):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(f"/api/admin/users/{user.pk}/update-status/", {"field": "is_active", "value": value}, format="json")

    def test_password_account_gets_forgot_password_route(self, send):
        user = self.make_user("p@example.com")
        self.assertEqual(self.toggle(user).status_code, 200)
        send.assert_called_once()
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs["recipient_list"], ["p@example.com"])
        self.assertIn("Forgot Password", kwargs["message"])
        self.assertIn("is now active", kwargs["message"])

    def test_google_account_told_to_use_google(self, send):
        user = self.make_user("g@example.com", password=False, picture="https://lh3.googleusercontent.com/a/x")
        self.toggle(user)
        self.assertIn("Continue with Google", send.call_args.kwargs["message"])
        self.assertNotIn("Forgot Password", send.call_args.kwargs["message"])

    def test_no_email_when_already_active_or_deactivating_or_banned(self, send):
        active = self.make_user("a@example.com")
        CustomUser.objects.filter(pk=active.pk).update(is_active=True)
        self.toggle(active, True)
        self.toggle(active, False)
        banned = self.make_user("b@example.com", is_banned=True)
        self.toggle(banned, True)
        send.assert_not_called()
