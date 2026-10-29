from django.test import TestCase
from rest_framework.test import APIClient

from .models import CustomUser


class SocialAccountLoginTests(TestCase):
    """Password login on a Google/Apple-only account says which button to use."""

    def setUp(self):
        self.client = APIClient()

    def make_user(self, email, picture="", password=None):
        user = CustomUser.objects.create(
            email=email, first_name="S", last_name="U",
            phone_number=f"0803{CustomUser.objects.count():07d}", profile_picture=picture,
        )
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()
        return user

    def login(self, email, password="anything"):
        return self.client.post("/api/login/", {"username": email, "password": password}, format="json")

    def test_google_account(self):
        self.make_user("g@example.com", picture="https://lh3.googleusercontent.com/a/abc")
        res = self.login("g@example.com")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.data["status"], "social_account")
        self.assertEqual(res.data["provider"], "google")
        self.assertIn("Continue with Google", res.data["message"])

    def test_apple_account(self):
        self.make_user("x1@privaterelay.appleid.com")
        res = self.login("x1@privaterelay.appleid.com")
        self.assertEqual(res.data["provider"], "apple")

    def test_unknown_provider(self):
        self.make_user("u@example.com")
        res = self.login("u@example.com")
        self.assertEqual(res.data["status"], "social_account")
        self.assertIsNone(res.data["provider"])
        self.assertIn("Google or Apple", res.data["message"])

    def test_password_account_still_gets_wrong_password(self):
        self.make_user("p@example.com", password="right-pass-123")
        res = self.login("p@example.com", "nope")
        self.assertEqual(res.data["status"], "wrong_password")
