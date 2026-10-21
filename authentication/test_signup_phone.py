from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.models import CustomUser


@patch("authentication.views.send_otp_sms", return_value=True, create=True)
@patch("authentication.views.send_otp_email", return_value=True, create=True)
@patch("authentication.views.send_otp_async", create=True)
@patch("authentication.views.create_dedicated_account", create=True)
@patch("authentication.views.create_paystack_customer", return_value=(False, "skipped"), create=True)
class SignupPhoneTests(TestCase):
    """A number held by a never-finished signup used to be refused forever,
    and a duplicate typed as 0810... crashed with "Signup failed"."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def signup(self, phone="08106904663", email="new@example.com"):
        cache.clear()  # the per-phone/IP throttle isn't what's under test
        return self.client.post("/api/signup/", {
            "email": email, "password": "Password123!", "first_name": "New", "last_name": "Saver",
            "phone_number": phone, "how_did_you_hear": "OTHER",
        }, format="json")

    def holder(self, hours_old, **fields):
        user = CustomUser.objects.create_user(
            email=fields.pop("email", "old@example.com"), password="x",
            phone_number="2348106904663", is_active=False, **fields)
        CustomUser.objects.filter(pk=user.pk).update(date_joined=timezone.now() - timedelta(hours=hours_old))
        return user

    def test_abandoned_signup_frees_the_number(self, *_):
        old = self.holder(hours_old=48)
        response = self.signup()
        self.assertEqual(response.status_code, 201, response.content)
        old.refresh_from_db()
        self.assertNotEqual(old.phone_number, "2348106904663")
        self.assertTrue(old.is_deleted)
        self.assertEqual(CustomUser.objects.get(email="new@example.com").phone_number, "2348106904663")

    def test_same_person_can_resign_with_their_old_email(self, *_):
        self.holder(hours_old=48, email="new@example.com")
        self.assertEqual(self.signup().status_code, 201)

    def test_recent_or_used_accounts_keep_their_number(self, *_):
        self.holder(hours_old=2)  # may still be finishing signup
        response = self.signup()
        self.assertEqual(response.status_code, 400)
        self.assertIn("phone_number", response.json())

    def test_duplicate_of_active_account_gets_clear_error_not_500(self, *_):
        CustomUser.objects.create_user(email="active@example.com", password="x", phone_number="2348106904663")
        response = self.signup(phone="08106904663")
        self.assertEqual(response.status_code, 400)
        self.assertIn("phone_number", response.json())

    def test_foreign_number_with_country_code_is_accepted(self, *_):
        response = self.signup(phone="+12025550123", email="abroad@example.com")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(CustomUser.objects.get(email="abroad@example.com").phone_number, "12025550123")

    def test_number_stored_in_old_local_format_is_still_a_duplicate(self, *_):
        # Older accounts store 0803..., new signups normalise to 234803...
        CustomUser.objects.create_user(email="legacy@example.com", password="x", phone_number="08033645283")
        response = self.signup(phone="08033645283", email="dupe@example.com")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(CustomUser.objects.filter(email="dupe@example.com").exists())


class AbroadNumberTests(TestCase):
    def test_detects_numbers_with_a_foreign_country_code(self):
        from authentication.utils import ABROAD_PHONE_Q, is_abroad_number
        for phone in ["12025550123", "+447911123456"]:
            self.assertTrue(is_abroad_number(phone), phone)
        for phone in ["2348106904663", "08106904663", "+2348106904663", "8033645283", "x4021", ""]:
            self.assertFalse(is_abroad_number(phone), phone)
        CustomUser.objects.create_user(email="uk@example.com", password="x", phone_number="447911123456")
        CustomUser.objects.create_user(email="ng@example.com", password="x", phone_number="2348106904663")
        self.assertEqual(list(CustomUser.objects.filter(ABROAD_PHONE_Q).values_list("email", flat=True)), ["uk@example.com"])


class SignupConversionTests(TestCase):
    def test_compares_at_the_same_point(self):
        from authentication.models import Transaction
        from authentication.utils import points_change, signup_conversion
        now = timezone.now()
        a = CustomUser.objects.create_user(email="a@example.com", password="x", phone_number="2348100000001")
        b = CustomUser.objects.create_user(email="b@example.com", password="x", phone_number="2348100000002")
        tx = Transaction.objects.create(user=a, transaction_type="credit", status="confirmed", amount=100,
                                        credited_to="SAVINGS", transaction_id="CONV-1")
        Transaction.objects.filter(pk=tx.pk).update(date=now)
        users = CustomUser.objects.filter(pk__in=[a.pk, b.pk])
        self.assertEqual(signup_conversion(users), (2, 1, 50.0))
        # Only deposits made before the cutoff count.
        self.assertEqual(signup_conversion(users, saved_by=now - timedelta(days=1)), (2, 0, 0.0))
        self.assertEqual(points_change(16.4, 11.5), "+4.9 pts")
        self.assertEqual(points_change(10, 12.5), "-2.5 pts")
        self.assertIsNone(points_change(None, 5))
