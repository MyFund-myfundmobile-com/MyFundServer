from datetime import date

from django.test import TestCase
from rest_framework.test import APIClient

from .models import CustomUser


class KycDateOfBirthTest(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(email="dob@example.com", password="x", first_name="D", last_name="B", phone_number="08039100002")
        CustomUser.objects.filter(pk=self.user.pk).update(profile_picture="https://ik.imagekit.io/myfundmobile/p.jpg")
        self.user.refresh_from_db()
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def patch_dob(self, value):
        return self.client.patch("/api/update-kyc/", {"date_of_birth": value}, format="multipart")

    def test_valid_date_saves(self):
        res = self.patch_dob("1995-06-15")
        self.assertEqual(res.status_code, 200, getattr(res, "data", None))
        self.user.refresh_from_db()
        self.assertEqual(self.user.date_of_birth, date(1995, 6, 15))

    def test_impossible_dates_are_refused(self):
        today = date.today()
        for value, message in [
            (today.isoformat(), "at least 13"),
            (date(today.year + 1, 1, 1).isoformat(), "future"),
            ("1900-01-01", "real date of birth"),
        ]:
            res = self.patch_dob(value)
            self.assertEqual(res.status_code, 400, value)
            self.assertIn(message, str(res.data["date_of_birth"]))
