import base64
from io import BytesIO
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from PIL import Image
from rest_framework.test import APIClient

from .models import CustomUser


def big_photo():
    """A >5MB PNG of noise (like a full-resolution phone photo)."""
    import os
    img = Image.frombytes("RGB", (1800, 1100), os.urandom(1800 * 1100 * 3))
    out = BytesIO()
    img.save(out, format="PNG")
    data = out.getvalue()
    assert len(data) > 5 * 1024 * 1024
    return data


class LargeKycIdPhotoTest(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(email="kyc@example.com", password="x", first_name="K", last_name="Y", phone_number="08039100001")
        CustomUser.objects.filter(pk=self.user.pk).update(profile_picture="https://ik.imagekit.io/myfundmobile/p.jpg")
        self.user.refresh_from_db()
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @patch("authentication.views.upload_to_imagekit", return_value="https://ik.imagekit.io/myfundmobile/kyc_test.jpg")
    def test_large_photo_is_shrunk_not_rejected(self, upload):
        photo = SimpleUploadedFile("license.png", big_photo(), content_type="image/png")
        res = self.client.patch("/api/update-kyc/", {"identification_type": "Driver's License", "id_upload": photo}, format="multipart")
        self.assertNotEqual(res.status_code, 400, getattr(res, "data", None))
        encoded, _user_id, name = upload.call_args.args[:3]
        self.assertTrue(name.endswith(".jpg"))
        self.assertLess(len(base64.b64decode(encoded)), 5 * 1024 * 1024)
        self.user.refresh_from_db()
        self.assertEqual(self.user.id_upload, "https://ik.imagekit.io/myfundmobile/kyc_test.jpg")

    def test_non_image_over_limit_gets_clear_message(self):
        junk = SimpleUploadedFile("license.png", b"x" * (5 * 1024 * 1024 + 10), content_type="image/png")
        res = self.client.patch("/api/update-kyc/", {"id_upload": junk}, format="multipart")
        self.assertEqual(res.status_code, 400)
        self.assertIn("clear photo", str(res.data))
