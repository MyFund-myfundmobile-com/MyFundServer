from types import SimpleNamespace
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from .exec_interest_models import ExecutiveInterest
from .models import AmbassadorCohort, CustomUser

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
ANSWER = "I have led my department's welfare team for two years."


def photo(content=PNG, name="me.png", kind="image/png"):
    return SimpleUploadedFile(name, content, content_type=kind)


@mock.patch("authentication.exec_interest.send_push_notification")
@mock.patch("authentication.exec_interest.send_transactional_email")
@mock.patch("authentication.exec_interest._upload_photo", return_value=("file1", "https://ik.imagekit.io/x/me.png"))
class ExecInterestTest(TestCase):
    def setUp(self):
        self.cohort = AmbassadorCohort.objects.create(cohort_number=4, status="active")
        self.amb = CustomUser.objects.create_user(email="amb@example.com", phone_number="08000000001",
                                                  password="x", first_name="Ada", last_name="Obi")
        CustomUser.objects.filter(pk=self.amb.pk).update(is_ambassador=True, ambassador_cohort=self.cohort)
        self.client = APIClient()

    def post(self, **over):
        body = {"email": " AMB@example.com ", "role": "lead", "why_fit": ANSWER, "ideas": ANSWER,
                "why_vote": ANSWER, "photo": photo(), **over}
        body = {k: v for k, v in body.items() if v is not None}
        return self.client.post("/api/ambassador-exec/interest/", body, format="multipart")

    def test_ambassador_submits(self, upload, *_):
        res = self.post()
        self.assertEqual(res.status_code, 201, res.data)
        e = ExecutiveInterest.objects.get()
        self.assertEqual((e.user_id, e.cohort_id, e.role, e.photo_url),
                         (self.amb.id, self.cohort.id, "lead", "https://ik.imagekit.io/x/me.png"))
        self.assertEqual(res.data["role_name"], "Lead")

    def test_resubmitting_updates_and_keeps_photo(self, upload, *_):
        self.post()
        res = self.post(role="secretary", photo=None)
        self.assertEqual(res.status_code, 200, res.data)
        self.assertTrue(res.data["updated"])
        e = ExecutiveInterest.objects.get()
        self.assertEqual((e.role, e.photo_url), ("secretary", "https://ik.imagekit.io/x/me.png"))
        self.assertEqual(upload.call_count, 1)

    def test_rejections(self, upload, *_):
        self.assertEqual(self.post(email="nobody@example.com").status_code, 404)
        self.assertEqual(self.post(role="president").status_code, 400)
        self.assertEqual(self.post(ideas="ok").status_code, 400)
        self.assertEqual(self.post(photo=None).status_code, 400)  # photo needed first time
        self.assertFalse(ExecutiveInterest.objects.exists())

    def test_non_ambassador_refused(self, *_):
        CustomUser.objects.filter(pk=self.amb.pk).update(is_ambassador=False)
        self.assertEqual(self.post().status_code, 404)


class PhotoCheckTest(TestCase):
    def test_rejects_non_images(self):
        from .exec_interest import _upload_photo
        user = SimpleNamespace(pk=1)
        with self.assertRaises(ValueError):
            _upload_photo(photo(b"%PDF-1.4" + b"\x00" * 64, "cv.pdf", "application/pdf"), user)
