import io
import tempfile
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from PIL import Image
from rest_framework.test import APIClient

from authentication.models import AmbassadorCohort, AmbassadorMonthlyReport, AmbassadorReportEvidence, CustomUser


def png(name):
    buf = io.BytesIO()
    Image.new("RGB", (4, 4), "purple").save(buf, "PNG")
    return SimpleUploadedFile(name, buf.getvalue(), content_type="image/png")


@override_settings(MEDIA_ROOT=tempfile.mkdtemp())
@patch("authentication.views.send_ambassador_report_notifications_task")
class ReportEvidenceTests(TestCase):
    """Several images per evidence type: the first in the report's own
    field (older apps keep working), the rest as extra evidence rows."""

    def setUp(self):
        cohort = AmbassadorCohort.objects.create(cohort_number=4, status="active")
        self.user = CustomUser.objects.create_user(
            email="amb@x.com", password="x", first_name="Amb", last_name="B", phone_number="08039990001",
            is_ambassador=True, ambassador_cohort=cohort)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.month = timezone.localdate().strftime("%Y-%m")

    def post(self, **files):
        data = {"month": self.month, "coursera_submitted": "3", **files}
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post("/api/ambassador-report/", data, format="multipart")

    def test_extra_certificates_are_kept_and_shown_to_reviewers(self, _task):
        res = self.post(coursera_certificate=png("one.png"), coursera_certificate_more=[png("two.png"), png("three.png")])
        self.assertEqual(res.status_code, 201, res.data)
        report = AmbassadorMonthlyReport.objects.get()
        self.assertTrue(report.coursera_certificate)
        self.assertEqual(list(report.extra_evidence.values_list("field", flat=True)), ["coursera_certificate"] * 2)

        from authentication.admin_views import _ambassador_report_data
        request = APIClient().get("/").wsgi_request
        data = _ambassador_report_data(request, report)
        self.assertEqual(len(data["evidence_files"]["coursera_certificate"]), 3)
        self.assertEqual(data["evidence"]["coursera_certificate"], data["evidence_files"]["coursera_certificate"][0])

    def test_one_image_still_works_and_bad_extras_are_refused(self, _task):
        self.assertEqual(self.post(coursera_certificate=png("one.png")).status_code, 201)
        self.assertFalse(AmbassadorReportEvidence.objects.exists())
        AmbassadorMonthlyReport.objects.all().delete()

        bad = SimpleUploadedFile("x.png", b"not an image", content_type="image/png")
        res = self.post(coursera_certificate=png("one.png"), coursera_certificate_more=[bad])
        self.assertEqual(res.status_code, 400)
        self.assertFalse(AmbassadorMonthlyReport.objects.exists())  # nothing half-saved
