"""
Tests for the admin email-campaign endpoints (authentication/views.py:
send_email, get_templates, get_template, save_template, update_template,
delete_template) - these were previously reachable by any authenticated
user (send_email) or with no auth check at all (the template CRUD views).
Tightened to IsAdminUser since the mobile Email tab now surfaces "send to
a whole user segment" as a one-tap admin action.
"""

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from .models import CustomUser, EmailTemplate


def _make_user(email, phone, **extra):
    extra.setdefault("first_name", "Test")
    extra.setdefault("last_name", "User")
    return CustomUser.objects.create_user(
        email=email,
        password="testpass123",
        phone_number=phone,
        **extra,
    )


class AdminEmailPermissionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.regular_user = _make_user("emailregular@example.com", "96000000001")
        self.staff = _make_user("emailstaff@example.com", "96000000002", is_staff=True)
        self.template = EmailTemplate.objects.create(
            title="Welcome Email",
            design_body="{}",
            design_html="<p>Hi</p>",
            last_update=timezone.now(),
        )

    def test_non_staff_rejected_on_every_email_endpoint(self):
        self.client.force_authenticate(user=self.regular_user)

        response = self.client.get(reverse("get_templates"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.get(reverse("get_template", args=[self.template.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.post(
            reverse("send_email"),
            {"subject": "Hi", "body": "<p>Hi</p>", "recipients": ["a@example.com"]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.post(
            reverse("save_template"),
            {"title": "New", "designBody": {}, "designHTML": "<p></p>", "lastUpdate": "2026-01-01"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.put(
            reverse("update_template", args=[self.template.id]),
            {"title": "Updated"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.delete(
            reverse("delete_template", args=[self.template.id])
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_staff_can_list_templates(self):
        self.client.force_authenticate(user=self.staff)
        response = self.client.get(reverse("get_templates"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        titles = [t["title"] for t in response.data]
        self.assertIn("Welcome Email", titles)

    @patch("authentication.views.send_generic_email")
    def test_staff_can_send_email(self, mock_send):
        mock_send.return_value = {"status": "completed", "sent": 1}
        self.client.force_authenticate(user=self.staff)
        response = self.client.post(
            reverse("send_email"),
            {
                "subject": "Hello",
                "body": "<p>Hello</p>",
                "recipients": ["recipient@example.com"],
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "success")
        mock_send.assert_called_once()

    @patch("authentication.views.send_generic_email")
    def test_send_reports_error_when_brevo_delivers_to_no_one(self, mock_send):
        # send_generic_email's inline path reports "completed" even when
        # every recipient failed at Brevo (each failure is caught and
        # tallied, not raised) - the view must not translate that into a
        # false "success" just because nothing raised.
        mock_send.return_value = {
            "status": "completed",
            "sent": 0,
            "failed": 1,
            "failed_emails": ["recipient@example.com"],
            "failure_reasons": ["recipient@example.com: ApiException: Unauthorized"],
        }
        self.client.force_authenticate(user=self.staff)
        response = self.client.post(
            reverse("send_email"),
            {
                "subject": "Hello",
                "body": "<p>Hello</p>",
                "recipients": ["recipient@example.com"],
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["status"], "error")
        self.assertIn("Unauthorized", response.data["message"])

    @patch("authentication.views.send_generic_email")
    def test_send_reports_partial_when_some_recipients_fail(self, mock_send):
        mock_send.return_value = {
            "status": "completed",
            "sent": 1,
            "failed": 1,
            "failed_emails": ["bad@example.com"],
            "failure_reasons": ["bad@example.com: ApiException: Invalid email"],
        }
        self.client.force_authenticate(user=self.staff)
        response = self.client.post(
            reverse("send_email"),
            {
                "subject": "Hello",
                "body": "<p>Hello</p>",
                "recipients": ["good@example.com", "bad@example.com"],
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(response.data["status"], "partial")
        self.assertEqual(response.data["failed_emails"], ["bad@example.com"])


class AutoSaveAsTemplateTest(TestCase):
    """
    send_email only auto-saves a template when the caller explicitly asks
    for it (save_as_template=True) - the webapp's own Unlayer "send" flow
    never sets this, so its already-saved templates don't get duplicated
    on every send.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("autosavestaff@example.com", "96000000003", is_staff=True)
        self.client.force_authenticate(user=self.staff)

    @patch("authentication.views.send_generic_email")
    def test_save_as_template_true_creates_template_on_success(self, mock_send):
        mock_send.return_value = {"status": "completed", "sent": 1}
        before = EmailTemplate.objects.count()

        response = self.client.post(
            reverse("send_email"),
            {
                "subject": "Quarterly Update",
                "body": "<p>Hello {first_name}</p>",
                "recipients": ["recipient@example.com"],
                "save_as_template": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(EmailTemplate.objects.count(), before + 1)

        created = EmailTemplate.objects.latest("id")
        self.assertTrue(created.title.startswith("Quarterly Update - "))
        self.assertEqual(created.design_html, "<p>Hello {first_name}</p>")

    @patch("authentication.views.send_generic_email")
    def test_omitting_save_as_template_does_not_create_one(self, mock_send):
        mock_send.return_value = {"status": "completed", "sent": 1}
        before = EmailTemplate.objects.count()

        response = self.client.post(
            reverse("send_email"),
            {
                "subject": "Webapp Send",
                "body": "<p>Hi</p>",
                "recipients": ["recipient@example.com"],
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(EmailTemplate.objects.count(), before)

    @patch("authentication.views.send_generic_email")
    def test_total_failure_does_not_create_a_template(self, mock_send):
        mock_send.return_value = {
            "status": "completed",
            "sent": 0,
            "failed": 1,
            "failed_emails": ["recipient@example.com"],
            "failure_reasons": ["recipient@example.com: ApiException: Unauthorized"],
        }
        before = EmailTemplate.objects.count()

        response = self.client.post(
            reverse("send_email"),
            {
                "subject": "Should Not Save",
                "body": "<p>Hi</p>",
                "recipients": ["recipient@example.com"],
                "save_as_template": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(EmailTemplate.objects.count(), before)

    @patch("authentication.views.send_generic_email")
    def test_duplicate_subject_gets_unique_title(self, mock_send):
        mock_send.return_value = {"status": "completed", "sent": 1}

        for _ in range(2):
            response = self.client.post(
                reverse("send_email"),
                {
                    "subject": "Same Subject",
                    "body": "<p>Hi</p>",
                    "recipients": ["recipient@example.com"],
                    "save_as_template": True,
                },
                format="json",
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        titles = list(
            EmailTemplate.objects.filter(title__startswith="Same Subject").values_list(
                "title", flat=True
            )
        )
        self.assertEqual(len(titles), 2)
        self.assertEqual(len(set(titles)), 2)  # both unique, no IntegrityError
