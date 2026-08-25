"""
Tests for the admin Email Campaigns endpoints (authentication/admin_views.py:
create_email_campaign, list_email_campaigns, send_next_email_campaign_batch,
cancel_email_campaign) - the day-by-day, admin-triggered batching for
segment sends larger than Brevo's 300/day cap.
"""

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework.test import APIClient

from .models import CustomUser, EmailCampaign


def _make_user(email, phone, **extra):
    extra.setdefault("first_name", "Test")
    extra.setdefault("last_name", "User")
    return CustomUser.objects.create_user(
        email=email,
        password="testpass123",
        phone_number=phone,
        **extra,
    )


def _fake_send_result(recipient_list, **kwargs):
    return {
        "status": "completed",
        "sent": len(recipient_list),
        "failed": 0,
        "failed_emails": [],
    }


class AdminEmailCampaignPermissionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.regular_user = _make_user("campaignregular@example.com", "97000000001")

    def test_non_staff_rejected_on_every_endpoint(self):
        self.client.force_authenticate(user=self.regular_user)

        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {"subject": "Hi", "body": "<p>Hi</p>"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.get(reverse("admin_list_email_campaigns"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[1])
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.post(reverse("admin_cancel_email_campaign", args=[1]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class CreateEmailCampaignTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("campaignstaff1@example.com", "97000000002", is_staff=True)
        self.client.force_authenticate(user=self.staff)

    @patch("authentication.admin_views.send_generic_email", side_effect=_fake_send_result)
    def test_small_segment_completes_immediately(self, mock_send):
        _make_user("amb1@example.com", "97000000003", is_ambassador=True)
        _make_user("amb2@example.com", "97000000004", is_ambassador=True)

        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {"subject": "Hello", "body": "<p>Hi {first_name}</p>", "is_ambassador": True},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # staff isn't an ambassador, so only the 2 explicit ambassadors match.
        self.assertEqual(response.data["total_recipients"], 2)
        self.assertEqual(response.data["sent_count"], 2)
        self.assertEqual(response.data["status"], "completed")
        self.assertEqual(response.data["remaining_count"], 0)
        self.assertFalse(response.data["can_send_next_batch"])
        mock_send.assert_called_once()

    @patch("authentication.admin_views.send_generic_email", side_effect=_fake_send_result)
    def test_large_segment_stays_in_progress(self, mock_send):
        for i in range(320):
            _make_user(f"bulk{i}@example.com", f"971{i:08d}")

        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {"subject": "Bulk", "body": "<p>Hi</p>"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # 320 bulk users + the staff account itself = 321 total matches
        # (no filters means "everyone").
        self.assertEqual(response.data["total_recipients"], 321)
        self.assertEqual(response.data["sent_count"], 300)
        self.assertEqual(response.data["status"], "in_progress")
        self.assertEqual(response.data["remaining_count"], 21)
        self.assertFalse(response.data["can_send_next_batch"])  # sent today already

        sent_recipients = mock_send.call_args.kwargs["recipient_list"]
        self.assertEqual(len(sent_recipients), 300)

    def test_rejects_when_no_recipients_match(self):
        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {"subject": "Hi", "body": "<p>Hi</p>", "is_ambassador": True},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_rejects_missing_subject_or_body(self):
        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {"subject": "", "body": "<p>Hi</p>"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class SendNextBatchTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("campaignstaff2@example.com", "97000000005", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.campaign = EmailCampaign.objects.create(
            subject="Bulk",
            body_html="<p>Hi</p>",
            created_by=self.staff,
            recipient_emails=[f"batch{i}@example.com" for i in range(320)],
            total_recipients=320,
            sent_count=300,
            failed_count=0,
            status="in_progress",
            last_batch_sent_at=timezone.now(),
        )

    def test_rejects_second_batch_same_day(self):
        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("authentication.admin_views.send_generic_email", side_effect=_fake_send_result)
    def test_next_day_sends_remainder_and_completes(self, mock_send):
        self.campaign.last_batch_sent_at = timezone.now() - timedelta(days=1)
        self.campaign.save(update_fields=["last_batch_sent_at"])

        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["sent_count"], 320)
        self.assertEqual(response.data["remaining_count"], 0)
        self.assertEqual(response.data["status"], "completed")

        sent_recipients = mock_send.call_args.kwargs["recipient_list"]
        self.assertEqual(len(sent_recipients), 20)

    def test_completed_campaign_rejects_further_batches(self):
        self.campaign.status = "completed"
        self.campaign.save(update_fields=["status"])
        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_nonexistent_campaign_404(self):
        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[999999])
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class CancelEmailCampaignTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("campaignstaff3@example.com", "97000000006", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.campaign = EmailCampaign.objects.create(
            subject="Bulk",
            body_html="<p>Hi</p>",
            recipient_emails=["a@example.com"] * 320,
            total_recipients=320,
            sent_count=300,
            status="in_progress",
        )

    def test_cancel_stops_further_batches(self):
        response = self.client.post(
            reverse("admin_cancel_email_campaign", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "cancelled")

        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ListEmailCampaignsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("campaignstaff4@example.com", "97000000007", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        EmailCampaign.objects.create(
            subject="One", body_html="<p>1</p>", recipient_emails=["a@example.com"],
            total_recipients=1, sent_count=1, status="completed",
        )

    def test_lists_campaigns(self):
        response = self.client.get(reverse("admin_list_email_campaigns"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        subjects = [c["subject"] for c in response.data]
        self.assertIn("One", subjects)
        # recipient_emails/body_html must never be serialized back out.
        self.assertNotIn("recipient_emails", response.data[0])
        self.assertNotIn("body_html", response.data[0])


class UploadCampaignImageTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("imagestaff@example.com", "98000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

    def test_non_staff_rejected(self):
        regular = _make_user("imageregular@example.com", "98000000002")
        self.client.force_authenticate(user=regular)
        response = self.client.post(
            reverse("admin_upload_campaign_image"),
            {"image_base64": "abc", "filename": "a.jpg"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_missing_image_rejected(self):
        response = self.client.post(
            reverse("admin_upload_campaign_image"), {"filename": "a.jpg"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_oversized_image_rejected(self):
        # Base64 is ~4/3 the size of the decoded bytes, so this needs to
        # clear 5MB * 4/3 (~6.99MB) of base64 text to actually exceed the
        # 5MB decoded cap - anything smaller falls through to a real
        # (and here, un-mocked) ImageKit call instead of the size guard.
        oversized = "A" * (8 * 1024 * 1024)
        response = self.client.post(
            reverse("admin_upload_campaign_image"),
            {"image_base64": oversized, "filename": "a.jpg"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("authentication.views.upload_to_imagekit")
    def test_uploads_and_strips_data_url_prefix(self, mock_upload):
        mock_upload.return_value = "https://ik.imagekit.io/myfundmobile/campaign_1_123_abcd.jpg"
        response = self.client.post(
            reverse("admin_upload_campaign_image"),
            {"image_base64": "data:image/jpeg;base64,ZmFrZWRhdGE=", "filename": "photo.jpg"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["url"],
            "https://ik.imagekit.io/myfundmobile/campaign_1_123_abcd.jpg",
        )
        # The data: URL prefix must be stripped before handing off to
        # ImageKit, and the "campaign" prefix must be used, not "profile".
        called_data, called_user_id, called_filename = mock_upload.call_args.args
        self.assertEqual(called_data, "ZmFrZWRhdGE=")
        self.assertEqual(mock_upload.call_args.kwargs.get("prefix"), "campaign")
