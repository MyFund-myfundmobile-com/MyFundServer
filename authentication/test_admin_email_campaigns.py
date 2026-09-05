"""
Tests for the admin Email Campaigns endpoints (authentication/admin_views.py:
create_email_campaign, list_email_campaigns, send_next_email_campaign_batch,
send_extra_email_campaign_batch, cancel_email_campaign) - the day-by-day,
admin-triggered batching for segment sends larger than Brevo's 300/day
cap: 280/day automatically, plus an optional same-day top-up of up to 20
more via send_extra_email_campaign_batch.
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
    """
    Sending itself happens off-request, in send_email_campaign_batch_task
    (see EmailCampaignBatchTaskTest below) - a synchronous inline send of
    up to 280 recipients reliably exceeded the platform's request timeout
    partway through (real incident, 2026-08-26: 4 people got emailed but
    the campaign record still showed 0 sent, since the request died
    before it could save that). These tests only cover what the view
    itself does: build the recipient snapshot and dispatch the task -
    mocking send_email_campaign_batch_task.delay so no real Celery broker
    is needed.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("campaignstaff1@example.com", "97000000002", is_staff=True)
        self.client.force_authenticate(user=self.staff)

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_small_segment_dispatches_background_task(self, mock_delay):
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
        # Nothing has actually sent yet - that's the task's job, in the
        # background. is_sending gates both batch buttons off in the
        # meantime.
        self.assertEqual(response.data["sent_count"], 0)
        self.assertEqual(response.data["status"], "in_progress")
        self.assertTrue(response.data["is_sending"])
        self.assertFalse(response.data["can_send_next_batch"])
        self.assertFalse(response.data["can_send_extra_today"])

        mock_delay.assert_called_once()
        args, kwargs = mock_delay.call_args
        self.assertEqual(len(args[1]), 2)
        self.assertTrue(kwargs.get("is_first_batch"))
        self.assertFalse(kwargs.get("is_extra_batch"))

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_large_segment_dispatches_280_capped_first_batch(self, mock_delay):
        for i in range(320):
            _make_user(f"bulk{i}@example.com", f"971{i:08d}")

        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {"subject": "Bulk", "body": "<p>Hi</p>"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # 320 bulk users + the staff account itself = 321 total matches
        # (no filters means "everyone"). Base batch is 280, not 300.
        self.assertEqual(response.data["total_recipients"], 321)
        self.assertEqual(response.data["sent_count"], 0)
        self.assertEqual(response.data["status"], "in_progress")
        self.assertTrue(response.data["is_sending"])

        args, kwargs = mock_delay.call_args
        dispatched_batch = args[1]
        self.assertEqual(len(dispatched_batch), 280)

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_extra_emails_prioritized_into_day_one_batch(self, mock_delay):
        # 300 segment matches (well over the 280 base batch) plus 2 hand-
        # typed extra emails that aren't in the segment at all - the extras
        # must still land in day one's batch, not get queued behind 280
        # segment matches.
        for i in range(299):
            _make_user(f"seg{i}@example.com", f"972{i:08d}", is_ambassador=True)

        response = self.client.post(
            reverse("admin_create_email_campaign"),
            {
                "subject": "Hello",
                "body": "<p>Hi</p>",
                "is_ambassador": True,
                "extra_emails": ["outsider1@example.com", "OUTSIDER2@Example.com"],
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # 299 ambassadors + 2 extras = 301 total.
        self.assertEqual(response.data["total_recipients"], 301)

        args, kwargs = mock_delay.call_args
        dispatched_batch = args[1]
        self.assertIn("outsider1@example.com", dispatched_batch)
        # Extra emails are lowercased/deduped like everything else.
        self.assertIn("outsider2@example.com", dispatched_batch)

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
            sent_count=280,
            failed_count=0,
            status="in_progress",
            last_batch_sent_at=timezone.now(),
        )

    def test_rejects_second_batch_same_day(self):
        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_next_day_dispatches_remainder(self, mock_delay):
        self.campaign.last_batch_sent_at = timezone.now() - timedelta(days=1)
        self.campaign.save(update_fields=["last_batch_sent_at"])

        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Dispatch, not delivery - sent_count is still whatever it was
        # (280) until the background task actually runs.
        self.assertEqual(response.data["sent_count"], 280)
        self.assertTrue(response.data["is_sending"])
        self.assertEqual(response.data["status"], "in_progress")

        args, kwargs = mock_delay.call_args
        dispatched_batch = args[1]
        self.assertEqual(len(dispatched_batch), 40)
        self.assertFalse(kwargs.get("is_first_batch"))
        self.assertFalse(kwargs.get("is_extra_batch"))

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_next_day_resets_extra_allowance(self, mock_delay):
        self.campaign.extra_sent_today = 20
        self.campaign.last_batch_sent_at = timezone.now() - timedelta(days=1)
        self.campaign.save(update_fields=["extra_sent_today", "last_batch_sent_at"])

        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["extra_sent_today"], 0)
        self.assertEqual(response.data["extra_remaining_today"], 20)

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_rejects_when_already_sending(self, mock_delay):
        self.campaign.last_batch_sent_at = timezone.now() - timedelta(days=1)
        self.campaign.is_sending = True
        self.campaign.save(update_fields=["last_batch_sent_at", "is_sending"])

        response = self.client.post(
            reverse("admin_send_next_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_delay.assert_not_called()

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


class SendExtraBatchTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("campaignstaff5@example.com", "97000000008", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        # 320 total, 280 already sent today (the base batch) - 40 remain.
        self.campaign = EmailCampaign.objects.create(
            subject="Bulk",
            body_html="<p>Hi</p>",
            created_by=self.staff,
            recipient_emails=[f"batch{i}@example.com" for i in range(320)],
            total_recipients=320,
            sent_count=280,
            failed_count=0,
            status="in_progress",
            last_batch_sent_at=timezone.now(),
        )

    def test_rejects_when_base_batch_not_sent_today(self):
        self.campaign.last_batch_sent_at = timezone.now() - timedelta(days=1)
        self.campaign.save(update_fields=["last_batch_sent_at"])
        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_dispatches_up_to_20_extra(self, mock_delay):
        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Still 280 (unchanged) in the response - the task hasn't run yet.
        self.assertEqual(response.data["sent_count"], 280)
        self.assertTrue(response.data["is_sending"])
        self.assertEqual(response.data["status"], "in_progress")

        args, kwargs = mock_delay.call_args
        dispatched_batch = args[1]
        self.assertEqual(len(dispatched_batch), 20)
        self.assertTrue(kwargs.get("is_extra_batch"))

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_rejects_once_extra_allowance_used_up(self, mock_delay):
        self.campaign.extra_sent_today = 20
        self.campaign.save(update_fields=["extra_sent_today"])
        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_delay.assert_not_called()

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_rejects_when_already_sending(self, mock_delay):
        self.campaign.is_sending = True
        self.campaign.save(update_fields=["is_sending"])
        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_delay.assert_not_called()

    @patch("authentication.tasks.send_email_campaign_batch_task.delay")
    def test_extra_batch_dispatches_a_small_remainder(self, mock_delay):
        # Only 10 left in the queue - the extra batch should dispatch
        # exactly those 10, not error out.
        self.campaign.sent_count = 310
        self.campaign.save(update_fields=["sent_count"])

        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_sending"])

        args, kwargs = mock_delay.call_args
        dispatched_batch = args[1]
        self.assertEqual(len(dispatched_batch), 10)

    def test_completed_campaign_rejects_extra_batch(self):
        self.campaign.status = "completed"
        self.campaign.save(update_fields=["status"])
        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[self.campaign.id])
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_nonexistent_campaign_404(self):
        response = self.client.post(
            reverse("admin_send_extra_email_campaign_batch", args=[999999])
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class EmailCampaignBatchTaskTest(TestCase):
    """
    send_email_campaign_batch_task (tasks.py) - the actual send loop that
    used to run inline inside the view (see module docstring above for
    why that broke). Called directly as a plain function here (Celery
    tasks are just callables outside of .delay()/.apply_async()), with
    send_email_via_brevo and time.sleep mocked so these run fast and
    without hitting Brevo for real.
    """

    def setUp(self):
        self.staff = _make_user("batchtaskstaff@example.com", "97000000009", is_staff=True)
        self.campaign = EmailCampaign.objects.create(
            subject="Task Test",
            body_html="<p>Hi {first_name}</p>",
            created_by=self.staff,
            recipient_emails=["a@example.com", "b@example.com", "c@example.com"],
            total_recipients=3,
            status="in_progress",
            is_sending=True,
        )

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_persists_progress_incrementally_per_recipient(self, mock_brevo, mock_sleep):
        # This is the core fix: sent_count must already reflect each send
        # as it happens, not only once at the very end - otherwise a crash
        # partway through a batch (the actual 2026-08-26 incident) loses
        # track of who was really emailed.
        from .tasks import send_email_campaign_batch_task

        seen_counts = []

        def _record_and_send(**kwargs):
            seen_counts.append(
                EmailCampaign.objects.get(pk=self.campaign.id).sent_count
            )

        mock_brevo.side_effect = _record_and_send

        send_email_campaign_batch_task(
            self.campaign.id,
            ["a@example.com", "b@example.com", "c@example.com"],
            is_first_batch=True,
        )

        # sent_count seen *during* each call - proves it's incremented
        # as-we-go (0, then 1, then 2), not stuck at 0 until the end.
        self.assertEqual(seen_counts, [0, 1, 2])

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.sent_count, 3)
        self.assertEqual(self.campaign.status, "completed")
        self.assertFalse(self.campaign.is_sending)

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_tracks_failures_without_losing_successes(self, mock_brevo, mock_sleep):
        from .tasks import send_email_campaign_batch_task

        def _side_effect(to_email, **kwargs):
            if to_email == "b@example.com":
                raise Exception("Brevo rejected")

        mock_brevo.side_effect = _side_effect

        send_email_campaign_batch_task(
            self.campaign.id,
            ["a@example.com", "b@example.com", "c@example.com"],
            is_first_batch=True,
        )

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.sent_count, 2)
        self.assertEqual(self.campaign.failed_count, 1)
        self.assertEqual(self.campaign.failed_emails, ["b@example.com"])
        self.assertEqual(self.campaign.status, "completed")
        self.assertFalse(self.campaign.is_sending)

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.views.finalize_email_template")
    @patch("authentication.views.create_pending_email_template")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_auto_saves_template_only_on_first_batch_with_sends(
        self, mock_brevo, mock_create, mock_finalize, mock_sleep
    ):
        from .tasks import send_email_campaign_batch_task

        send_email_campaign_batch_task(
            self.campaign.id, ["a@example.com"], is_first_batch=True,
        )
        mock_create.assert_called_once()
        mock_finalize.assert_called_once()

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.views.finalize_email_template")
    @patch("authentication.views.create_pending_email_template")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_does_not_auto_save_on_later_batches(
        self, mock_brevo, mock_create, mock_finalize, mock_sleep
    ):
        from .tasks import send_email_campaign_batch_task

        send_email_campaign_batch_task(
            self.campaign.id, ["a@example.com"], is_first_batch=False,
        )
        mock_create.assert_not_called()
        mock_finalize.assert_not_called()

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_extra_batch_increments_extra_sent_today(self, mock_brevo, mock_sleep):
        from .tasks import send_email_campaign_batch_task

        self.campaign.extra_sent_today = 5
        self.campaign.save(update_fields=["extra_sent_today"])

        send_email_campaign_batch_task(
            self.campaign.id,
            ["a@example.com", "b@example.com"],
            is_extra_batch=True,
        )

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.extra_sent_today, 7)

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_unknown_campaign_id_does_not_raise(self, mock_brevo, mock_sleep):
        from .tasks import send_email_campaign_batch_task

        # Should log and return quietly, not blow up the Celery worker.
        send_email_campaign_batch_task(999999, ["a@example.com"])
        mock_brevo.assert_not_called()


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


class BrevoDailyUsageTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("brevostaff@example.com", "99000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

    def test_non_staff_rejected(self):
        regular = _make_user("brevoregular@example.com", "99000000002")
        self.client.force_authenticate(user=regular)
        response = self.client.get(reverse("admin_brevo_daily_usage"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("sib_api_v3_sdk.TransactionalEmailsApi.get_email_event_report")
    def test_reports_usage_from_live_brevo_event_log(self, mock_report):
        from unittest.mock import MagicMock
        mock_report.return_value = MagicMock(events=[MagicMock() for _ in range(24)])

        response = self.client.get(reverse("admin_brevo_daily_usage"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["used_today"], 24)
        self.assertEqual(response.data["daily_limit"], 300)
        self.assertEqual(response.data["remaining_today"], 276)
        self.assertFalse(response.data["near_limit"])

        # Confirms this queries Brevo's real event log, not a local
        # counter - "requests" is the actual send-attempt event.
        self.assertEqual(mock_report.call_args.kwargs.get("event"), "requests")

    @patch("sib_api_v3_sdk.TransactionalEmailsApi.get_email_event_report")
    def test_near_limit_flag(self, mock_report):
        from unittest.mock import MagicMock
        mock_report.return_value = MagicMock(events=[MagicMock() for _ in range(285)])

        response = self.client.get(reverse("admin_brevo_daily_usage"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["near_limit"])
        self.assertEqual(response.data["remaining_today"], 15)
