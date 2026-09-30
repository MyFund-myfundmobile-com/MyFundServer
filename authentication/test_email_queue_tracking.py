"""Delivery tags survive individual sends and deferred daily batches."""
from unittest.mock import patch
from django.test import SimpleTestCase
from .tasks import send_bulk_email_task
from .utils import send_generic_email


class QueuedEmailTrackingTest(SimpleTestCase):
    @patch("authentication.tasks.send_bulk_email_task.apply_async")
    @patch("authentication.utils.personalize_email_payload")
    def test_forced_queue_preserves_template_tag(self, personalize, enqueue):
        personalize.return_value = {
            "to": "reader@example.com", "subject": "Hello", "html_message": "Hi",
        }
        result = send_generic_email(
            "Hello", "Hi", ["reader@example.com"],
            tags=["template-42"], force_queue=True,
        )
        self.assertEqual(result["status"], "queued")
        self.assertEqual(enqueue.call_args.kwargs["args"][0][0]["tags"], ["template-42"])

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    @patch("authentication.tasks.send_bulk_email_task.apply_async")
    def test_daily_batches_send_with_same_tag(self, enqueue, send, sleep):
        payloads = [
            {"to": f"reader{i}@example.com", "subject": "Hello",
             "html_message": "Hi", "tags": ["template-42"]}
            for i in range(2)
        ]
        with patch("authentication.services.brevo_service.DAILY_EMAIL_LIMIT", 1):
            first = send_bulk_email_task.run(payloads, "hello@example.com")
            self.assertEqual(first["remaining_scheduled"], 1)
            send.assert_called_once_with(
                to_email="reader0@example.com", subject="Hello", html_content="Hi",
                from_email="hello@example.com", tags=["template-42"],
            )
            deferred = enqueue.call_args.kwargs
            self.assertEqual(deferred["countdown"], 86400)
            self.assertEqual(deferred["args"][0][0]["tags"], ["template-42"])
            send_bulk_email_task.run(*deferred["args"])
            self.assertEqual(send.call_args.kwargs["tags"], ["template-42"])
            self.assertEqual(send.call_args.kwargs["to_email"], "reader1@example.com")

    @patch("authentication.tasks.time.sleep")
    @patch("authentication.services.brevo_service.send_email_via_brevo")
    def test_old_untagged_jobs_still_send(self, send, sleep):
        result = send_bulk_email_task.run(
            [{"to": "reader@example.com", "subject": "Hello", "html_message": "Hi"}],
            "hello@example.com",
        )
        self.assertEqual(result["sent"], 1)
        self.assertIsNone(send.call_args.kwargs["tags"])
