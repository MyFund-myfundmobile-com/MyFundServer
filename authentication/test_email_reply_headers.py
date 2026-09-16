from unittest.mock import patch
from django.test import SimpleTestCase, override_settings
from .services.brevo_service import send_email_via_brevo


@override_settings(EMAIL_REPLY_TO="MyFund <ceo@myfundmobile.com>")
class EmailReplyHeadersTests(SimpleTestCase):
    @patch("authentication.services.brevo_service.get_brevo_client")
    @patch("authentication.services.brevo_service.sib_api_v3_sdk.TransactionalEmailsApi")
    def test_default_reply_address(self, api, client):
        send_email_via_brevo("reader@example.com", "Test", "<p>Hi</p>", from_email="MyFund <noreply@myfundmobile.com>")
        payload = api.return_value.send_transac_email.call_args.args[0]
        self.assertEqual(payload.reply_to["email"], "ceo@myfundmobile.com")

    @patch("authentication.services.brevo_service.get_brevo_client")
    @patch("authentication.services.brevo_service.sib_api_v3_sdk.TransactionalEmailsApi")
    def test_explicit_reply_address_preserved(self, api, client):
        send_email_via_brevo("reader@example.com", "Test", "<p>Hi</p>", reply_to="author@example.com")
        payload = api.return_value.send_transac_email.call_args.args[0]
        self.assertEqual(payload.reply_to["email"], "author@example.com")
