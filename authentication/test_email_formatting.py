from unittest.mock import patch

from django.test import TestCase

from .models import CustomUser
from .utils import personalize_email_payload, plain_breaks_to_html


class PlainBreaksToHtmlTest(TestCase):
    """Plain-text messages keep their line breaks once rendered as HTML."""

    def test_plain_text_breaks_become_br(self):
        self.assertEqual(plain_breaks_to_html("Hi Ada,\n\nSaved.\n"), "Hi Ada,<br><br>Saved.")

    def test_html_messages_are_left_alone(self):
        message = "Hi Ada,<br><br>Your <b>QuickSave</b>\nwas successful."
        self.assertEqual(plain_breaks_to_html(message), message)

    def test_single_line_is_unchanged(self):
        self.assertEqual(plain_breaks_to_html("Hello"), "Hello")

    def test_rendered_email_keeps_paragraphs(self):
        html = personalize_email_payload("nobody@example.com", "Hi", "Line one\n\nLine two",
                                         template="email/email_light.html")["html_message"]
        self.assertIn("Line one<br><br>Line two", html)


class ReferralEmailFormattingTest(TestCase):
    def test_referrer_email_puts_reward_on_its_own_bold_line(self):
        n = iter(range(10))
        mk = lambda email, **extra: CustomUser.objects.create_user(
            email=email, password="x", first_name=email.split("@")[0].title(), last_name="B",
            phone_number=f"0804300{next(n):04d}", **extra)
        ambassador = mk("christine@example.com", is_ambassador=True)
        referred = mk("lion@example.com", referral=ambassador)
        with patch("authentication.utils.send_transactional_email") as send:
            referred.send_confirmation_email(ambassador, is_referrer=True)
        message = send.call_args.kwargs["message"]
        self.assertIn("<b>₦500.00 added to your wallet</b></span><br>for referring <b>Lion</b>.", message)
        self.assertIn("<br><br><b>P.S.</b> As our valued Ambassador", message)
        self.assertNotIn("\n", message)
        self.assertNotIn("Gbajabiamila", message)  # the template already has the footer
