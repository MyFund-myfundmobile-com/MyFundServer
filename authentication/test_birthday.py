import datetime
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from authentication.birthday import birthday_message, birthday_users
from authentication.models import CustomUser
from authentication.tasks import send_birthday_greetings


def make_user(email, dob, kyc="approved", **extra):
    return CustomUser.objects.create_user(email=email, password="x-strong-pass-1", first_name="Ada",
                                          date_of_birth=dob, kyc_status=kyc, **extra)


class BirthdayTests(TestCase):
    def setUp(self):
        today = timezone.localdate()
        self.today = today
        self.saver = make_user("saver@example.com", today.replace(year=1990), phone_number="08033924595",
                               savings=Decimal("150000"))
        make_user("nokyc@example.com", today.replace(year=1990), kyc="not_started", phone_number="08030000001")
        make_user("placeholder@example.com", datetime.date(1900, today.month, today.day), phone_number="08030000002")

    def test_only_kyc_users_with_a_real_birthday_are_greeted(self):
        self.assertEqual(list(birthday_users(self.today)), [self.saver])

    def test_message_is_personal(self):
        msg = birthday_message(self.saver)
        self.assertIn("₦150,000", " ".join(msg["highlights"]))
        self.assertIn("₦150,000", msg["push_body"])
        self.assertLessEqual(len(msg["sms"]), 160)

    def at(self, hour, minute=5):
        return timezone.make_aware(datetime.datetime.combine(self.today, datetime.time(hour, minute)))

    @patch("authentication.utils.send_sms", return_value=True)
    @patch("authentication.utils.send_push_notification")
    @patch("authentication.utils.send_generic_email")
    def test_channels_go_out_at_different_times_once_each(self, email, push, sms):
        from authentication.models import BirthdayGreeting
        run = lambda h, m=5: patch("django.utils.timezone.now", return_value=self.at(h, m))
        with run(7):
            send_birthday_greetings()
        self.assertEqual((push.call_count, email.call_count, sms.call_count), (0, 0, 0))
        with run(13):  # late start: only push, even though email's hour has passed
            send_birthday_greetings()
            send_birthday_greetings()
        self.assertEqual((push.call_count, email.call_count, sms.call_count), (1, 0, 0))
        with run(13, 30):  # too soon after the push
            send_birthday_greetings()
        self.assertEqual(email.call_count, 0)
        with run(14):
            send_birthday_greetings()
        self.assertEqual((push.call_count, email.call_count, sms.call_count), (1, 1, 0))
        with run(15):
            send_birthday_greetings()
        with run(16):
            send_birthday_greetings()
        self.assertEqual((push.call_count, email.call_count, sms.call_count), (1, 1, 1))
        g = BirthdayGreeting.objects.get(user=self.saver)
        self.assertTrue(g.push_sent_at < g.email_sent_at < g.sms_sent_at)

    @patch("authentication.utils.send_push_notification")
    @patch("authentication.utils.send_generic_email", side_effect=RuntimeError("brevo down"))
    def test_failed_channel_is_not_retried_hourly(self, email, push):
        send_birthday_greetings(channel="email")
        send_birthday_greetings(channel="email")
        self.assertEqual(email.call_count, 1)
