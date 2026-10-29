from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.first_savings import first_savings_status, send_first_savings_reminders
from authentication.models import CustomUser, Transaction


class FirstSavingsTests(TestCase):
    def make_user(self, n, days_ago, **fields):
        user = CustomUser.objects.create(email=f'new{n}@example.test', phone_number=f'0900000{n:04d}', first_name='New', **fields)
        CustomUser.objects.filter(pk=user.pk).update(date_joined=timezone.now() - timedelta(days=days_ago, hours=1))
        user.refresh_from_db()
        return user

    def deposit(self, user, n, status='confirmed', description='QuickSave (Transfer)'):
        Transaction.objects.create(user=user, transaction_type='credit', status=status, amount=1000,
                                   description=description, credited_to='SAVINGS', transaction_id=f'tx-{n}')

    def test_eligibility(self):
        new = self.make_user(1, 3)
        self.assertEqual(first_savings_status(new), {'eligible': True, 'pending_deposit': False})
        self.assertFalse(first_savings_status(self.make_user(2, 45))['eligible'])  # not new
        saved_then_withdrew = self.make_user(3, 3)
        self.deposit(saved_then_withdrew, 3)
        self.assertFalse(first_savings_status(saved_then_withdrew)['eligible'])
        self.assertFalse(first_savings_status(self.make_user(4, 3, savings=500))['eligible'])
        pending = self.make_user(5, 3)
        self.deposit(pending, 5, status='pending', description='QuickSave (Card)')
        self.assertEqual(first_savings_status(pending), {'eligible': True, 'pending_deposit': True})

    def test_endpoint(self):
        client = APIClient()
        client.force_authenticate(self.make_user(6, 1))
        self.assertTrue(client.get('/api/first-savings/status/').json()['eligible'])
        self.assertIn(APIClient().get('/api/first-savings/status/').status_code, [401, 403])

    def test_endpoint_includes_savers_this_week(self):
        cache.clear()
        for n in (20, 21):
            self.deposit(self.make_user(n, 40), n)
        self.deposit(self.make_user(22, 40), 22, status='pending')
        client = APIClient()
        client.force_authenticate(self.make_user(23, 1))
        self.assertEqual(client.get('/api/first-savings/status/').json()['savers_this_week'], 2)

    def test_reminder_taps_open_quicksave_with_first_save_amount(self):
        self.make_user(30, 2)
        with patch('authentication.utils.send_push_notification') as push:
            send_first_savings_reminders()
        call = push.call_args.kwargs
        self.assertIn("Dr. Tee", call['title'])
        self.assertEqual(call['data']['deep_link']['screen_params']['params']['quickSaveAmount'], 1000)

    def test_reminders_only_on_day_2_and_7_once(self):
        targets = [self.make_user(10, 2), self.make_user(11, 7)]
        self.make_user(12, 3)  # not a reminder day
        saver = self.make_user(13, 2)
        self.deposit(saver, 13)
        with patch('authentication.utils.send_push_notification') as push:
            self.assertEqual(send_first_savings_reminders(), 2)
            self.assertEqual({c.kwargs['user'] for c in push.call_args_list}, set(targets))
            self.assertEqual(push.call_args_list[0].kwargs['data']['deep_link']['screen_params']['screen'], 'Save')
        # Already sent - a second run the same day sends nothing.
        send_first_savings_reminders()
        self.assertEqual(send_first_savings_reminders(), 0)


class FirstSaveGuideTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = CustomUser.objects.create_user(email="guide@example.com", password="x", first_name="G", last_name="U", phone_number="08035550001")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def show_guide(self):
        return self.client.get("/api/first-savings/status/").data["show_guide"]

    def event(self, name):
        return self.client.post("/api/first-savings/guide/", {"event": name}, format="json")

    def test_once_a_day_and_stops_after_three_closes(self):
        from authentication.models import FirstSaveGuide

        for close in ("dismiss", "tap", "dismiss"):
            self.assertTrue(self.show_guide())
            self.event("shown")
            self.assertFalse(self.show_guide())  # already shown today
            self.event(close)
            FirstSaveGuide.objects.filter(user=self.user).update(last_shown_at=timezone.now() - timedelta(days=1))
        self.assertFalse(self.show_guide())
        guide = FirstSaveGuide.objects.get(user=self.user)
        self.assertEqual((guide.times_shown, guide.dismissals), (3, 3))
        self.assertIsNotNone(guide.tapped_at)

    def test_never_shown_once_they_have_saved(self):
        CustomUser.objects.filter(pk=self.user.pk).update(savings=500)
        self.user.refresh_from_db()
        self.assertFalse(self.show_guide())

    def test_older_never_savers_still_see_it(self):
        CustomUser.objects.filter(pk=self.user.pk).update(date_joined=timezone.now() - timedelta(days=200))
        self.assertTrue(self.show_guide())

    def test_rejects_unknown_event(self):
        self.assertEqual(self.event("explode").status_code, 400)
