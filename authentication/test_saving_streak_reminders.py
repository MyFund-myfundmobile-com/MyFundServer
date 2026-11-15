import calendar
from datetime import datetime, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

from django.test import TestCase
from rest_framework.test import APIClient

from authentication.active_saver_views import saving_stats, saving_summaries
from authentication.models import AutoSave, CustomUser, PushNotifications, TopSaverHistory, Transaction
from authentication.saving_streak_reminders import PUSH_TYPE, send_streak_reminders

WAT = ZoneInfo("Africa/Lagos")


def wat(year, month, day, hour=10):
    return datetime(year, month, day, hour, 5, tzinfo=WAT)


class SavingStreakReminderTests(TestCase):
    # 23 Nov 2026 is 7 days before month end; the 25th is 5.
    SEVEN_LEFT = wat(2026, 11, 23)

    def setUp(self):
        self.n = iter(range(100))
        self.rank = iter(range(1, 100))

    def user(self, email):
        return CustomUser.objects.create_user(email=email, password="x", first_name="Ada", last_name="B",
                                              phone_number=f"0803600{next(self.n):04d}")

    def saved_month(self, user, month, year):
        TopSaverHistory.objects.create(user=user, month=month, year=year, rank=next(self.rank), total_savings=Decimal("1"))

    def quicksave(self, user, when, amount="1000"):
        tx = Transaction.objects.create(user=user, transaction_type="credit", status="confirmed",
                                        amount=Decimal(amount), description="QuickSave: card")
        Transaction.objects.filter(pk=tx.pk).update(date=when)

    def reminders(self, user):
        return PushNotifications.objects.filter(user=user, data__type=PUSH_TYPE)

    def test_only_at_risk_savers_get_one_reminder_per_stage(self):
        at_risk, saved_now, on_autosave, never = (self.user(e) for e in ("r@x.com", "s@x.com", "a@x.com", "n@x.com"))
        for u in (at_risk, saved_now, on_autosave):
            self.saved_month(u, 9, 2026)
            self.saved_month(u, 10, 2026)
        # Saved this month, but the board hasn't been refreshed - still counts.
        self.quicksave(saved_now, self.SEVEN_LEFT - timedelta(days=2))
        AutoSave.objects.create(user=on_autosave, amount=500, frequency="weekly", active=True)

        self.assertEqual(send_streak_reminders(self.SEVEN_LEFT), 1)
        push = self.reminders(at_risk).get()
        self.assertIn("2-month savings streak", push.title)
        self.assertEqual(push.data["deep_link"]["screen_params"]["params"], {"quickSaveModalVisible": True})
        for u in (saved_now, on_autosave, never):
            self.assertFalse(self.reminders(u).exists())

        # Re-running the same day (beat retries, restarts) sends nothing new.
        self.assertEqual(send_streak_reminders(self.SEVEN_LEFT + timedelta(hours=1)), 0)
        # Not a reminder day.
        self.assertEqual(send_streak_reminders(wat(2026, 11, 25)), 0)
        # 3 days left and the last day are new stages.
        send_streak_reminders(wat(2026, 11, 27))
        send_streak_reminders(wat(2026, 11, 30))
        self.assertEqual(self.reminders(at_risk).count(), 3)

    def test_a_save_after_the_first_reminder_stops_the_rest(self):
        saver = self.user("late@x.com")
        self.saved_month(saver, 10, 2026)
        send_streak_reminders(self.SEVEN_LEFT)
        self.quicksave(saver, wat(2026, 11, 24))
        self.assertEqual(send_streak_reminders(wat(2026, 11, 27)), 0)
        self.assertEqual(self.reminders(saver).count(), 1)

    def test_a_withdrawal_that_cancels_the_save_keeps_them_at_risk(self):
        saver = self.user("net@x.com")
        self.saved_month(saver, 10, 2026)
        self.quicksave(saver, wat(2026, 11, 20))
        tx = Transaction.objects.create(user=saver, transaction_type="debit", status="confirmed", source="SAVINGS",
                                        amount=Decimal("1000"), description="Withdrawal: Savings > Wallet")
        Transaction.objects.filter(pk=tx.pk).update(date=wat(2026, 11, 21))
        self.assertEqual(send_streak_reminders(self.SEVEN_LEFT), 1)

    def test_streak_summary_counts_this_month_from_live_transactions(self):
        saver = self.user("live@x.com")
        now = wat(2026, 11, 10)
        self.saved_month(saver, 10, 2026)
        self.assertEqual(saving_summaries([saver.pk], now)[saver.pk]["streak_months"], 1)
        self.quicksave(saver, wat(2026, 11, 9))
        self.assertEqual(saving_summaries([saver.pk], now)[saver.pk]["streak_months"], 2)
        self.assertTrue(saving_stats(saver, now)["saved_this_month"])

    def test_endpoint_has_home_chip_fields(self):
        saver = self.user("chip@x.com")
        client = APIClient()
        client.force_authenticate(saver)
        data = client.get("/api/saving-streak/").data
        self.assertIn("days_left", data)
        self.assertFalse(data["autosave_on"])
        AutoSave.objects.create(user=saver, amount=500, frequency="weekly", active=True)
        self.assertTrue(client.get("/api/saving-streak/").data["autosave_on"])
