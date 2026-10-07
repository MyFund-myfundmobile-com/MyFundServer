from datetime import datetime, timedelta, timezone as dt_tz
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .foya import send_due_foya_pushes, today_payload
from .foya_models import WAT, FoyaCampaign, FoyaEvent, FoyaPush
from .models import CustomUser

CATEGORIES = [
    {"key": "founder", "label": "Founder of the Year", "url": "https://foyaglobal.com/f"},
    {"key": "realestate", "label": "Real Estate & Urban Development", "url": "https://foyaglobal.com/r"},
    {"key": "fintech", "label": "Fintech & Financial Innovation", "url": "https://foyaglobal.com/x"},
]
SCHEDULE = {"0": "founder", "1": "realestate", "2": "founder", "3": "fintech", "4": "founder", "5": "realestate", "6": "founder"}
# Lagos wall-clock times used below (2026-10-05 is a Monday).
MON_NOON = datetime(2026, 10, 5, 12, 0, tzinfo=WAT)


def campaign(**extra):
    defaults = dict(is_active=True, start_at=datetime(2026, 10, 1, tzinfo=WAT),
                    end_at=datetime(2026, 11, 4, 21, 59, tzinfo=WAT), categories=CATEGORIES, weekday_schedule=SCHEDULE)
    return FoyaCampaign.objects.create(**{**defaults, **extra})


class FoyaTodayTest(TestCase):
    def test_weekday_mapping_uses_lagos_time_around_midnight(self):
        c = campaign()
        # 22:59 UTC Monday = 23:59 Lagos Monday -> founder
        self.assertEqual(c.category_for(datetime(2026, 10, 5, 22, 59, tzinfo=dt_tz.utc))["key"], "founder")
        # 23:00 UTC Monday = 00:00 Lagos Tuesday -> realestate (UTC still says Monday)
        self.assertEqual(c.category_for(datetime(2026, 10, 5, 23, 0, tzinfo=dt_tz.utc))["key"], "realestate")
        self.assertEqual(c.category_for(datetime(2026, 10, 8, 9, 0, tzinfo=WAT))["key"], "fintech")  # Thursday

    def test_payload_active_and_inactive(self):
        c = campaign()
        data = today_payload(MON_NOON)
        self.assertTrue(data["active"])
        self.assertEqual(data["category"]["label"], "Founder of the Year")
        self.assertEqual(data["signup_url"], "https://foyaglobal.com/signup")
        # After the vote closes, before it starts, or switched off -> inactive.
        self.assertFalse(today_payload(datetime(2026, 11, 4, 22, 0, tzinfo=WAT))["active"])
        self.assertFalse(today_payload(datetime(2026, 9, 30, 12, 0, tzinfo=WAT))["active"])
        c.is_active = False
        c.save()
        self.assertFalse(today_payload(MON_NOON)["active"])

    def test_endpoint_is_public(self):
        campaign(start_at=timezone.now() - timedelta(days=1), end_at=timezone.now() + timedelta(days=1))
        res = APIClient().get("/api/foya-campaign/today/")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.data["active"])
        self.assertEqual(set(res.data["category"]), {"key", "label", "url"})

    def test_event_logging(self):
        user = CustomUser.objects.create_user(email="v@example.com", password="x", first_name="V", last_name="T", phone_number="08035000001")
        client = APIClient()
        client.force_authenticate(user)
        res = client.post("/api/foya-campaign/event/", {"event": "vote_tap", "category": "fintech", "source": "push"}, format="json")
        self.assertEqual(res.status_code, 201)
        e = FoyaEvent.objects.get()
        self.assertEqual((e.user, e.event, e.category_key, e.source), (user, "vote_tap", "fintech", "push"))
        self.assertEqual(client.post("/api/foya-campaign/event/", {"event": "hack"}, format="json").status_code, 400)


@patch("authentication.foya.time.sleep", lambda s: None)
@patch("authentication.utils.send_push_notification")
class FoyaPushTest(TestCase):
    def setUp(self):
        self.c = campaign()
        mk = lambda email, phone, **extra: CustomUser.objects.create_user(email=email, password="x", first_name="A", last_name="B", phone_number=phone, **extra)
        token = [{"token": "ExponentPushToken[x]"}]
        self.fan = mk("fan@example.com", "08036000001")
        self.fan.expo_push_tokens = token
        self.fan.save()
        self.opted_out = mk("quiet@example.com", "08036000002")
        self.opted_out.expo_push_tokens = token
        self.opted_out.notification_preferences = {**self.opted_out.notification_preferences, "admin_messages": False}
        self.opted_out.save()
        mk("notoken@example.com", "08036000003")
        self.default_prefs = mk("default@example.com", "08036000004")
        self.default_prefs.expo_push_tokens = token
        self.default_prefs.notification_preferences = {}  # never touched their settings
        self.default_prefs.save()
        self.push = FoyaPush.objects.create(campaign=self.c, slot="final_week", title="One week left", body="Vote",
                                            send_at=datetime(2026, 10, 28, 10, 0, tzinfo=WAT))

    def test_fourth_push_is_refused(self, send):
        FoyaPush.objects.create(campaign=self.c, slot="launch", title="t", body="b")
        FoyaPush.objects.create(campaign=self.c, slot="last_day", title="t", body="b")
        with self.assertRaises(ValidationError):
            FoyaPush.objects.create(campaign=self.c, slot="launch", title="4th", body="b")
        self.assertEqual(self.c.pushes.count(), 3)

    def test_sends_once_to_opted_in_users_only(self, send):
        send.return_value = {"sent": 1, "total": 1, "success": True}
        at = datetime(2026, 10, 28, 10, 0, tzinfo=WAT)
        self.assertEqual(send_due_foya_pushes(at), ["final_week"])
        self.assertEqual(sorted(c.args[0].email for c in send.call_args_list), ["default@example.com", "fan@example.com"])
        self.assertEqual(send.call_args.kwargs["data"], {"type": "foya_vote"})
        self.push.refresh_from_db()
        self.assertEqual((self.push.status, self.push.recipients_count), ("sent", 2))
        # A retry / the next hourly run must not send the slot again.
        self.assertEqual(send_due_foya_pushes(at + timedelta(minutes=5)), [])
        self.assertEqual(send.call_count, 2)

    def test_not_due_or_quiet_hours(self, send):
        self.assertEqual(send_due_foya_pushes(datetime(2026, 10, 28, 9, 0, tzinfo=WAT)), [])  # not yet due
        self.assertEqual(send_due_foya_pushes(datetime(2026, 10, 28, 21, 30, tzinfo=WAT)), [])  # quiet hours
        self.assertEqual(send_due_foya_pushes(datetime(2026, 10, 29, 7, 0, tzinfo=WAT)), [])  # still quiet
        send.assert_not_called()
        self.assertEqual(send_due_foya_pushes(datetime(2026, 10, 29, 8, 0, tzinfo=WAT)), ["final_week"])  # catches up at 8am

    def test_nothing_after_end_or_when_inactive(self, send):
        self.assertEqual(send_due_foya_pushes(datetime(2026, 11, 5, 10, 0, tzinfo=WAT)), [])
        self.c.is_active = False
        self.c.save()
        self.assertEqual(send_due_foya_pushes(datetime(2026, 10, 28, 10, 0, tzinfo=WAT)), [])
        send.assert_not_called()

    def test_unscheduled_launch_and_cancelled_never_send(self, send):
        FoyaPush.objects.create(campaign=self.c, slot="launch", title="t", body="b")  # no send_at yet
        self.push.status = "cancelled"
        self.push.save()
        self.assertEqual(send_due_foya_pushes(datetime(2026, 10, 30, 12, 0, tzinfo=WAT)), [])
        send.assert_not_called()
