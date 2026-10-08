from datetime import datetime, timedelta, timezone as dt_tz
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .foya import send_due_foya_pushes, today_payload
from .foya_models import WAT, FoyaCampaign, FoyaEvent, FoyaPosition, FoyaPush
from .models import CustomUser

CATEGORIES = [
    {"key": "founder", "label": "Founder of the Year", "url": "https://foyaglobal.com/f",
     "banner_body": "Today, vote for our founder, Dr. Tee, as **Founder of the Year**. It's free, once a day."},
    {"key": "realestate", "label": "Real Estate & Urban Development", "url": "https://foyaglobal.com/r"},
    {"key": "fintech", "label": "Fintech & Financial Innovation", "url": "https://foyaglobal.com/x"},
]
# Mon-Fri founder, Sat realestate, Sun fintech (migration 0116).
SCHEDULE = {"0": "founder", "1": "founder", "2": "founder", "3": "founder", "4": "founder", "5": "realestate", "6": "fintech"}
# Lagos wall-clock times used below (2026-10-05 is a Monday).
MON_NOON = datetime(2026, 10, 5, 12, 0, tzinfo=WAT)


def campaign(**extra):
    defaults = dict(is_active=True, start_at=datetime(2026, 10, 1, tzinfo=WAT),
                    end_at=datetime(2026, 11, 4, 21, 59, tzinfo=WAT), categories=CATEGORIES, weekday_schedule=SCHEDULE)
    return FoyaCampaign.objects.create(**{**defaults, **extra})


class FoyaTodayTest(TestCase):
    def test_weekday_mapping_uses_lagos_time_around_midnight(self):
        c = campaign()
        days = {d: c.category_for(datetime(2026, 10, 5 + d, 12, 0, tzinfo=WAT))["key"] for d in range(7)}
        self.assertEqual(days, {0: "founder", 1: "founder", 2: "founder", 3: "founder", 4: "founder", 5: "realestate", 6: "fintech"})
        # 22:59 UTC Friday = 23:59 Lagos Friday -> founder
        self.assertEqual(c.category_for(datetime(2026, 10, 9, 22, 59, tzinfo=dt_tz.utc))["key"], "founder")
        # 23:00 UTC Friday = 00:00 Lagos Saturday -> realestate (UTC still says Friday)
        self.assertEqual(c.category_for(datetime(2026, 10, 9, 23, 0, tzinfo=dt_tz.utc))["key"], "realestate")
        # 23:00 UTC Saturday = 00:00 Lagos Sunday -> fintech
        self.assertEqual(c.category_for(datetime(2026, 10, 10, 23, 0, tzinfo=dt_tz.utc))["key"], "fintech")

    def test_payload_active_and_inactive(self):
        c = campaign()
        data = today_payload(MON_NOON)
        self.assertTrue(data["active"])
        self.assertEqual(data["category"]["label"], "Founder of the Year")
        self.assertIn("**Founder of the Year**", data["category"]["banner_body"])
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
        self.assertEqual(set(res.data["category"]), {"key", "label", "url", "banner_body"})

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


class FoyaPositionTest(TestCase):
    def setUp(self):
        now = timezone.now()
        self.c = campaign(start_at=now - timedelta(days=1), end_at=now + timedelta(days=10), show_position=True)
        mk = lambda email, phone, **extra: CustomUser.objects.create_user(email=email, password="x", first_name="S", last_name="T", phone_number=phone, **extra)
        self.staff = mk("staff.foya@example.com", "08037000001", is_staff=True)
        self.member = mk("member.foya@example.com", "08037000002")
        self.client = APIClient()
        self.today_key = self.c.category_for()["key"]

    def save(self, rows, user=None):
        self.client.force_authenticate(user or self.staff)
        return self.client.post("/api/admin/foya/positions/", {"positions": rows}, format="json")

    def test_banner_position_rules(self):
        self.assertIsNone(today_payload()["position"])  # no data yet
        res = self.save([{"category_key": self.today_key, "position": 2, "field_size": 9, "is_tied": False}])
        self.assertEqual(res.status_code, 200, res.data)
        pos = today_payload()["position"]
        self.assertEqual((pos["position"], pos["field_size"], pos["is_tied"]), (2, 9, False))
        # Older than 48h -> hidden.
        self.assertIsNone(today_payload(timezone.now() + timedelta(hours=49))["position"])
        # Switched off -> hidden.
        self.c.show_position = False
        self.c.save()
        self.assertIsNone(today_payload()["position"])

    def test_only_todays_category_is_shown(self):
        other = next(k for k in ("founder", "realestate", "fintech") if k != self.today_key)
        self.save([{"category_key": other, "position": 1, "field_size": 5}])
        self.assertIsNone(today_payload()["position"])

    def test_staff_only_and_validation(self):
        res = self.save([{"category_key": "founder", "position": 1, "field_size": 5}], user=self.member)
        self.assertEqual(res.status_code, 403)
        res = self.save([{"category_key": "founder", "position": 6, "field_size": 5}])
        self.assertEqual(res.status_code, 400)
        self.assertIn("founder", res.data["fields"])
        self.assertEqual(self.save([{"category_key": "nope", "position": 1, "field_size": 5}]).status_code, 400)
        self.assertFalse(FoyaPosition.objects.exists())

    def test_history_records_old_and_new(self):
        rows = [{"category_key": k, "position": 3, "field_size": 8} for k in ("founder", "realestate", "fintech")]
        self.save(rows)
        self.save([{"category_key": "founder", "position": 1, "field_size": 8, "is_tied": True},
                   {"category_key": "realestate", "position": 3, "field_size": 8}])  # unchanged -> no new row
        self.assertEqual(FoyaPosition.objects.count(), 4)
        latest = FoyaPosition.objects.filter(category_key="founder").first()
        self.assertEqual((latest.position, latest.is_tied, latest.previous_position, latest.updated_by), (1, True, 3, self.staff))
        state = self.client.get("/api/admin/foya/").data
        self.assertEqual(len(state["history"]), 4)
        self.assertEqual(len(state["pushes"]), 0)

    def test_toggle_show_position(self):
        self.client.force_authenticate(self.staff)
        res = self.client.patch("/api/admin/foya/", {"show_position": False}, format="json")
        self.assertEqual(res.status_code, 200)
        self.c.refresh_from_db()
        self.assertFalse(self.c.show_position)
        self.client.force_authenticate(self.member)
        self.assertEqual(self.client.patch("/api/admin/foya/", {"show_position": True}, format="json").status_code, 403)


@patch("authentication.foya.time.sleep", lambda s: None)
@patch("authentication.utils.send_push_notification", return_value={"sent": 1, "total": 1, "success": True})
class FoyaDailyPushTest(TestCase):
    def setUp(self):
        from datetime import date
        self.c = campaign(daily_push_enabled=True, daily_push_start=date(2026, 10, 9), daily_push_hour=10)
        user = CustomUser.objects.create_user(email="d@example.com", password="x", first_name="D", last_name="P", phone_number="08038000001")
        user.expo_push_tokens = [{"token": "ExponentPushToken[x]"}]
        user.save()

    def run_at(self, *args):
        return send_due_foya_pushes(datetime(*args, tzinfo=WAT))

    def test_once_a_day_at_ten_with_todays_category(self, send):
        self.assertEqual(self.run_at(2026, 10, 9, 9, 0), [])            # before 10:00
        self.assertEqual(self.run_at(2026, 10, 9, 10, 0), ["daily:founder"])  # Friday
        self.assertEqual(self.run_at(2026, 10, 9, 11, 0), [])           # already sent today
        self.assertEqual(self.run_at(2026, 10, 10, 10, 0), ["daily:realestate"])  # Saturday
        self.assertEqual(self.run_at(2026, 10, 11, 10, 0), ["daily:fintech"])     # Sunday
        self.assertEqual(send.call_count, 3)
        self.assertEqual(send.call_args.kwargs["data"], {"type": "foya_vote"})
        title, body = send.call_args.args[1], send.call_args.args[2]
        self.assertEqual(title, "Vote for MyFund (FOYA)")
        # No position showing -> "Vote for <category>."
        self.assertEqual(body, "MyFund has been nominated for the FOYA Global Awards 2026. Vote for Fintech & Financial Innovation. 24 days left. Tap to vote for today.")
        from .foya_models import FoyaDailyPush
        self.assertEqual(FoyaDailyPush.objects.count(), 3)

    def test_not_before_start_disabled_quiet_or_after_end(self, send):
        self.assertEqual(self.run_at(2026, 10, 8, 12, 0), [])  # before start date
        self.assertEqual(self.run_at(2026, 10, 9, 21, 0), [])  # quiet hours
        self.assertEqual(self.run_at(2026, 11, 5, 12, 0), [])  # after the vote
        self.c.daily_push_enabled = False
        self.c.save()
        self.assertEqual(self.run_at(2026, 10, 9, 12, 0), [])
        send.assert_not_called()

    def test_skipped_on_a_special_push_day(self, send):
        FoyaPush.objects.create(campaign=self.c, slot="final_week", title="One week left", body="Vote",
                                send_at=datetime(2026, 10, 28, 10, 0, tzinfo=WAT))
        self.assertEqual(self.run_at(2026, 10, 28, 10, 0), ["final_week"])  # only the special one
        self.assertEqual(self.run_at(2026, 10, 28, 12, 0), [])
        self.assertEqual(send.call_count, 1)
        self.assertEqual(self.run_at(2026, 10, 29, 10, 0), ["daily:founder"])

    def test_final_day_copy(self, send):
        from .foya import days_left_text
        self.assertEqual(days_left_text(self.c, datetime(2026, 11, 3, 10, 0, tzinfo=WAT)), "1 day left")
        self.assertEqual(days_left_text(self.c, datetime(2026, 11, 4, 10, 0, tzinfo=WAT)), "Voting closes tonight")


    def test_copy_includes_position_when_showing(self, send):
        from .foya import daily_push_copy
        now = datetime(2026, 10, 9, 10, 0, tzinfo=WAT)
        self.c.show_position = True
        self.c.save()
        p = FoyaPosition.objects.create(campaign=self.c, category_key="founder", position=2, field_size=9)
        FoyaPosition.objects.filter(pk=p.pk).update(updated_at=now - timedelta(hours=1))
        _key, title, body = daily_push_copy(self.c, now)
        self.assertEqual(body, "MyFund has been nominated for the FOYA Global Awards 2026. Now 2nd of 9 for Founder of the Year. 26 days left. Tap to vote for today.")
        # Older than 48h -> falls back.
        FoyaPosition.objects.filter(pk=p.pk).update(updated_at=now - timedelta(hours=49))
        self.assertIn("Vote for Founder of the Year.", daily_push_copy(self.c, now)[2])
