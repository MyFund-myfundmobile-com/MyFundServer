"""
Month-end saving-streak reminders.

A month counts towards a saving streak when the saver puts in more than they
take out that month (authentication.utils.monthly_net_savings). Month end is
the only moment a streak can be lost, so savers whose streak is at risk get
at most three pushes, at 10:00 WAT: 7 days, 3 days and 0 days before the
month ends. "At risk" means:

- they saved last month (a streak of 1+ months running into this one),
- they haven't saved this month yet (checked live, not from the board), and
- they have no active AutoSave (it will save for them).

Each push opens QuickSave. A (month, stage) push is never sent twice - the
stored PushNotifications row is the record.
"""
import calendar
import logging

from django.utils import timezone

from .active_saver_views import live_savers_this_month, previous_month, streaks
from .models import AutoSave, CustomUser, PushNotifications, TopSaverHistory

logger = logging.getLogger(__name__)

PUSH_TYPE = "SAVING_STREAK_REMINDER"
# Days left in the month (Lagos) on which a reminder goes out.
REMIND_DAYS_LEFT = (7, 3, 0)


def _months(n):
    return f"{n}-month savings"


def reminder_copy(days_left, streak, month_name, month_end):
    """(title, message) for one stage. {first_name} is filled in by
    send_push_notification."""
    run = _months(streak)
    if days_left == 7:
        return (f"🔥 Keep your {run} streak going",
                f"{{first_name}}, save any amount before {month_end} so {month_name} counts too. Tap to QuickSave.")
    if days_left == 3:
        return ("🔥 3 days left to keep your streak",
                f"You haven't saved in {month_name} yet. Any amount keeps your {run} streak alive. Tap to QuickSave.")
    return (f"⏳ Last day to keep your {run} streak!",
            "Save any amount today to keep it. Tip: turn on AutoSave and never miss a month.")


def at_risk_savers(now=None):
    """[(user, streak_months)] whose streak ends this month unless they save."""
    now = now or timezone.now()
    last_month, last_year = previous_month(now)
    saved_last = set(TopSaverHistory.objects.filter(month=last_month, year=last_year)
                     .values_list("user_id", flat=True))
    if not saved_last:
        return []
    saved_now = live_savers_this_month(saved_last, now)
    on_autosave = set(AutoSave.objects.filter(user_id__in=saved_last, active=True)
                      .values_list("user_id", flat=True))
    ids = saved_last - saved_now - on_autosave
    runs = streaks(ids, last_month, last_year)
    users = CustomUser.objects.filter(pk__in=ids, is_active=True, is_deleted=False, is_banned=False)
    return [(user, runs.get(user.pk, 1)) for user in users]


def send_streak_reminders(now=None):
    """Run daily at 10:00 WAT. Returns the number of pushes sent."""
    from .utils import send_push_notification

    now = now or timezone.now()
    local = timezone.localtime(now)
    last_day = calendar.monthrange(local.year, local.month)[1]
    days_left = last_day - local.day
    if days_left not in REMIND_DAYS_LEFT:
        return 0
    month_key = f"{local.year}-{local.month:02d}"
    month_name = local.strftime("%B")
    month_end = f"{last_day} {local.strftime('%b')}"
    sent = 0
    for user, streak in at_risk_savers(now):
        if PushNotifications.objects.filter(user=user, data__type=PUSH_TYPE, data__month=month_key,
                                            data__days_left=days_left).exists():
            continue
        title, message = reminder_copy(days_left, streak, month_name, month_end)
        try:
            send_push_notification(
                user=user, title=title, message=message, notif_type="SYSTEM",
                data={"type": PUSH_TYPE, "month": month_key, "days_left": days_left, "streak": streak,
                      "category": "USER_SAVINGS",
                      "deep_link": {"screen": "MainTab", "screen_params": {
                          "screen": "Save", "params": {"quickSaveModalVisible": True}}}},
            )
            sent += 1
        except Exception:
            logger.exception("Streak reminder to user %s failed", user.pk)
    logger.info("Saving-streak reminders (%s, %s days left): %s sent", month_key, days_left, sent)
    return sent
