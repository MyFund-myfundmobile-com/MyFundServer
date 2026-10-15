"""
First-savings nudge for new users who haven't saved yet.

Daily returns (calculate_daily_roi_task) only reach users who already hold a
savings or investment balance at 12 noon WAT, so brand-new users never get
the "Your Funds Have Grown!" push. For their first 30 days, the app shows them
a gentle prompt (Home modal, Quick Actions, account cards) and they get at
most two reminder pushes - day 2 and day 7 - which stop once they save.
"""
from datetime import timedelta
from zoneinfo import ZoneInfo

from django.db.models import Q
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CustomUser, PushNotifications, Transaction

WAT = ZoneInfo("Africa/Lagos")
NEW_USER_DAYS = 30
REMINDER_DAYS = (2, 7)
PUSH_TYPE = "FIRST_SAVINGS_NUDGE"
DEPOSIT_PREFIXES = ("QuickSave", "AutoSave", "QuickInvest", "AutoInvest", "Target Savings Deposit")


def _deposits(user):
    by_description = Q()
    for prefix in DEPOSIT_PREFIXES:
        by_description |= Q(description__startswith=prefix)
    return Transaction.objects.filter(user=user, transaction_type="credit").filter(
        by_description | Q(credited_to__in=["SAVINGS", "INVESTMENT"])
    )


def has_ever_saved(user):
    # A balance alone isn't enough to rule someone in - someone who saved and
    # withdrew everything has still saved before.
    return bool(user.savings or user.investment) or _deposits(user).filter(status="confirmed").exists()


def first_savings_status(user, now=None):
    now = now or timezone.now()
    joined = user.date_joined
    is_new = bool(joined and joined >= now - timedelta(days=NEW_USER_DAYS))
    eligible = is_new and not has_ever_saved(user)
    return {
        "eligible": eligible,
        # A deposit awaiting confirmation: show its status, don't ask them to pay again.
        "pending_deposit": eligible and _deposits(user).filter(
            status="pending", date__gte=now - timedelta(days=3)
        ).exists(),
    }


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def first_savings_status_view(request):
    return Response(first_savings_status(request.user))


def send_first_savings_reminders(now=None):
    """Day-2 and day-7 reminders (by Lagos calendar date). Returns pushes sent."""
    from .utils import send_push_notification

    now = now or timezone.now()
    today = now.astimezone(WAT).date()
    sent = 0
    candidates = CustomUser.objects.filter(
        is_active=True, is_deleted=False, is_banned=False,
        date_joined__gte=now - timedelta(days=max(REMINDER_DAYS) + 1),
    )
    for user in candidates.iterator():
        step = (today - user.date_joined.astimezone(WAT).date()).days
        if step not in REMINDER_DAYS:
            continue
        status = first_savings_status(user, now)
        if not status["eligible"] or status["pending_deposit"]:
            continue
        if PushNotifications.objects.filter(user=user, data__type=PUSH_TYPE, data__step=step).exists():
            continue
        title, message = (
            ("Ready for your first QuickSave?",
             "Hi {first_name}, you can start with any amount. Save before 12 noon and you'll see your first returns today.")
            if step == REMINDER_DAYS[0] else
            ("Your money could be growing daily",
             "Hi {first_name}, once you save, MyFund shows what your money earns every day at 12 noon. Start with any amount.")
        )
        send_push_notification(
            user=user, title=title, message=message, notif_type="SYSTEM",
            data={"type": PUSH_TYPE, "step": step, "category": "USER_SAVINGS",
                  "deep_link": {"screen": "MainTab", "screen_params": {
                      "screen": "Save", "params": {"quickSaveModalVisible": True}}}},
        )
        sent += 1
    return sent
