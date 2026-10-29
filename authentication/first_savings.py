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

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from rest_framework import status as http_status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CustomUser, FirstSaveGuide, PushNotifications, Transaction

WAT = ZoneInfo("Africa/Lagos")
NEW_USER_DAYS = 30
REMINDER_DAYS = (2, 7)
PUSH_TYPE = "FIRST_SAVINGS_NUDGE"
# What the nudge asks for - the app's QuickSave minimum.
FIRST_SAVE_AMOUNT = 500
# The Home spotlight on QuickSave stops after this many closes.
MAX_GUIDE_DISMISSALS = 3
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


def savers_this_week():
    """Distinct people with a confirmed deposit in the last 7 days - real
    social proof for the nudge. Cached for an hour; it's the same for everyone."""
    def count():
        by_description = Q()
        for prefix in DEPOSIT_PREFIXES:
            by_description |= Q(description__startswith=prefix)
        return Transaction.objects.filter(
            transaction_type="credit", status="confirmed",
            date__gte=timezone.now() - timedelta(days=7),
        ).filter(by_description | Q(credited_to__in=["SAVINGS", "INVESTMENT"])
                 ).values("user_id").distinct().count()
    return cache.get_or_set("first-savings:savers-this-week", count, 60 * 60)


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


def show_first_save_guide(user, now=None):
    """Anyone who has never saved, regardless of when they joined: at most
    once a Lagos day, never while a first deposit is confirming, and not
    after MAX_GUIDE_DISMISSALS closes."""
    now = now or timezone.now()
    guide = FirstSaveGuide.objects.filter(user=user).first()
    if guide and guide.dismissals >= MAX_GUIDE_DISMISSALS:
        return False
    if guide and guide.last_shown_at and guide.last_shown_at.astimezone(WAT).date() == now.astimezone(WAT).date():
        return False
    if has_ever_saved(user):
        return False
    return not _deposits(user).filter(status="pending", date__gte=now - timedelta(days=3)).exists()


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def first_savings_status_view(request):
    status = first_savings_status(request.user)
    if status["eligible"]:
        status["savers_this_week"] = savers_this_week()
    status["show_guide"] = show_first_save_guide(request.user)
    return Response(status)


GUIDE_EVENTS = ("shown", "dismiss", "tap")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def first_save_guide_event(request):
    """shown: counts a display. dismiss / tap: the guide was closed (Not now,
    Done, or tapping through to QuickSave) - each counts toward the limit, so
    someone who taps through but doesn't save sees it at most 3 times too."""
    event = request.data.get("event")
    if event not in GUIDE_EVENTS:
        return Response({"detail": "Unknown event."}, status=http_status.HTTP_400_BAD_REQUEST)
    guide, _ = FirstSaveGuide.objects.get_or_create(user=request.user)
    now = timezone.now()
    if event == "shown":
        guide.times_shown += 1
        guide.last_shown_at = now
    else:
        guide.dismissals = min(guide.dismissals + 1, MAX_GUIDE_DISMISSALS)
        if event == "tap":
            guide.tapped_at = now
    guide.save()
    return Response({"dismissals": guide.dismissals, "times_shown": guide.times_shown})


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
        # In Dr. Tee's voice, like the in-app nudge.
        title, message = (
            ("Hi {first_name}, it's Dr. Tee 👋",
             f"Your first ₦{FIRST_SAVE_AMOUNT:,} can start earning 13% a year today. "
             "Save before 12 noon and watch it grow from today. 💜")
            if step == REMINDER_DAYS[0] else
            ("{first_name}, your money could be growing daily",
             "It's Dr. Tee. ₦50,000 saved on MyFund earns about ₦6,500 in a year, added every day. "
             f"Start with ₦{FIRST_SAVE_AMOUNT:,} today. 💜")
        )
        send_push_notification(
            user=user, title=title, message=message, notif_type="SYSTEM",
            data={"type": PUSH_TYPE, "step": step, "category": "USER_SAVINGS",
                  "deep_link": {"screen": "MainTab", "screen_params": {
                      "screen": "Save", "params": {"quickSaveModalVisible": True,
                                                   "quickSaveAmount": FIRST_SAVE_AMOUNT}}}},
        )
        sent += 1
    return sent
