"""FOYA voting campaign: today's category for the Home banner, tap/view
logging, and the (max 3) campaign pushes - see foya_models.py."""
import logging
import time

from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from .foya_models import WAT, FoyaCampaign, FoyaEvent, FoyaPush

logger = logging.getLogger(__name__)

PUSH_DATA = {"type": "foya_vote"}
# No campaign pushes between 9pm and 8am Lagos time.
QUIET_START_HOUR, QUIET_END_HOUR = 21, 8
# Expo accepts ~600 notifications/second; we send one HTTP call per device,
# so a short pause every batch keeps us far below that.
BATCH_SIZE, BATCH_PAUSE_SECONDS = 100, 1


def live_campaign(now=None):
    now = now or timezone.now()
    campaign = FoyaCampaign.objects.filter(is_active=True).order_by("-start_at").first()
    return campaign if campaign and campaign.is_live(now) else None


def today_payload(now=None):
    now = now or timezone.now()
    campaign = live_campaign(now)
    category = campaign.category_for(now) if campaign else None
    if not category:
        return {"active": False}
    return {
        "active": True,
        "category": {key: category.get(key) for key in ("key", "label", "url")},
        "signup_url": campaign.signup_url,
        "login_url": campaign.login_url,
        "end_at": campaign.end_at,
    }


@api_view(["GET"])
@permission_classes([AllowAny])
def foya_today(request):
    return Response(today_payload())


class FoyaEventThrottle(UserRateThrottle):
    rate = "120/hour"


class FoyaAnonEventThrottle(AnonRateThrottle):
    rate = "60/hour"


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([FoyaEventThrottle, FoyaAnonEventThrottle])
def foya_event(request):
    event = request.data.get("event")
    source = request.data.get("source", "banner")
    if event not in dict(FoyaEvent.EVENTS) or source not in dict(FoyaEvent.SOURCES):
        return Response({"error": "Invalid event."}, status=400)
    FoyaEvent.objects.create(
        user=request.user if request.user.is_authenticated else None,
        event=event, source=source, category_key=str(request.data.get("category") or "")[:40],
    )
    return Response({"ok": True}, status=201)


# ── Pushes ────────────────────────────────────────────────────────────────

def in_quiet_hours(now=None):
    hour = (now or timezone.now()).astimezone(WAT).hour
    return hour >= QUIET_START_HOUR or hour < QUIET_END_HOUR


def push_recipients():
    """Active users with a device token who haven't turned off broadcast
    ("admin_messages") pushes - the app's only promotional push setting."""
    from django.db.models import Q
    from .models import CustomUser
    # Not .exclude(admin_messages=False): for users whose preferences are
    # {} the key lookup is NULL in SQL, and exclude() would drop them too.
    allowed = (Q(notification_preferences__isnull=True)
               | ~Q(notification_preferences__has_key="admin_messages")
               | Q(notification_preferences__admin_messages=True))
    return (CustomUser.objects.filter(is_active=True, is_deleted=False, is_banned=False)
            .exclude(expo_push_tokens=[]).exclude(expo_push_tokens__isnull=True)
            .filter(allowed))


def send_to(users, push):
    from .utils import send_push_notification
    reached = 0
    for index, user in enumerate(users.iterator(chunk_size=BATCH_SIZE) if hasattr(users, "iterator") else users, 1):
        try:
            if send_push_notification(user, push.title, push.body, data=dict(PUSH_DATA), notif_type="ADMIN").get("sent"):
                reached += 1
        except Exception:
            logger.exception("FOYA push to user %s failed", user.pk)
        if index % BATCH_SIZE == 0:
            time.sleep(BATCH_PAUSE_SECONDS)
    return reached


def send_due_foya_pushes(now=None):
    """Send every due FOYA push exactly once. Safe to run any number of
    times (beat, retries, restarts): each row is locked and marked sent
    BEFORE delivery, so a slot can never go out twice - at worst a crash
    mid-send leaves it partly delivered, never duplicated."""
    now = now or timezone.now()
    if in_quiet_hours(now):
        return []
    sent = []
    due = FoyaPush.objects.filter(status="scheduled", send_at__isnull=False, send_at__lte=now,
                                  campaign__is_active=True, campaign__start_at__lte=now, campaign__end_at__gt=now)
    for push_id in due.values_list("pk", flat=True):
        with transaction.atomic():
            push = FoyaPush.objects.select_for_update(skip_locked=True).filter(pk=push_id, status="scheduled").first()
            if not push:
                continue  # sent or claimed by another worker
            push.status, push.sent_at = "sent", now
            push.save(update_fields=["status", "sent_at"])
        count = send_to(push_recipients(), push)
        FoyaPush.objects.filter(pk=push.pk).update(recipients_count=count)
        logger.info("FOYA push %s sent to %s users", push.slot, count)
        sent.append(push.slot)
    return sent
