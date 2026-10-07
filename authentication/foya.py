"""FOYA voting campaign: today's category for the Home banner, tap/view
logging, and the (max 3) campaign pushes - see foya_models.py."""
import logging
import time

from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from datetime import timedelta

from .foya_models import WAT, FoyaCampaign, FoyaEvent, FoyaPosition, FoyaPush

logger = logging.getLogger(__name__)

PUSH_DATA = {"type": "foya_vote"}
# No campaign pushes between 9pm and 8am Lagos time.
QUIET_START_HOUR, QUIET_END_HOUR = 21, 8
# Expo accepts ~600 notifications/second; we send one HTTP call per device,
# so a short pause every batch keeps us far below that.
BATCH_SIZE, BATCH_PAUSE_SECONDS = 100, 1
# A ranking older than this isn't shown - stale numbers would mislead.
POSITION_MAX_AGE = timedelta(hours=48)


def live_campaign(now=None):
    now = now or timezone.now()
    campaign = FoyaCampaign.objects.filter(is_active=True).order_by("-start_at").first()
    return campaign if campaign and campaign.is_live(now) else None


def latest_position(campaign, category_key):
    return campaign.positions.filter(category_key=category_key).first()


def banner_position(campaign, category_key, now=None):
    """Today's category ranking for the banner, or None (switched off, no
    data yet, or older than 48 hours)."""
    if not campaign.show_position:
        return None
    latest = latest_position(campaign, category_key)
    if not latest or latest.updated_at < (now or timezone.now()) - POSITION_MAX_AGE:
        return None
    return {"position": latest.position, "field_size": latest.field_size,
            "is_tied": latest.is_tied, "updated_at": latest.updated_at}


def today_payload(now=None):
    now = now or timezone.now()
    campaign = live_campaign(now)
    category = campaign.category_for(now) if campaign else None
    if not category:
        return {"active": False}
    return {
        "active": True,
        # banner_body: the banner's line for this category (editable in the
        # admin categories JSON); **text** marks bold.
        "category": {key: category.get(key) for key in ("key", "label", "url", "banner_body")},
        "signup_url": campaign.signup_url,
        "login_url": campaign.login_url,
        "end_at": campaign.end_at,
        "position": banner_position(campaign, category.get("key"), now),
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


# ── Staff: daily positions + campaign status (web admin FOYA page) ───────

def _admin_campaign():
    return FoyaCampaign.objects.order_by("-start_at").first()


def _position_row(p):
    return {"id": p.id, "category_key": p.category_key, "position": p.position, "field_size": p.field_size,
            "is_tied": p.is_tied, "previous_position": p.previous_position, "previous_field_size": p.previous_field_size,
            "previous_is_tied": p.previous_is_tied, "updated_at": p.updated_at,
            "updated_by": (p.updated_by.full_name or p.updated_by.email) if p.updated_by_id else ""}


def admin_state(campaign):
    latest = {c["key"]: latest_position(campaign, c["key"]) for c in campaign.categories or []}
    today = campaign.category_for() or {}
    return {
        "id": campaign.id,
        "is_active": campaign.is_active,
        "is_live": campaign.is_live(),
        "show_position": campaign.show_position,
        "end_at": campaign.end_at,
        "today_category": today.get("key"),
        "categories": [{**c, "latest": _position_row(latest[c["key"]]) if latest[c["key"]] else None}
                       for c in campaign.categories or []],
        "history": [_position_row(p) for p in campaign.positions.select_related("updated_by")[:14]],
        "pushes": [{"slot": p.slot, "label": p.get_slot_display(), "title": p.title, "send_at": p.send_at,
                    "status": p.status, "sent_at": p.sent_at, "recipients_count": p.recipients_count}
                   for p in campaign.pushes.order_by("id")],
    }


@api_view(["GET", "PATCH"])
@permission_classes([IsAdminUser])
def foya_admin(request):
    campaign = _admin_campaign()
    if not campaign:
        return Response({"error": "No FOYA campaign."}, status=404)
    if request.method == "PATCH":
        if not isinstance(request.data.get("show_position"), bool):
            return Response({"error": "show_position must be true or false."}, status=400)
        campaign.show_position = request.data["show_position"]
        campaign.save(update_fields=["show_position"])
        logger.info("FOYA show_position set to %s by %s", campaign.show_position, request.user.email)
    return Response(admin_state(campaign))


@api_view(["POST"])
@permission_classes([IsAdminUser])
def foya_admin_positions(request):
    """Save today's positions for every category in one go. Each change
    adds a row recording who, when, and the value it replaced."""
    campaign = _admin_campaign()
    if not campaign:
        return Response({"error": "No FOYA campaign."}, status=404)
    keys = {c["key"] for c in campaign.categories or []}
    rows = request.data.get("positions")
    if not isinstance(rows, list) or not rows:
        return Response({"error": "Send a list of positions."}, status=400)
    errors, cleaned = {}, []
    for row in rows:
        key = row.get("category_key") if isinstance(row, dict) else None
        if key not in keys:
            return Response({"error": f"Unknown category: {key}"}, status=400)
        try:
            position, field_size = int(row.get("position")), int(row.get("field_size"))
        except (TypeError, ValueError):
            errors[key] = "Enter whole numbers."
            continue
        if field_size < 1 or not 1 <= position <= field_size:
            errors[key] = "Position must be between 1 and the field size."
            continue
        cleaned.append((key, position, field_size, bool(row.get("is_tied"))))
    if errors:
        return Response({"error": "Please check the highlighted rows.", "fields": errors}, status=400)
    with transaction.atomic():
        for key, position, field_size, tied in cleaned:
            previous = latest_position(campaign, key)
            if previous and (previous.position, previous.field_size, previous.is_tied) == (position, field_size, tied):
                continue  # unchanged
            FoyaPosition.objects.create(
                campaign=campaign, category_key=key, position=position, field_size=field_size, is_tied=tied,
                previous_position=previous.position if previous else None,
                previous_field_size=previous.field_size if previous else None,
                previous_is_tied=previous.is_tied if previous else None,
                updated_by=request.user,
            )
    return Response(admin_state(campaign))
