"""
Register-interest waitlist for GroupBuy properties that can't be bought yet.

Properties with no units left show "Disabled for now" in the app. Instead of
a dead button, users can tell us what interests them and roughly how much
they could put in. The team gets a push for each new registration and can
see the list per property in mobile Admin.
"""
import logging

from django.db import transaction
from django.db.models import Count
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from .models import CustomUser, GroupBuyInterest, Property

logger = logging.getLogger(__name__)

INTEREST_CHOICES = {
    "co_own": "Co-own a share",
    "rental_income": "Earn rental income",
    "live_in": "Buy to live in",
    "resale": "Resell for profit",
}
BUDGET_CHOICES = {
    "under_100k": "Under ₦100k",
    "100k_500k": "₦100k – ₦500k",
    "500k_2m": "₦500k – ₦2m",
    "over_2m": "Over ₦2m",
}

# Janet, Tolulope and Chubi (Engagement) - same people as the ambassador
# application alerts.
INTEREST_ALERT_EMAILS = [
    "tolulopeahmed@gmail.com",
    "janet.adegbenro@gmail.com",
    "josephgideon95@gmail.com",
]


def _notify_team(interest):
    from .utils import send_push_notification

    user, prop = interest.user, interest.property
    name = f"{user.first_name} {user.last_name}".strip() or user.email
    picks = ", ".join(INTEREST_CHOICES[k] for k in interest.interests if k in INTEREST_CHOICES) or "no preference"
    budget = BUDGET_CHOICES.get(interest.budget, "budget not given")
    total = GroupBuyInterest.objects.filter(property=prop).count()
    message = f"{name} registered interest in {prop.name} ({picks}; {budget}). Total interested: {total}."
    for admin in CustomUser.objects.filter(email__in=INTEREST_ALERT_EMAILS, is_active=True):
        if getattr(admin, "expo_push_tokens", None):
            try:
                send_push_notification(
                    user=admin, title="🏠 New GroupBuy interest", message=message,
                    data={"deep_link": {"screen": "AdminGroupBuyInterests", "screen_params": {"propertyId": prop.id}}},
                    notif_type="ADMIN_ALERT",
                )
            except Exception:
                logger.exception("GroupBuy interest push failed for %s", admin.email)


def _serialize(interest):
    return {
        "property_id": interest.property_id,
        "interests": interest.interests,
        "budget": interest.budget,
        "note": interest.note,
        "created_at": interest.created_at,
    }


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_groupbuy_interests(request):
    rows = GroupBuyInterest.objects.filter(user=request.user)
    return Response({
        "interests": [_serialize(r) for r in rows],
        "interest_choices": INTEREST_CHOICES,
        "budget_choices": BUDGET_CHOICES,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def register_groupbuy_interest(request, property_id):
    prop = Property.objects.filter(pk=property_id).first()
    if not prop:
        return Response({"detail": "Property not found."}, status=status.HTTP_404_NOT_FOUND)

    interests = request.data.get("interests") or []
    if not isinstance(interests, list) or not interests or any(k not in INTEREST_CHOICES for k in interests):
        return Response({"detail": "Please choose at least one option."}, status=status.HTTP_400_BAD_REQUEST)
    budget = request.data.get("budget") or ""
    if budget and budget not in BUDGET_CHOICES:
        return Response({"detail": "Please choose a valid amount."}, status=status.HTTP_400_BAD_REQUEST)
    note = str(request.data.get("note") or "").strip()[:500]

    with transaction.atomic():
        interest, created = GroupBuyInterest.objects.update_or_create(
            user=request.user, property=prop,
            defaults={"interests": list(dict.fromkeys(interests)), "budget": budget, "note": note},
        )
        # Only the first registration alerts the team; edits don't re-ping.
        if created:
            from .ambassador_application_views import _run_in_background

            # Pushes go out after the response, so Expo never slows the save.
            transaction.on_commit(lambda: _run_in_background(lambda: _notify_team(interest)))

    return Response({"created": created, "interest": _serialize(interest)},
                    status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def admin_groupbuy_interests(request):
    """Per-property counts plus the people behind them, newest first."""
    rows = GroupBuyInterest.objects.select_related("user", "property")
    property_id = request.query_params.get("property_id")
    if property_id:
        rows = rows.filter(property_id=property_id)

    counts = (GroupBuyInterest.objects.values("property_id", "property__name")
              .annotate(total=Count("id")).order_by("-total"))
    return Response({
        "properties": [
            {"property_id": c["property_id"], "name": c["property__name"], "total": c["total"]} for c in counts
        ],
        "results": [
            {
                "id": r.id,
                "property_id": r.property_id,
                "property_name": r.property.name,
                "name": f"{r.user.first_name} {r.user.last_name}".strip(),
                "email": r.user.email,
                "phone": r.user.phone_number,
                "avatar": str(r.user.profile_picture or ""),
                "interests": [INTEREST_CHOICES.get(k, k) for k in r.interests],
                "budget": BUDGET_CHOICES.get(r.budget, ""),
                "note": r.note,
                "created_at": r.created_at,
            }
            for r in rows[:500]
        ],
    })
