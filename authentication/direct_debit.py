"""AutoSave from a bank account, with no card (Paystack Direct Debit).

Flow:
  1. The app asks GET /api/direct-debit/ whether it's on, which banks are
     supported, and which of the user's saved accounts qualify.
  2. POST /api/direct-debit/autosave/ with a saved account + amount +
     frequency + address. If that account already has an active mandate, the
     AutoSave starts straight away. Otherwise we create a mandate (Paystack
     Initialize Authorization, non-hosted) and return the one-off activation
     transfer (usually N50 to "NIBSS DIRECT DEBIT" at Paystack-Titan).
  3. Paystack's webhooks (direct_debit.authorization.created / .active) - or
     the app polling GET /api/direct-debit/mandates/<id>/ - mark it active,
     and the requested AutoSave starts on its own: the mandate's
     authorization_code is subscribed to a plan exactly like a card's, so
     every debit arrives as the usual subscription charge.success.

DIRECT_DEBIT_MODE (env): "off" (default - hidden), "staff" (team only, for
testing), "on" (everyone). Paystack must have Direct Debit enabled on the
integration first.
"""
import logging
import os
import uuid

import requests
from django.conf import settings
from django.core.cache import cache
from django.db import transaction as db_transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import AutoSave, BankAccount, BankMandate
from .utils import send_push_notification, send_transactional_email

logger = logging.getLogger(__name__)

PAYSTACK = "https://api.paystack.co"
BANK_FREQUENCIES = ["daily", "weekly", "monthly"]  # no hourly bank debits
MIN_AMOUNT = 500
PENDING_REUSE_DAYS = 7
BANKS_CACHE_KEY = "paystack_direct_debit_banks"


def _headers():
    key = os.environ.get("PAYSTACK_KEY_LIVE", "")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def is_enabled_for(user):
    mode = os.environ.get("DIRECT_DEBIT_MODE", "off").strip().lower()
    return mode == "on" or (mode == "staff" and user.is_staff)


def supported_banks():
    """[{code, name}] Paystack can debit, cached for 6 hours (the list grows
    over time, so it's never hardcoded)."""
    banks = cache.get(BANKS_CACHE_KEY)
    if banks is not None:
        return banks
    try:
        res = requests.get(
            f"{PAYSTACK}/bank", params={"country": "nigeria", "perPage": 500},
            headers=_headers(), timeout=20,
        )
        res.raise_for_status()
        banks = [
            {"code": b["code"], "name": b["name"]}
            for b in res.json().get("data") or []
            if b.get("available_for_direct_debit") and b.get("active", True)
            and not b.get("is_deleted")
        ]
    except (requests.RequestException, ValueError, KeyError) as exc:
        logger.warning("Direct Debit bank list unavailable: %s", exc)
        return []
    cache.set(BANKS_CACHE_KEY, banks, 6 * 60 * 60)
    return banks


def _norm(name):
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


def supported_code_for(account, banks):
    """The Paystack bank code if this saved account's bank supports Direct
    Debit, else None. Older saved accounts may lack bank_code, so the name
    is a fallback."""
    by_code = {b["code"]: b for b in banks}
    if account.bank_code and account.bank_code in by_code:
        return account.bank_code
    wanted = _norm(account.bank_name)
    for b in banks:
        if wanted and (_norm(b["name"]) == wanted or _norm(b["name"]).startswith(wanted)):
            return b["code"]
    return None


def _mandate_json(m):
    return {
        "id": m.id,
        "status": m.status,
        "bank_name": m.bank_name,
        "account_last4": m.account_number[-4:],
        "label": m.label,
        "bank_account_id": m.bank_account_id,
        "pending_amount": m.pending_amount,
        "pending_frequency": m.pending_frequency,
        "transfer": {
            "amount": m.transfer_amount,
            "account_number": m.transfer_account_number,
            "account_name": m.transfer_account_name,
            "bank_name": m.transfer_bank_name,
        } if m.status == "pending" and m.transfer_account_number else None,
        "created_at": m.created_at,
        "activated_at": m.activated_at,
    }


# --------------------------------------------------------------------------
# Starting the AutoSave once a mandate is active
# --------------------------------------------------------------------------
def start_autosave_on_mandate(mandate, amount, frequency):
    """Plan + subscription on the mandate's authorization - the same Paystack
    calls as the card AutoSave (views.autosave). Returns the AutoSave or
    raises ValueError with a message safe to show the user."""
    user = mandate.user
    if mandate.status != "active" or not mandate.authorization_code:
        raise ValueError("Your bank account isn't active for AutoSave yet.")
    if AutoSave.objects.filter(user=user, frequency=frequency, active=True).exists():
        raise ValueError(f"You already have an active {frequency} AutoSave.")

    try:
        plan = requests.post(f"{PAYSTACK}/plan", json={
            "name": f"{frequency.capitalize()} AutoSave Plan for {user.email} (bank)",
            "interval": frequency,
            "amount": int(amount) * 100,
        }, headers=_headers(), timeout=30)
        plan.raise_for_status()
        plan_code = (plan.json().get("data") or {}).get("plan_code")
        if not plan_code:
            raise ValueError("Couldn't create the AutoSave plan. Please try again.")

        sub = requests.post(f"{PAYSTACK}/subscription", json={
            "customer": user.email,
            "plan": plan_code,
            "authorization": mandate.authorization_code,
        }, headers=_headers(), timeout=30)
        body = sub.json() if sub.content else {}
        if not sub.ok or not body.get("status"):
            raise ValueError(body.get("message") or "Couldn't start AutoSave. Please try again.")
    except requests.RequestException as exc:
        logger.error("Direct Debit AutoSave for %s failed at Paystack: %s", user.email, exc)
        raise ValueError("Our payment provider didn't respond. Please try again shortly.")

    data = body.get("data") or {}
    autosave = AutoSave.objects.create(
        user=user, frequency=frequency, amount=amount, active=True, mandate=mandate,
        paystack_sub_id=data.get("id"),
        paystack_sub_code=data.get("subscription_code"),
        paystack_sub_token=data.get("email_token"),
        paystack_plan_code=plan_code,
        paystack_trans_ref=data.get("reference"),
    )
    user.autosave_enabled = True
    user.save(update_fields=["autosave_enabled"])

    if mandate.pending_amount:
        mandate.pending_amount = None
        mandate.pending_frequency = ""
        mandate.save(update_fields=["pending_amount", "pending_frequency", "updated_at"])

    send_transactional_email(
        subject="AutoSave Activated!",
        message=(
            f"Hi {user.first_name},<br><br>"
            f"Your AutoSave has been activated. You are now saving ₦{int(amount):,} {frequency} "
            f"straight from your {mandate.label} - no card needed.<br><br>"
            f"Keep growing your funds.🥂"
        ),
        from_email="MyFund <info@myfundmobile.com>",
        recipient_list=[user.email],
    )
    send_push_notification(
        user=user,
        title="AutoSave Activated! ✅",
        message=(f"Well done {user.first_name}! You're now saving ₦{int(amount):,} {frequency} "
                 f"from your {mandate.label}. Keep growing your funds."),
        data={"type": "AutoSave", "status": "activated", "frequency": frequency,
              "amount": str(amount), "channel": "direct_debit"},
        notif_type="SYSTEM",
    )
    return autosave


def mark_mandate_active(mandate, authorization_code=""):
    """Idempotent. Activates the mandate and starts the AutoSave the user
    asked for when they set it up."""
    with db_transaction.atomic():
        mandate = BankMandate.objects.select_for_update().get(pk=mandate.pk)
        if mandate.status == "active":
            return mandate
        if authorization_code:
            mandate.authorization_code = authorization_code
        mandate.status = "active"
        mandate.activated_at = timezone.now()
        mandate.save(update_fields=["authorization_code", "status", "activated_at", "updated_at"])

    user = mandate.user
    if mandate.pending_amount and mandate.pending_frequency:
        try:
            start_autosave_on_mandate(mandate, mandate.pending_amount, mandate.pending_frequency)
            return mandate
        except ValueError as exc:
            logger.warning("Mandate %s active but AutoSave didn't start: %s", mandate.pk, exc)
            send_push_notification(
                user=user,
                title="Bank account linked ✅",
                message=(f"Your {mandate.label} is ready for AutoSave, but we couldn't start it: "
                         f"{exc} Open AutoSave to try again."),
                data={"type": "AutoSave", "status": "mandate_active"},
                notif_type="SYSTEM",
            )
            return mandate

    send_push_notification(
        user=user,
        title="Bank account linked ✅",
        message=f"Your {mandate.label} is now ready for AutoSave - no card needed.",
        data={"type": "AutoSave", "status": "mandate_active"},
        notif_type="SYSTEM",
    )
    return mandate


def refresh_pending_mandate(mandate):
    """Asks Paystack about a pending mandate, for when a webhook was missed."""
    if mandate.status != "pending":
        return mandate
    try:
        res = requests.get(f"{PAYSTACK}/customer/authorization/verify/{mandate.reference}",
                           headers=_headers(), timeout=20)
    except requests.RequestException:
        return mandate
    if res.status_code != 200:
        return mandate  # 404 until the customer approves it
    data = (res.json() or {}).get("data") or {}
    code = data.get("authorization_code") or ""
    if code and not mandate.authorization_code:
        mandate.authorization_code = code
        mandate.save(update_fields=["authorization_code", "updated_at"])
    if data.get("active") is True or data.get("status") == "active":
        return mark_mandate_active(mandate, code)
    return mandate


# --------------------------------------------------------------------------
# Webhooks (called from views.paystack_webhook_processing)
# --------------------------------------------------------------------------
def _mandate_for_event(data):
    code = data.get("authorization_code") or ""
    if code:
        m = BankMandate.objects.filter(authorization_code=code).first()
        if m:
            return m
    email = ((data.get("customer") or {}).get("email") or "").strip()
    if not email:
        return None
    pending = BankMandate.objects.filter(user__email__iexact=email, status="pending")
    last4 = str(data.get("last4") or "")
    if last4:
        match = [m for m in pending if m.account_number.endswith(last4)]
        if match:
            return match[0]
    return pending.first()


def handle_mandate_webhook(event):
    name = event.get("event")
    data = event.get("data") or {}
    mandate = _mandate_for_event(data)
    if not mandate:
        logger.warning("Direct Debit webhook %s matched no mandate: %s", name,
                       data.get("authorization_code"))
        return
    code = data.get("authorization_code") or ""
    if name == "direct_debit.authorization.active" or data.get("active") is True:
        mark_mandate_active(mandate, code)
    elif code and not mandate.authorization_code:
        mandate.authorization_code = code
        mandate.save(update_fields=["authorization_code", "updated_at"])


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def direct_debit_overview(request):
    user = request.user
    if not is_enabled_for(user):
        return Response({"enabled": False})
    banks = supported_banks()
    accounts = []
    for acc in BankAccount.objects.filter(user=user).order_by("-is_default", "id"):
        accounts.append({
            "id": acc.id,
            "bank_name": acc.bank_name,
            "account_name": acc.account_name,
            "account_last4": acc.account_number[-4:],
            "is_default": acc.is_default,
            "supported": bool(supported_code_for(acc, banks)),
        })
    mandates = BankMandate.objects.filter(user=user).exclude(status="inactive")
    for m in mandates.filter(status="pending"):
        refresh_pending_mandate(m)
    address = (user.address or "").strip()
    return Response({
        "enabled": True,
        "frequencies": BANK_FREQUENCIES,
        "min_amount": max(MIN_AMOUNT, getattr(settings, "MIN_DEPOSIT_AMOUNT", 0)),
        "supported_bank_names": sorted({b["name"] for b in banks}),
        "accounts": accounts,
        "mandates": [_mandate_json(m) for m in
                     BankMandate.objects.filter(user=user).exclude(status="inactive")],
        "address": {
            "street": "" if address in ("", "Enter Address") else address,
            "state": "" if user.state in ("", "Choose") else user.state,
        },
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def direct_debit_autosave(request):
    user = request.user
    if not is_enabled_for(user):
        return Response({"error": "AutoSave from a bank account isn't available yet."},
                        status=status.HTTP_403_FORBIDDEN)
    d = request.data
    frequency = (d.get("frequency") or "").lower()
    if frequency not in BANK_FREQUENCIES:
        return Response({"error": "Choose daily, weekly or monthly for bank AutoSave."},
                        status=status.HTTP_400_BAD_REQUEST)
    try:
        amount = int(str(d.get("amount", "")).replace(",", ""))
    except ValueError:
        return Response({"error": "Enter a valid amount."}, status=status.HTTP_400_BAD_REQUEST)
    minimum = max(MIN_AMOUNT, getattr(settings, "MIN_DEPOSIT_AMOUNT", 0))
    if amount < minimum:
        return Response({"error": f"Minimum AutoSave amount is ₦{minimum:,}."},
                        status=status.HTTP_400_BAD_REQUEST)
    if AutoSave.objects.filter(user=user, frequency=frequency, active=True).exists():
        return Response({"error": f"You already have an active {frequency} AutoSave."},
                        status=status.HTTP_400_BAD_REQUEST)

    account = BankAccount.objects.filter(user=user, id=d.get("bank_account_id")).first()
    if not account:
        return Response({"error": "Choose one of your saved bank accounts."},
                        status=status.HTTP_404_NOT_FOUND)
    bank_code = supported_code_for(account, supported_banks())
    if not bank_code:
        return Response({"error": f"{account.bank_name} doesn't support AutoSave without a card yet. "
                                  "Use another bank account or a card."},
                        status=status.HTTP_400_BAD_REQUEST)

    # Already linked: start right away.
    active = BankMandate.objects.filter(user=user, bank_account=account, status="active").first()
    if active:
        try:
            start_autosave_on_mandate(active, amount, frequency)
        except ValueError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"status": "active", "mandate": _mandate_json(active)})

    # Waiting on the same account's activation: keep it, update the request.
    cutoff = timezone.now() - timezone.timedelta(days=PENDING_REUSE_DAYS)
    pending = BankMandate.objects.filter(user=user, bank_account=account, status="pending",
                                         created_at__gte=cutoff).first()
    if pending and pending.transfer_account_number:
        pending.pending_amount, pending.pending_frequency = amount, frequency
        pending.save(update_fields=["pending_amount", "pending_frequency", "updated_at"])
        return Response({"status": "pending", "mandate": _mandate_json(pending)})

    street = (d.get("street") or "").strip()
    city = (d.get("city") or "").strip()
    state = (d.get("state") or "").strip()
    if not (street and city and state):
        return Response({"error": "Enter your street address, city and state."},
                        status=status.HTTP_400_BAD_REQUEST)

    reference = f"MFDD-{uuid.uuid4().hex[:16]}"
    payload = {
        "email": user.email,
        "channel": "direct_debit",
        "use_hosted_url": False,
        "reference": reference,
        "account": {"number": account.account_number, "bank_code": bank_code},
        "address": {"street": street, "city": city, "state": state},
    }
    try:
        res = requests.post(f"{PAYSTACK}/customer/authorization/initialize",
                            json=payload, headers=_headers(), timeout=30)
        body = res.json() if res.content else {}
    except (requests.RequestException, ValueError) as exc:
        logger.error("Direct Debit init failed for %s: %s", user.email, exc)
        return Response({"error": "Our payment provider didn't respond. Please try again shortly."},
                        status=status.HTTP_502_BAD_GATEWAY)
    if not res.ok or not body.get("status"):
        logger.warning("Direct Debit init refused for %s: %s", user.email, body)
        return Response({"error": body.get("message") or "Couldn't link this bank account."},
                        status=status.HTTP_400_BAD_REQUEST)

    data = body.get("data") or {}
    transfer = data.get("transferDetails") or {}
    mandate = BankMandate.objects.create(
        user=user, bank_account=account, bank_name=account.bank_name, bank_code=bank_code,
        account_number=account.account_number, account_name=account.account_name,
        reference=data.get("reference") or reference,
        paystack_mandate_id=str((data.get("mandate") or {}).get("id") or ""),
        transfer_amount=str(transfer.get("amount") or ""),
        transfer_account_number=str(transfer.get("account_number") or ""),
        transfer_account_name=transfer.get("account_name") or "",
        transfer_bank_name=transfer.get("bank_name") or "",
        pending_amount=amount, pending_frequency=frequency,
    )
    # Remember the address for next time, only if we had none.
    if (user.address or "").strip() in ("", "Enter Address"):
        user.address = f"{street}, {city}"
        user.save(update_fields=["address"])

    out = {"status": "pending", "mandate": _mandate_json(mandate)}
    if not transfer and data.get("redirect_url"):
        # Some banks confirm in their own app/page instead of a transfer.
        out["redirect_url"] = data["redirect_url"]
    return Response(out, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def direct_debit_mandate_status(request, mandate_id):
    mandate = BankMandate.objects.filter(user=request.user, id=mandate_id).first()
    if not mandate:
        return Response({"error": "Not found."}, status=status.HTTP_404_NOT_FOUND)
    mandate = refresh_pending_mandate(mandate)
    mandate.refresh_from_db()
    has_autosave = AutoSave.objects.filter(mandate=mandate, active=True).exists()
    return Response({**_mandate_json(mandate), "autosave_active": has_autosave})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def direct_debit_cancel_mandate(request, mandate_id):
    """Unlinks the bank account: stops any AutoSave on it, then deactivates
    the mandate at Paystack so nothing more can be debited."""
    from .views import deactivate_autosave_for_user

    user = request.user
    mandate = BankMandate.objects.filter(user=user, id=mandate_id).exclude(status="inactive").first()
    if not mandate:
        return Response({"error": "Not found."}, status=status.HTTP_404_NOT_FOUND)
    try:
        for freq in set(AutoSave.objects.filter(mandate=mandate, active=True)
                        .values_list("frequency", flat=True)):
            deactivate_autosave_for_user(user, freq)
        if mandate.authorization_code:
            res = requests.post(f"{PAYSTACK}/customer/authorization/deactivate",
                                json={"authorization_code": mandate.authorization_code},
                                headers=_headers(), timeout=30)
            if not res.ok:
                logger.warning("Mandate %s deactivate at Paystack: %s %s",
                               mandate.pk, res.status_code, res.text[:200])
    except requests.RequestException:
        return Response({"error": "Couldn't reach our payment provider. Please try again."},
                        status=status.HTTP_502_BAD_GATEWAY)
    mandate.status = "inactive"
    mandate.save(update_fields=["status", "updated_at"])
    return Response({"message": f"{mandate.label} unlinked."})
