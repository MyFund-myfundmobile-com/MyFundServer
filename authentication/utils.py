import requests
from .models import PushNotifications, TopSaverHistory, Transaction
from .models import PushNotifications
from django.utils import timezone
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import threading
import logging
import smtplib
import random
import string
import requests
import time
import logging
import requests
from django.contrib.auth import get_user_model
from .models import PushNotifications  # Ensure this is the correct import

import logging
import requests

from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"


class SafeDict(dict):
    """
    Returns the placeholder itself if key is missing,
    so message formatting won't crash.
    Example:
    "Hi {first_name} {unknown}".format_map(SafeDict({"first_name": "Tee"}))
    => "Hi Tee {unknown}"
    """

    def __missing__(self, key):
        return "{" + key + "}"


def build_push_context(user, extra_context=None):
    """
    Build personalization context for push notifications.
    """
    extra_context = extra_context or {}

    first_name = getattr(user, "first_name", "") or ""
    last_name = getattr(user, "last_name", "") or ""
    email = getattr(user, "email", "") or ""
    phone_number = getattr(user, "phone_number", "") or ""

    full_name = f"{first_name} {last_name}".strip()

    context = {
        "first_name": first_name,
        "last_name": last_name,
        "full_name": full_name,
        "email": email,
        "phone_number": phone_number,
        "user_id": str(user.id) if getattr(user, "id", None) else "",
    }

    # allow extra values like amount, savings_balance, etc.
    context.update(extra_context)

    return context


def render_push_text(template, context):
    """
    Safely render push title/message with placeholders.
    Example:
    template = "Hi {first_name}, your wallet was credited with ₦{amount}"
    """
    if not template:
        return ""

    try:
        return str(template).format_map(SafeDict(context))
    except Exception as e:
        logger.error(f"Push template rendering failed: {e}")
        return str(template)


def send_push_notification(
    user=None,
    title="",
    message="",
    data=None,
    notif_type="SYSTEM",
    user_id=None,
    extra_context=None,
):
    """
    Send a push notification to a user via Expo and store in DB.

    Supports personalization placeholders like:
    {first_name}, {last_name}, {full_name}, {email}, {phone_number}, {user_id}

    You can also pass extra_context for custom placeholders like:
    {amount}, {plan_name}, {wallet_balance}, etc.
    """

    data = data or {}
    extra_context = extra_context or {}

    if user is None and user_id is not None:
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            logger.warning(
                f"Push notification failed: user with id {user_id} does not exist"
            )
            return {"sent": 0, "total": 0, "success": False}

    if user is None:
        logger.warning("Push notification failed: no user or user_id provided")
        return {"sent": 0, "total": 0, "success": False}

    # Build personalization context
    context = build_push_context(user, extra_context=extra_context)

    # Render title and message before saving and sending
    rendered_title = render_push_text(title, context)
    rendered_message = render_push_text(message, context)

    tokens = getattr(user, "expo_push_tokens", []) or []

    notification = PushNotifications.objects.create(
        user=user,
        title=rendered_title,
        message=rendered_message,
        notification_type=notif_type,
        data={**data, "personalization_context": context},
    )
    logger.info(f"Created notification ID {notification.id} for {user.email}")

    if not tokens:
        logger.warning(f"No push tokens for {user.email}")
        return {"sent": 0, "total": 0, "success": False}

    sent_count = 0
    valid_tokens_count = 0

    for token_entry in tokens:
        token = token_entry.get("token")
        if not token:
            continue

        valid_tokens_count += 1

        payload = {
            "to": token,
            "sound": "default",
            "title": rendered_title,
            "body": rendered_message,
            "data": {**data, "notification_id": str(notification.id)},
            "channelId": "default",
            "priority": "high",
        }

        # Expo only renders a notification's action buttons (registered via
        # setNotificationCategoryAsync on-device) when the push carries a
        # top-level categoryId - a "category" key buried inside `data` (as
        # set by push_deep_links.py) is not the same thing and gets
        # silently ignored by Expo, so the buttons never appear no matter
        # how correctly they're registered client-side.
        category = data.get("category")
        if category:
            payload["categoryId"] = category

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(
                EXPO_PUSH_URL,
                json=payload,
                headers=headers,
                timeout=10,
            )
            res_data = resp.json()

            expo_data = res_data.get("data")
            if isinstance(expo_data, dict):
                if expo_data.get("status") == "ok":
                    sent_count += 1
                else:
                    logger.warning(f"Failed sending push to {token}: {res_data}")
            elif isinstance(expo_data, list):
                item = expo_data[0] if expo_data else {}
                if item.get("status") == "ok":
                    sent_count += 1
                else:
                    logger.warning(f"Failed sending push to {token}: {res_data}")
            else:
                logger.warning(f"Unexpected Expo response for {token}: {res_data}")

        except Exception as e:
            logger.error(f"Error sending push to {token}: {e}")

    return {
        "sent": sent_count,
        "total": valid_tokens_count,
        "success": sent_count > 0,
    }


def send_admin_push_notification(
    title,
    message,
    data=None,
    notif_type="ADMIN_ALERT",
    extra_context=None,
):
    """
    Send push notifications to all admin users.
    Supports personalization too.
    """
    User = get_user_model()
    # Single source of truth: is_staff already gates the actual
    # admin-action endpoints (action_views.py's _require_staff), so it's
    # also what should gate who gets notified - a hardcoded email list
    # drifts out of sync with real staff status and silently drops new
    # admins from alerts (or keeps notifying former ones).
    admins = User.objects.filter(is_staff=True)

    if not admins.exists():
        logger.warning("No admin users found for push notification")
        return {"sent": 0, "total": 0}

    sent_count = 0

    for admin in admins:
        if getattr(admin, "expo_push_tokens", []):
            result = send_push_notification(
                user=admin,
                title=title,
                message=message,
                data=data,
                notif_type=notif_type,
                extra_context=extra_context,
            )
            if result and result.get("sent", 0) > 0:
                sent_count += 1
                logger.info(f"Admin push sent to {admin.email}")
        else:
            logger.warning(f"No push tokens for admin {admin.email}")

    return {"sent": sent_count, "total": admins.count()}


import logging
import re
import time
import os
import resend
from datetime import date
from django.conf import settings
from django.utils import timezone
from django.utils.html import strip_tags
from django.template.loader import render_to_string

from .models import CustomUser, ROITransaction

logger = logging.getLogger(__name__)

# ===== RESEND INIT =====
resend.api_key = os.environ.get("RESEND_API_KEY")


def validate_email(email):
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def send_generic_email(
    subject,
    message,
    recipient_list,
    from_email=None,
    use_celery_threshold=30,
    template="email/email.html",
    extra_context=None,
):
    """
    Smart, universal email sender (RESEND VERSION - SMTP REMOVED)
    """

    logger.info(
        f"📧 START send_generic_email - Subject: '{subject}', Recipients: {len(recipient_list) if isinstance(recipient_list, list) else 'single'}"
    )

    if isinstance(recipient_list, str):
        recipient_list = [recipient_list]

    if not recipient_list:
        logger.warning("No recipients provided")
        return {"status": "skipped", "reason": "No recipients"}

    valid_recipients = []
    invalid_recipients = []

    for email in recipient_list:
        email = str(email).strip().lower()
        if validate_email(email):
            valid_recipients.append(email)
        else:
            invalid_recipients.append(email)
            logger.warning(f"Invalid email skipped: {email}")

    if not valid_recipients:
        logger.error("No valid email addresses")
        return {
            "status": "error",
            "reason": "No valid emails",
            "invalid": invalid_recipients,
        }

    from_email = from_email or settings.DEFAULT_FROM_EMAIL
    total_valid = len(valid_recipients)

    extra_context = extra_context or {}

    logger.info(
        f"📧 Valid recipients: {total_valid}, Invalid skipped: {len(invalid_recipients)}"
    )

    # ---------- PERSONALIZATION (UNCHANGED) ----------
    def personalize(email_addr):
        try:
            user = CustomUser.objects.filter(email=email_addr).first()

            today = timezone.now().date()
            year, month = today.year, today.month
            if month <= 3:
                qs, qe, ql = (
                    date(year - 1, 10, 1),
                    date(year - 1, 12, 31),
                    f"Q4 {year-1}",
                )
            elif month <= 6:
                qs, qe, ql = date(year, 1, 1), date(year, 3, 31), f"Q1 {year}"
            elif month <= 9:
                qs, qe, ql = date(year, 4, 1), date(year, 6, 30), f"Q2 {year}"
            else:
                qs, qe, ql = date(year, 7, 1), date(year, 9, 30), f"Q3 {year}"

            roi_qs = (
                ROITransaction.objects.filter(
                    user=user, accrued_date__range=[qs, qe], is_paid_out=True
                )
                if user
                else []
            )

            total_roi = sum(r.amount for r in roi_qs)
            savings_roi = sum(r.amount for r in roi_qs if r.roi_type == "SAVINGS")
            investment_roi = sum(r.amount for r in roi_qs if r.roi_type == "INVESTMENT")

            placeholders = {
                "{first_name}": user.first_name if user else "User",
                "{last_name}": user.last_name if user else "",
                "{full_name}": getattr(user, "full_name", email_addr),
                "{email}": email_addr,
                "{wallet}": f"{getattr(user, 'wallet', 0):,.2f}",
                "{savings}": f"{getattr(user, 'savings', 0):,.2f}",
                "{investment}": f"{getattr(user, 'investment', 0):,.2f}",
                "{total_payout}": f"{total_roi:,.2f}",
                "{savings_roi}": f"{savings_roi:,.2f}",
                "{investment_roi}": f"{investment_roi:,.2f}",
                "{quarter_label}": ql,
            }

            # Add custom dynamic values
            for key, value in extra_context.items():
                placeholders[f"{{{key}}}"] = value

            p_subject = subject
            p_message = message

            for k, v in placeholders.items():
                p_subject = p_subject.replace(k, v)
                p_message = p_message.replace(k, v)

            context = {
                "subject": p_subject,
                "message": p_message,
                "user": user,
                "email": email_addr,
            }

            try:
                html_message = render_to_string(template, context)
            except Exception as e:
                logger.warning(f"Template rendering failed for {email_addr}: {e}")
                html_message = f"<html><body>{p_message}</body></html>"

            plain_message = strip_tags(html_message) or p_message

            return {
                "to": email_addr,
                "subject": p_subject,
                "html_message": html_message,
                "plain_message": plain_message,
            }

        except Exception as e:
            logger.error(f"Personalization error for {email_addr}: {e}")
            return {
                "to": email_addr,
                "subject": subject,
                "html_message": f"<html><body>{message}</body></html>",
                "plain_message": str(message),
            }

    payloads = [personalize(e) for e in valid_recipients]

    logger.info(f"📧 Personalization complete. Payloads: {len(payloads)}")

    # ---------- INLINE SEND (RESEND REPLACEMENT) ----------
    if use_celery_threshold == 0 or total_valid <= use_celery_threshold:
        logger.info(f"📧 Using INLINE Resend send for {total_valid} recipients")

        sent_count = 0
        failed_emails = []

        for p in payloads:
            try:
                # ===== RESEND (REPLACES SMTP COMPLETELY) =====
                resend.Emails.send(
                    {
                        "from": from_email or "MyFund <noreply@myfundmobile.com>",
                        "to": [p["to"]],
                        "subject": p["subject"],
                        "html": p["html_message"],
                    }
                )

                sent_count += 1
                logger.info(f"✅ Email sent via Resend to {p['to']}")

            except Exception as e:
                logger.error(f"❌ Resend failed for {p['to']}: {e}")
                failed_emails.append(p["to"])

            time.sleep(1)

        return {
            "status": "completed",
            "sent": sent_count,
            "failed": len(failed_emails),
            "failed_emails": failed_emails,
            "total": total_valid,
            "invalid_skipped": len(invalid_recipients),
            "invalid_emails": invalid_recipients,
        }

    # ---------- CELERY BATCH SEND (UNCHANGED LOGIC) ----------
    logger.info(f"📧 Using CELERY batch send for {total_valid} recipients")

    try:
        from .tasks import send_bulk_email_task

        BATCH_SIZE = 45
        DELAY_BETWEEN_EMAILS = 72
        num_batches = (total_valid + BATCH_SIZE - 1) // BATCH_SIZE

        batches = [
            payloads[i : i + BATCH_SIZE] for i in range(0, total_valid, BATCH_SIZE)
        ]

        for i, batch in enumerate(batches):
            countdown_seconds = i * 900

            logger.info(
                f"⏱ Scheduling batch {i+1}/{num_batches} in {countdown_seconds}s ({len(batch)} emails)"
            )

            send_bulk_email_task.apply_async(
                args=[batch, from_email],
                kwargs={
                    "batch_size": len(batch),
                    "delay_seconds": DELAY_BETWEEN_EMAILS,
                },
                countdown=countdown_seconds,
                queue="email_queue",
            )

        return {
            "status": "queued",
            "total": total_valid,
            "invalid_skipped": len(invalid_recipients),
            "method": "resend_batched",
            "note": "Emails queued in safe batches",
            "estimated_hours": f"{num_batches} hours",
        }

    except Exception as e:
        logger.error(f"❌ Failed to queue Celery task: {e}")
        return {"status": "error", "reason": str(e), "total": total_valid}


def get_user_balance(user, source):
    if source == "Savings":
        return user.savings
    elif source == "Investment":
        return user.investment
    elif source == "Wallet":
        return user.wallet
    else:
        return 0


def set_user_balance(user, source, amount):
    if source == "Savings":
        user.savings = amount
    elif source == "Investment":
        user.investment = amount
    elif source == "Wallet":
        user.wallet = amount


def split_amount_by_percentage(total_amount, user_percentage_pairs):
    """Split total_amount across users proportionally to their percentage share.

    user_percentage_pairs: iterable of (user_id, percentage) tuples, where
    percentage is out of 100 (does not need to sum to exactly 100).

    Uses the largest-remainder method so the returned shares always sum to
    exactly total_amount (to the cent) - straight proportional rounding can
    otherwise lose or invent pennies.

    Returns: dict of {user_id: Decimal share}, rounded to 2 decimal places.
    """
    from decimal import Decimal, ROUND_DOWN

    total_amount = Decimal(str(total_amount))
    pairs = [(user_id, Decimal(str(pct))) for user_id, pct in user_percentage_pairs]
    total_percentage = sum(pct for _, pct in pairs)

    if total_percentage <= 0 or not pairs:
        return {user_id: Decimal("0.00") for user_id, _ in pairs}

    shares = {}
    remainders = []
    cents_allocated = Decimal("0.00")

    for user_id, pct in pairs:
        exact_share = (total_amount * pct) / total_percentage
        floored_share = exact_share.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
        shares[user_id] = floored_share
        cents_allocated += floored_share
        remainders.append((exact_share - floored_share, user_id))

    leftover_cents = int(
        ((total_amount - cents_allocated) * 100).to_integral_value()
    )

    # Distribute leftover pennies to the largest fractional remainders first,
    # tie-broken deterministically by user_id.
    remainders.sort(key=lambda item: (-item[0], item[1]))
    for i in range(leftover_cents):
        _, user_id = remainders[i % len(remainders)]
        shares[user_id] += Decimal("0.01")

    return shares


def generate_reference(length=20):
    """Generate a unique reference string with allowed characters."""
    allowed_chars = string.ascii_lowercase + string.digits + "-_"
    return "".join(random.choice(allowed_chars) for _ in range(length))


from decimal import Decimal

SAVINGS_DAILY_RATE = Decimal("0.00033")  # ~1% per month
INVESTMENT_DAILY_RATE = Decimal("0.0005")  # ~1.5% per month


# utils.py - Replace the entire calculate_daily_roi function
from django.utils import timezone
from decimal import Decimal
from .models import DailyROIAccrual, ROITransaction


def calculate_daily_roi(user, date=None):
    """Calculate and store daily ROI for user"""
    if date is None:
        date = timezone.now().date()

    # Check if ROI already calculated for today
    if DailyROIAccrual.objects.filter(user=user, date=date).exists():
        accrual = DailyROIAccrual.objects.get(user=user, date=date)
        return accrual.total_roi, accrual.savings_roi, accrual.investment_roi

    # Calculate ROI
    roi_data = user.calculate_daily_roi(date)

    # Create daily accrual record
    accrual = DailyROIAccrual.objects.create(
        user=user,
        date=date,
        savings_balance=user.savings,
        investment_balance=user.investment,
        savings_roi=roi_data["savings_roi"],
        investment_roi=roi_data["investment_roi"],
        total_roi=roi_data["total_roi"],
    )

    # Create ROI transaction records
    if roi_data["savings_roi"] > 0:
        ROITransaction.objects.create(
            user=user,
            amount=roi_data["savings_roi"],
            roi_type="SAVINGS",
            accrued_date=date,
        )

    if roi_data["investment_roi"] > 0:
        ROITransaction.objects.create(
            user=user,
            amount=roi_data["investment_roi"],
            roi_type="INVESTMENT",
            accrued_date=date,
        )

    return roi_data["total_roi"], roi_data["savings_roi"], roi_data["investment_roi"]


def get_user_roi_summary(user, start_date, end_date):
    """Get ROI summary for a date range"""
    accruals = DailyROIAccrual.objects.filter(
        user=user, date__range=[start_date, end_date]
    )

    total_savings_roi = sum(accrual.savings_roi for accrual in accruals)
    total_investment_roi = sum(accrual.investment_roi for accrual in accruals)
    total_roi = sum(accrual.total_roi for accrual in accruals)

    return {
        "savings_roi": total_savings_roi,
        "investment_roi": total_investment_roi,
        "total_roi": total_roi,
        "days_count": accruals.count(),
    }


import requests
import logging
import phonenumbers
from django.conf import settings
from phonenumbers import number_type, PhoneNumberType
import urllib.parse

logger = logging.getLogger(__name__)


# --------------------------------------------------
# PHONE NORMALIZATION (STRICT SINGLE SOURCE OF TRUTH)
# --------------------------------------------------
def normalize_phone(phone_number, region="NG"):
    try:
        phone_number = phone_number.strip().replace(" ", "").replace("-", "")

        if phone_number.startswith("0") and region.upper() == "NG":
            phone_number = "+234" + phone_number[1:]

        parsed = phonenumbers.parse(phone_number, region)

        if not phonenumbers.is_valid_number(parsed):
            return None

        formatted = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )

        # FORCE 234 FORMAT ONLY (NO +)
        return formatted.replace("+", "")

    except Exception:
        return None


# --------------------------------------------------
# SMS SENDER (FINAL FIXED VERSION)
# --------------------------------------------------
def send_sms_via_payless(phone_number, message):
    base_url = settings.PAYLESS_SMS_URL
    username = settings.PAYLESS_SMS_USERNAME
    password = settings.PAYLESS_SMS_PASSWORD
    sender = settings.PAYLESS_SMS_SENDER_ID

    clean_number = normalize_phone(phone_number)

    if not clean_number:
        logger.error(f"❌ Invalid phone number: {phone_number}")
        return False

    encoded_message = urllib.parse.quote(message)

    full_url = (
        f"{base_url}?option=com_spc&comm=spc_api"
        f"&username={username}"
        f"&password={password}"
        f"&sender={sender}"
        f"&recipient={clean_number}"
        f"&message={encoded_message}"
    )

    logger.info(f"📲 Sending SMS to {clean_number}")

    try:
        response = requests.get(full_url, timeout=20)
        text = response.text.strip()

        logger.info(f"✅ Payless Response: {text}")

        # STRICT SUCCESS CHECK
        return text.upper().startswith("OK")

    except Exception as e:
        logger.error(f"❌ SMS Error: {e}")
        return False


# --------------------------------------------------
# VALIDATION WRAPPER (USED BY API)
# --------------------------------------------------
def validate_phone_number(phone_number, region="NG"):
    cleaned = normalize_phone(phone_number, region)

    if not cleaned:
        return {"valid": False, "error": "Invalid phone number format."}

    return {"valid": True, "formatted": cleaned, "error": None}


import urllib.parse
import os
import requests
import urllib.parse
from django.conf import settings


def send_bulk_sms(numbers, message):
    """
    Send bulk SMS using Payless Bulk SMS (SPC API format)
    """
    base_url = settings.PAYLESS_SMS_URL
    username = settings.PAYLESS_SMS_USERNAME
    password = settings.PAYLESS_SMS_PASSWORD
    sender = settings.PAYLESS_SMS_SENDER_ID

    encoded_message = urllib.parse.quote(message)
    recipients = numbers.replace(" ", "")  # clean up any spaces

    full_url = (
        f"{base_url}?option=com_spc&comm=spc_api"
        f"&username={username}"
        f"&password={password}"
        f"&sender={sender}"
        f"&recipient={recipients}"
        f"&message={encoded_message}"
    )

    print("🔗 Sending SMS via:", full_url)

    try:
        response = requests.get(full_url, timeout=20)
        text = response.text.strip()
        print("✅ Payless Response:", text)

        if text.upper().startswith("OK"):
            return {"success": True, "response": text}
        else:
            return {"success": False, "response": text}

    except Exception as e:
        print("❌ Error sending SMS:", e)
        return {"success": False, "error": str(e)}


def send_sms(phone_number, message):
    return send_sms_via_payless(phone_number, message)


import logging
from django.db.models import Q
from rest_framework.exceptions import AuthenticationFailed
from authentication.models import CustomUser

logger = logging.getLogger(__name__)


def authenticate_user_by_email_or_phone(username: str, password: str) -> CustomUser:
    """
    Authenticate a user by email OR phone number.

    Raises AuthenticationFailed if credentials are invalid or user not found.
    """
    username = (username or "").strip()
    password = password or ""

    # Normalize Nigerian phone numbers
    if username.isdigit() and username.startswith("0") and len(username) == 11:
        username = "+234" + username[1:]
    elif username.startswith("+234") and len(username) == 14:
        username = username  # already normalized
    # else, treat it as email or other number formats

    try:
        user = CustomUser.objects.get(
            Q(email__iexact=username) | Q(phone_number__iexact=username)
        )
    except CustomUser.DoesNotExist:
        logger.warning(f"Authentication failed: user not found for '{username}'")
        raise AuthenticationFailed("User not found")

    if not user.check_password(password):
        logger.warning(f"Authentication failed: invalid password for '{username}'")
        raise AuthenticationFailed("Invalid credentials")

    logger.info(f"User authenticated successfully: {user.email}")
    return user


from django.db.models import Sum, F, DecimalField, Q, Window
from django.db.models.functions import Coalesce, RowNumber
from django.db import transaction
from django.db import connection
from django.core.cache import cache


def _update_top_savers_worker():
    connection.close()

    now = timezone.now()
    current_month = now.month
    current_year = now.year
    lock_key = f"top_savers_lock_{current_year}_{current_month}"

    try:
        logger.info(f"Starting top savers update for {current_month}/{current_year}")

        user_amounts = (
            Transaction.objects.filter(
                date__month=current_month,
                date__year=current_year,
                status="confirmed",
                transaction_type="credit",
                credited_to__in=["SAVINGS", "INVESTMENT"],
            )
            .values("user_id")
            .annotate(
                total=Coalesce(
                    Sum("amount"),
                    Decimal("0.00"),
                    output_field=DecimalField(max_digits=14, decimal_places=2),
                )
            )
            .filter(total__gt=0)
            .annotate(
                rank=Window(
                    expression=RowNumber(),
                    order_by=[F("total").desc(), F("user_id").asc()],
                )
            )
            .order_by("rank")
        )

        ranked = list(user_amounts)

        if not ranked:
            logger.info("No users to rank for this month")
            return

        user_ids = [r["user_id"] for r in ranked]
        users = {
            u.id: u
            for u in CustomUser.objects.filter(id__in=user_ids).only(
                "id", "first_name", "last_name", "email"
            )
        }

        logger.info("Top savers ranking inputs for %s/%s:", current_month, current_year)
        for r in ranked:
            user = users.get(r["user_id"])
            if not user:
                logger.warning(
                    "Top saver ranking skipped unknown user_id=%s total=%s rank=%s",
                    r["user_id"],
                    r["total"],
                    r["rank"],
                )
                continue

            logger.info(
                "TopSaver candidate -> rank=%s user_id=%s name=%s email=%s total_saved=%s",
                r["rank"],
                user.id,
                f"{user.first_name} {user.last_name}".strip(),
                user.email,
                r["total"],
            )

        updated_count = 0
        with transaction.atomic():
            TopSaverHistory.objects.filter(
                month=current_month,
                year=current_year,
            ).delete()

            history_objects = []

            for r in ranked:
                user = users.get(r["user_id"])
                if not user:
                    continue

                history_objects.append(
                    TopSaverHistory(
                        user=user,
                        month=current_month,
                        year=current_year,
                        rank=r["rank"],
                        total_savings=r["total"],
                    )
                )
                updated_count += 1

            if history_objects:
                TopSaverHistory.objects.bulk_create(history_objects)

        logger.info(f"Successfully updated {updated_count} top savers")

    except Exception as exc:
        logger.error(f"Error updating top savers: {str(exc)}", exc_info=True)
    finally:
        cache.delete(lock_key)
        logger.info("Cleared top savers lock for %s/%s", current_month, current_year)
        connection.close()


def update_top_savers():
    """
    Initiates the top savers update in a background thread.
    Returns immediately without blocking.

    Usage:
        update_top_savers()  # Returns immediately, task runs in background
    """
    thread = threading.Thread(
        target=_update_top_savers_worker, daemon=True, name="UpdateTopSaversThread"
    )
    thread.start()
    logger.info("Top savers update thread started")
    # return thread  # Optional: return thread if you need to join() later


from decimal import Decimal
from decimal import Decimal

WITHDRAWAL_CHARGES = {
    "savings": Decimal("0.10"),  # 10%
    "investment": Decimal("0.15"),  # 15%
    "wallet": Decimal("0.00"),  # 0%
}


def calculate_withdrawal_charges(amount: Decimal, source_account: str):
    """
    Business rule (FINAL):
    - Charge is a percentage of the requested amount
    - Net amount = requested amount - charge
    - Scheduled withdrawals are handled BEFORE calling this function
    """
    rate = WITHDRAWAL_CHARGES.get(source_account, Decimal("0.00"))

    charge_amount = (amount * rate).quantize(Decimal("0.01"))
    net_amount = (amount - charge_amount).quantize(Decimal("0.01"))

    return rate, charge_amount, net_amount


import logging
from datetime import date
from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from .models import WithdrawalsRequestToAdmin, CustomUser, Transaction

logger = logging.getLogger(__name__)

ADMIN_ALERT_EMAILS = [
    "tolulopeahmed@gmail.com",
    "janet.adegbenro@gmail.com",
]


def process_scheduled_withdrawal(withdrawal, triggered_by="celery"):
    """
    Safely processes a scheduled withdrawal.

    - Credits user.wallet, not user.savings
    - Creates a separate wallet credit transaction record
    - Marks withdrawal as processed
    - Prevents double-crediting
    - Sends push notification and email after DB commit
    """

    amount = Decimal(withdrawal.total_amount or withdrawal.amount or 0)

    if amount <= 0:
        raise ValueError("Scheduled withdrawal amount must be greater than zero.")

    with transaction.atomic():
        withdrawal = WithdrawalsRequestToAdmin.objects.select_for_update().get(
            pk=withdrawal.pk
        )

        if withdrawal.is_processed:
            return "already_processed"

        user = CustomUser.objects.select_for_update().get(pk=withdrawal.user_id)

        credit_transaction_id = f"SWC-{withdrawal.transaction_id}"

        existing_credit = Transaction.objects.filter(
            user=user,
            transaction_id=credit_transaction_id,
            transaction_type="credit",
            status="confirmed",
        ).first()

        if existing_credit:
            withdrawal.is_processed = True
            withdrawal.status = "completed"
            withdrawal.save(update_fields=["is_processed", "status"])
            return "already_credited"

        previous_wallet = user.wallet or Decimal("0.00")

        user.wallet = previous_wallet + amount
        user.save(update_fields=["wallet"])

        Transaction.objects.create(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=amount,
            total_amount=amount,
            source="SCHEDULED_WITHDRAWAL",
            credited_to="WALLET",
            description="Scheduled Withdrawal Credited to Wallet",
            balance_before=previous_wallet,
            balance_after=user.wallet,
            transaction_id=credit_transaction_id,
        )

        withdrawal.is_processed = True
        # `status` never got flipped to "completed" here even though the
        # credit above is exactly what "completes" the withdrawal - it
        # stayed "pending" forever, which made a fully-processed row look
        # stuck to anyone (support/admin) checking the list view for it.
        withdrawal.status = "completed"
        withdrawal.save(update_fields=["is_processed", "status"])

        # The original debit Transaction (created when the withdrawal was
        # first scheduled) was otherwise never touched by this function -
        # it stayed "pending" forever even after the wallet credit above
        # completed the withdrawal. That ledger gap is exactly what
        # management/commands/fix_scheduled_withdrawals.py had to be
        # written to hand-patch after the fact; closing it here means new
        # withdrawals won't need that patch going forward.
        Transaction.objects.filter(
            user=user,
            transaction_id=withdrawal.transaction_id,
            transaction_type="debit",
        ).exclude(status="confirmed").update(status="confirmed")

    try:
        send_push_notification(
            user=user,
            title="Withdrawal Completed ✅",
            message=(
                f"Your scheduled withdrawal of ₦{amount:,.2f} "
                f"has been credited to your MyFund wallet."
            ),
            data={
                "amount": str(amount),
                "type": "scheduled_withdrawal_completed",
                "transaction_id": credit_transaction_id,
            },
            notif_type="SUCCESS",
        )
    except Exception:
        logger.exception(
            "Push notification failed for scheduled withdrawal %s", withdrawal.pk
        )

    try:
        send_generic_email(
            subject="Scheduled Withdrawal Completed ✅",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Your scheduled withdrawal of ₦{amount:,.2f} has been successfully "
                f"credited to your MyFund wallet.<br><br>"
                "You can now use or withdraw the funds anytime.<br><br>"
                "Thank you for using MyFund."
            ),
            from_email="MyFund <info@mg.myfundmobile.com>",
            recipient_list=[user.email],
        )
    except Exception:
        logger.exception("User email failed for scheduled withdrawal %s", withdrawal.pk)

    try:
        send_generic_email(
            subject="[AUTO] Scheduled Withdrawal Processed ✅",
            message=(
                f"Scheduled withdrawal processed successfully.<br><br>"
                f"User: {user.first_name} {user.last_name} ({user.email})<br>"
                f"Amount credited: ₦{amount:,.2f}<br>"
                f"Original Transaction ID: {withdrawal.transaction_id}<br>"
                f"Credit Transaction ID: {credit_transaction_id}<br>"
                f"Triggered by: {triggered_by}<br>"
            ),
            from_email="MyFund <info@mg.myfundmobile.com>",
            recipient_list=ADMIN_ALERT_EMAILS,
        )
    except Exception:
        logger.exception(
            "Admin email failed for scheduled withdrawal %s", withdrawal.pk
        )

    if triggered_by == "celery":
        # Same is_staff consolidation as send_admin_push_notification()'s
        # recipient targeting - a hardcoded email list silently drops
        # whichever admin isn't on it.
        admin_users = CustomUser.objects.filter(is_staff=True, is_active=True)

        for admin_user in admin_users:
            try:
                send_push_notification(
                    user=admin_user,
                    title="Scheduled Withdrawal Completed",
                    message=(
                        f"{user.first_name} {user.last_name}'s scheduled withdrawal "
                        f"of ₦{amount:,.2f} has been credited to wallet by Celery."
                    ),
                    data={
                        "type": "scheduled_withdrawal_completed_admin",
                        "customer_user_id": str(user.pk),
                        "customer_email": user.email,
                        "amount": str(amount),
                        "transaction_id": credit_transaction_id,
                    },
                    notif_type="SUCCESS",
                )
            except Exception:
                logger.exception(
                    "Admin push failed for scheduled withdrawal %s to %s",
                    withdrawal.pk,
                    admin_user.email,
                )

    return "processed"


def get_next_payout_date(today: date) -> date:
    year = today.year
    payout_dates = [
        date(year, 1, 1),
        date(year, 4, 1),
        date(year, 7, 1),
        date(year, 10, 1),
    ]

    for payout in payout_dates:
        if today < payout:
            return payout

    return date(year + 1, 1, 1)


import requests
from django.conf import settings

PAYSTACK_BASE_URL = "https://api.paystack.co"


def get_paystack_headers():
    return {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def create_paystack_recipient(account_name, account_number, bank_code):
    """
    Create a Paystack transfer recipient for withdrawals.
    Returns the recipient_code on success, else None.
    """
    payload = {
        "type": "nuban",
        "name": account_name,
        "account_number": account_number,
        "bank_code": bank_code,
        "currency": "NGN",
    }

    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/transferrecipient",
            json=payload,
            headers=get_paystack_headers(),
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        print(f"Paystack recipient request failed: {e}")
        return None
    except ValueError:
        print("Invalid JSON response from Paystack recipient endpoint")
        return None

    if not response.ok or not data.get("status"):
        print("PAYSTACK RECIPIENT RESPONSE:", response.status_code, data)
        return None

    recipient_data = data.get("data", {}) or {}
    return recipient_data.get("recipient_code")


def create_paystack_customer(user):
    """
    Create a Paystack customer if the user does not already have one.
    Returns: (success: bool, result: customer_code or error dict)
    """

    existing_code = getattr(user, "paystack_customer_code", None)

    if existing_code:
        existing_code = str(existing_code).strip()

        # Guard against corrupted tuple-like values accidentally stored
        if existing_code.startswith("CUS_"):
            return True, existing_code

        # If corrupted, clear it and recreate
        user.paystack_customer_code = None
        user.save(update_fields=["paystack_customer_code"])

    payload = {
        "email": user.email,
        "first_name": getattr(user, "first_name", "") or "",
        "last_name": getattr(user, "last_name", "") or "",
        "phone": (
            getattr(user, "phone_number", None) or getattr(user, "phone", None) or ""
        ),
    }

    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/customer",
            json=payload,
            headers=get_paystack_headers(),
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        return False, {"message": f"Paystack customer request failed: {str(e)}"}
    except ValueError:
        return False, {
            "message": "Invalid JSON response from Paystack customer endpoint"
        }

    if not response.ok or not data.get("status"):
        return False, data

    customer_data = data.get("data", {}) or {}
    customer_code = customer_data.get("customer_code")

    if not customer_code or not str(customer_code).startswith("CUS_"):
        return False, {
            "message": "Customer code missing or invalid from Paystack response",
            "raw": data,
        }

    user.paystack_customer_code = str(customer_code).strip()
    user.save(update_fields=["paystack_customer_code"])

    return True, user.paystack_customer_code


def identify_paystack_customer(user, bvn, bank_code, account_number):
    """
    Trigger Paystack customer identification for DVA creation.
    Returns: (success: bool, result: response dict)
    Only returns success when identification is completed, not merely accepted.
    """

    customer_code = getattr(user, "paystack_customer_code", None)

    if not customer_code or not str(customer_code).startswith("CUS_"):
        ok, result = create_paystack_customer(user)
        if not ok:
            return False, result
        customer_code = result
    else:
        customer_code = str(customer_code).strip()

    payload = {
        "country": "NG",
        "type": "bank_account",
        "account_number": account_number,
        "bvn": bvn,
        "bank_code": bank_code,
        "first_name": getattr(user, "first_name", "") or "",
        "last_name": getattr(user, "last_name", "") or "",
    }

    print("PAYSTACK IDENTIFICATION PAYLOAD:", payload)
    print("PAYSTACK IDENTIFICATION CUSTOMER CODE:", customer_code)

    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/customer/{customer_code}/identification",
            json=payload,
            headers=get_paystack_headers(),
            timeout=30,
        )

        print("PAYSTACK IDENTIFICATION STATUS CODE:", response.status_code)
        print("PAYSTACK IDENTIFICATION HEADERS:", dict(response.headers))
        print("PAYSTACK IDENTIFICATION RAW TEXT:", response.text)

        try:
            data = response.json()
        except ValueError:
            return False, {
                "message": "Paystack identification endpoint returned a non-JSON response.",
                "status_code": response.status_code,
                "raw_text": response.text,
            }

    except requests.RequestException as e:
        print("PAYSTACK IDENTIFICATION REQUEST FAILED:", str(e))
        return False, {"message": f"Paystack identification request failed: {str(e)}"}

    print("PAYSTACK IDENTIFICATION RESPONSE JSON:", data)

    if response.status_code == 200 and data.get("status") is True:
        return True, data

    return False, {
        "message": data.get("message", "Customer identification not yet completed."),
        "status_code": response.status_code,
        "raw": data,
        "raw_text": response.text,
    }


def create_dedicated_account(user, preferred_bank="wema-bank", force_create=False):
    """
    Create a Paystack dedicated virtual account after customer identification.
    Returns: (success: bool, result: account dict or error dict)

    If force_create=True, do not trust locally saved DVA fields; attempt fresh creation from Paystack.
    """
    existing_account_number = getattr(user, "dva_account_number", None)

    if existing_account_number and not force_create:
        return True, {
            "account_number": existing_account_number,
            "bank_name": getattr(user, "dva_bank_name", ""),
            "account_name": getattr(user, "dva_account_name", ""),
            "account_id": getattr(user, "dva_account_id", ""),
        }

    if not getattr(user, "paystack_customer_code", None):
        return False, {"message": "User has no Paystack customer code"}

    payload = {
        "customer": user.paystack_customer_code,
        "preferred_bank": preferred_bank,
    }

    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/dedicated_account",
            json=payload,
            headers=get_paystack_headers(),
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        return False, {"message": f"Paystack DVA request failed: {str(e)}"}
    except ValueError:
        return False, {
            "message": "Invalid JSON response from Paystack dedicated account endpoint"
        }

    print("CREATE DVA STATUS CODE:", response.status_code)
    print("CREATE DVA RESPONSE:", data)

    if not response.ok or not data.get("status"):
        return False, data

    dedicated = data.get("data", {}) or {}
    bank = dedicated.get("bank", {}) or {}

    account_number = dedicated.get("account_number")
    account_name = dedicated.get("account_name")
    account_id = dedicated.get("id")

    if not account_number:
        return False, {
            "message": "Account number missing from Paystack DVA response",
            "raw": data,
        }

    user.dva_account_number = account_number
    user.dva_account_name = account_name
    user.dva_bank_name = bank.get("name")
    user.dva_account_id = str(account_id) if account_id is not None else None

    update_fields = [
        "dva_account_number",
        "dva_account_name",
        "dva_bank_name",
        "dva_account_id",
    ]

    if hasattr(user, "dva_assigned_at"):
        user.dva_assigned_at = timezone.now()
        update_fields.append("dva_assigned_at")

    user.save(update_fields=update_fields)

    return True, {
        "account_number": user.dva_account_number,
        "bank_name": user.dva_bank_name,
        "account_name": user.dva_account_name,
        "account_id": user.dva_account_id,
    }


# DVA MANAGEMENT - Utility to normalize bank names to Paystack provider slugs
def normalize_provider_slug(bank_name):
    """
    Convert common bank names to Paystack provider slugs.
    Defaults to wema-bank if unknown.
    """
    if not bank_name:
        return "wema-bank"

    value = str(bank_name).strip().lower()

    mapping = {
        "wema bank": "wema-bank",
        "wema": "wema-bank",
        "titan paystack": "titan-paystack",
        "titan": "titan-paystack",
    }

    return mapping.get(value, value.replace(" ", "-"))


def clear_local_dva_fields(user, save=True):
    """
    Clear locally stored DVA fields on the user.
    Does NOT reset paystack_identified by default.
    """
    user.dva_account_number = None
    user.dva_account_name = None
    user.dva_bank_name = None
    user.dva_account_id = None

    update_fields = [
        "dva_account_number",
        "dva_account_name",
        "dva_bank_name",
        "dva_account_id",
    ]

    if hasattr(user, "dva_assigned_at"):
        user.dva_assigned_at = None
        update_fields.append("dva_assigned_at")

    if save:
        user.save(update_fields=update_fields)

    return True, {
        "message": "Local DVA fields cleared successfully.",
        "cleared_fields": update_fields,
    }


def fetch_dedicated_account_by_id(dedicated_account_id):
    """
    Fetch a dedicated account directly from Paystack by DVA id.
    Returns: (success: bool, result: dict)
    """
    if not dedicated_account_id:
        return False, {"message": "No dedicated account id provided."}

    try:
        response = requests.get(
            f"{PAYSTACK_BASE_URL}/dedicated_account/{dedicated_account_id}",
            headers=get_paystack_headers(),
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        return False, {"message": f"Fetch DVA request failed: {str(e)}"}
    except ValueError:
        return False, {"message": "Invalid JSON response from fetch DVA endpoint"}

    if not response.ok or not data.get("status"):
        return False, {
            "message": data.get("message", "Failed to fetch dedicated account"),
            "raw": data,
            "status_code": response.status_code,
        }

    return True, data.get("data", {}) or {}


def list_dedicated_accounts_for_customer(user):
    """
    List dedicated accounts for a user's Paystack customer code.
    Returns: (success: bool, result: list|dict)
    """
    customer_code = getattr(user, "paystack_customer_code", None)
    if not customer_code:
        return False, {"message": "User has no Paystack customer code."}

    try:
        response = requests.get(
            f"{PAYSTACK_BASE_URL}/dedicated_account",
            headers=get_paystack_headers(),
            params={"customer": customer_code},
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        return False, {"message": f"List DVA request failed: {str(e)}"}
    except ValueError:
        return False, {"message": "Invalid JSON response from list DVA endpoint"}

    if not response.ok or not data.get("status"):
        return False, {
            "message": data.get("message", "Failed to list dedicated accounts"),
            "raw": data,
            "status_code": response.status_code,
        }

    return True, data.get("data", []) or []


def requery_dedicated_account(user, query_date=None):
    """
    Trigger Paystack requery for a user's DVA.
    Uses account number and provider slug.
    Returns: (success: bool, result: dict)
    """
    account_number = getattr(user, "dva_account_number", None)
    if not account_number:
        return False, {"message": "User has no local DVA account number to requery."}

    provider_slug = normalize_provider_slug(getattr(user, "dva_bank_name", None))
    query_date = query_date or date.today().isoformat()

    try:
        response = requests.get(
            f"{PAYSTACK_BASE_URL}/dedicated_account/requery",
            headers=get_paystack_headers(),
            params={
                "account_number": account_number,
                "provider_slug": provider_slug,
                "date": query_date,
            },
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        return False, {"message": f"Requery DVA request failed: {str(e)}"}
    except ValueError:
        return False, {"message": "Invalid JSON response from requery DVA endpoint"}

    if not response.ok or not data.get("status"):
        return False, {
            "message": data.get("message", "Failed to requery dedicated account"),
            "raw": data,
            "status_code": response.status_code,
        }

    return True, data


def sync_user_dva_from_paystack(user):
    """
    Sync the user's local DVA fields from Paystack.
    Priority:
    1. Fetch by local dva_account_id if available
    2. Otherwise list by paystack_customer_code and select an assigned account
    3. If no assigned DVA exists, clear local DVA fields

    Returns: (success: bool, result: dict)
    """
    dedicated = None

    local_dva_id = getattr(user, "dva_account_id", None)
    if local_dva_id:
        ok, result = fetch_dedicated_account_by_id(local_dva_id)
        if ok:
            dedicated = result
        else:
            print(f"Fetch by local DVA id failed for {user.email}: {result}")

    if dedicated is None:
        ok, result = list_dedicated_accounts_for_customer(user)
        if not ok:
            return False, result

        accounts = result or []

        assigned_accounts = [item for item in accounts if item.get("assigned") is True]

        if assigned_accounts:
            # Pick the latest by created_at/update order returned by Paystack
            dedicated = assigned_accounts[0]
        else:
            clear_local_dva_fields(user, save=True)
            return True, {
                "message": "No assigned DVA found on Paystack. Local DVA fields cleared.",
                "action": "cleared_local_dva",
            }

    bank = dedicated.get("bank", {}) or {}
    account_id = dedicated.get("id")
    account_number = dedicated.get("account_number")
    account_name = dedicated.get("account_name")
    assigned = dedicated.get("assigned", False)

    if not assigned or not account_number:
        clear_local_dva_fields(user, save=True)
        return True, {
            "message": "Dedicated account is not assigned on Paystack. Local fields cleared.",
            "action": "cleared_local_dva",
            "raw": dedicated,
        }

    user.dva_account_number = account_number
    user.dva_account_name = account_name
    user.dva_bank_name = bank.get("name")
    user.dva_account_id = str(account_id) if account_id is not None else None

    update_fields = [
        "dva_account_number",
        "dva_account_name",
        "dva_bank_name",
        "dva_account_id",
    ]

    if hasattr(user, "dva_assigned_at") and not getattr(user, "dva_assigned_at", None):
        user.dva_assigned_at = timezone.now()
        update_fields.append("dva_assigned_at")

    user.save(update_fields=update_fields)

    return True, {
        "message": "Local DVA synced successfully from Paystack.",
        "account_number": user.dva_account_number,
        "bank_name": user.dva_bank_name,
        "account_name": user.dva_account_name,
        "account_id": user.dva_account_id,
        "raw": dedicated,
    }


def deactivate_user_dva(user, clear_local=True):
    """
    Deactivate (unassign) a user's dedicated account on Paystack.
    Optionally clears local DVA fields after Paystack success.

    Returns: (success: bool, result: dict)
    """
    dedicated_account_id = getattr(user, "dva_account_id", None)

    if not dedicated_account_id:
        return False, {"message": "User has no local DVA account id."}

    try:
        response = requests.delete(
            f"{PAYSTACK_BASE_URL}/dedicated_account/{dedicated_account_id}",
            headers=get_paystack_headers(),
            timeout=30,
        )
        data = response.json()
    except requests.RequestException as e:
        return False, {"message": f"Deactivate DVA request failed: {str(e)}"}
    except ValueError:
        return False, {"message": "Invalid JSON response from deactivate DVA endpoint"}

    if not response.ok or not data.get("status"):
        return False, {
            "message": data.get("message", "Failed to deactivate dedicated account"),
            "raw": data,
            "status_code": response.status_code,
        }

    result = {
        "message": data.get("message", "Dedicated account deactivated successfully."),
        "raw": data,
    }

    if clear_local:
        clear_local_dva_fields(user, save=True)
        result["local_clear"] = True

    return True, result


def recreate_user_dva(user, preferred_bank="wema-bank"):
    """
    Recreate a user's DVA from admin.
    Requires a Paystack customer code and successful identification.
    """
    if not getattr(user, "paystack_customer_code", None):
        return False, {"message": "User has no Paystack customer code."}

    if not getattr(user, "paystack_identified", False):
        return False, {
            "message": "User is not currently marked as Paystack identified."
        }

    return create_dedicated_account(
        user,
        preferred_bank=preferred_bank,
        force_create=True,
    )


from decimal import Decimal
from django.utils import timezone

from .models import Transaction
from .utils import send_generic_email, send_push_notification


from decimal import Decimal
from django.db import transaction as db_transaction
from django.utils import timezone


def approve_quicksave_credit(
    *,
    user,
    amount,
    transaction_id,
    description="QuickSave (Transfer)",
    source="BANK_TRANSFER",
    paystack_reference=None,
    paystack_auth_code=None,
):
    amount = Decimal(str(amount))

    with db_transaction.atomic():
        locked_user = type(user).objects.select_for_update().get(pk=user.pk)

        tx = (
            Transaction.objects.select_for_update()
            .filter(
                user=locked_user,
                transaction_id=transaction_id,
                status="pending",
            )
            .first()
        )

        if not tx:
            return False, f"Pending transaction {transaction_id} not found."

        previous_balance = locked_user.savings or Decimal("0.00")
        new_balance = previous_balance + amount

        locked_user.savings = new_balance
        locked_user.save(update_fields=["savings"])

        tx.status = "confirmed"
        tx.description = description
        tx.source = source
        tx.credited_to = "SAVINGS"
        tx.amount = amount
        tx.service_charge = Decimal("0.00")
        tx.total_amount = amount
        tx.balance_before = previous_balance
        tx.balance_after = new_balance
        tx.paystack_reference = paystack_reference
        tx.paystack_auth_code = paystack_auth_code
        tx.save(
            update_fields=[
                "status",
                "description",
                "source",
                "credited_to",
                "amount",
                "service_charge",
                "total_amount",
                "balance_before",
                "balance_after",
                "paystack_reference",
                "paystack_auth_code",
            ]
        )

    if locked_user.referral:
        locked_user.confirm_referral_rewards(is_referrer=False)

    locked_user.update_total_savings_and_investment_this_month()
    locked_user.save(
        update_fields=[
            "total_savings_and_investments_this_month",
            "updated_at",
        ]
    )

    send_generic_email(
        subject="QuickSave Updated! ✅",
        message=(
            f"Hi {locked_user.first_name},<br><br>"
            f"Your QuickSave deposit of ₦{amount:,.2f} "
            f"has been confirmed and added to your Savings account."
        ),
        from_email="MyFund <info@mg.myfundmobile.com>",
        recipient_list=[locked_user.email],
    )

    send_push_notification(
        user=locked_user,
        title="QuickSave Approved ✅",
        message=(
            f"Hi {locked_user.first_name}, your transfer of "
            f"₦{amount:,.2f} has been added to your Savings account."
        ),
        data={
            "amount": str(amount),
            "transaction_id": tx.transaction_id,
            "type": "QuickSave",
            "source": source,
            "status": "confirmed",
            "paystack_reference": paystack_reference,
        },
        notif_type="CREDIT",
    )

    return True, "QuickSave approved successfully."


from decimal import Decimal
from django.db import transaction as db_transaction
from django.utils import timezone


def approve_quickinvest_credit(
    *,
    user,
    amount,
    transaction_id,
    description="QuickInvest (Transfer)",
    source="BANK_TRANSFER",
):
    amount = Decimal(str(amount))

    with db_transaction.atomic():
        locked_user = type(user).objects.select_for_update().get(pk=user.pk)

        tx = (
            Transaction.objects.select_for_update()
            .filter(
                user=locked_user,
                transaction_id=transaction_id,
                status="pending",
            )
            .first()
        )

        if not tx:
            return False, f"Pending transaction {transaction_id} not found."

        previous_balance = locked_user.investment or Decimal("0.00")
        new_balance = previous_balance + amount

        locked_user.investment = new_balance
        locked_user.save(update_fields=["investment"])

        tx.status = "confirmed"
        tx.description = description
        tx.source = source
        tx.credited_to = "INVESTMENT"
        tx.amount = amount
        tx.service_charge = Decimal("0.00")
        tx.total_amount = amount
        tx.balance_before = previous_balance
        tx.balance_after = new_balance
        tx.save(
            update_fields=[
                "status",
                "description",
                "source",
                "credited_to",
                "amount",
                "service_charge",
                "total_amount",
                "balance_before",
                "balance_after",
            ]
        )

    if locked_user.referral:
        locked_user.confirm_referral_rewards(is_referrer=False)

    locked_user.update_total_savings_and_investment_this_month()

    send_generic_email(
        subject="QuickInvest Updated! ✅",
        message=(
            f"Hi {locked_user.first_name},<br><br>"
            f"Your QuickInvest deposit of ₦{amount:,.2f} "
            f"has been confirmed and added to your Investment account."
        ),
        from_email="MyFund <info@mg.myfundmobile.com>",
        recipient_list=[locked_user.email],
    )

    send_push_notification(
        user=locked_user,
        title="QuickInvest Approved ✅",
        message=(
            f"Hi {locked_user.first_name}, your transfer of "
            f"₦{amount:,.2f} has been added to your Investment account."
        ),
        data={
            "amount": str(amount),
            "transaction_id": tx.transaction_id,
            "type": "QuickInvest",
            "source": source,
            "status": "confirmed",
        },
        notif_type="CREDIT",
    )

    return True, "QuickInvest approved successfully."


import requests
from django.conf import settings


def requery_paystack_dva(account_number):
    url = f"https://api.paystack.co/dedicated_account/requery?account_number={account_number}"

    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.get(url, headers=headers, timeout=60)

    try:
        data = response.json()
    except Exception:
        data = {"status": False, "message": response.text}

    return response.status_code, data


def send_ambassador_status_notification(user, became_ambassador=True):
    """
    Send push notification + email when ambassador status changes.
    """
    try:
        if became_ambassador:
            push_title = "🎉 You are now a MyFund Ambassador!"
            push_message = (
                f"Hi {user.first_name}, congratulations! "
                "Your account has been updated to Ambassador status. You now have access to the MyFund Ambassador portal and benefits. Enjoy!"
            )

            email_subject = "You are now a MyFund Ambassador 🎉"
            email_message = (
                f"Hi {user.first_name},<br><br>"
                "Congratulations! Your MyFund account has been updated to "
                "<b>Ambassador status</b>.<br><br>"
                "You can now enjoy ambassador-related benefits and opportunities on MyFund.<br><br>"
                "Keep winning with MyFund. 🚀"
            )

            data = {
                "type": "AMBASSADOR_GRANTED",
                "is_ambassador": True,
            }
        else:
            push_title = "Ambassador Status Updated"
            push_message = (
                f"Hi {user.first_name}, your MyFund Ambassador status has been removed."
            )

            email_subject = "Your MyFund Ambassador Status Was Updated"
            email_message = (
                f"Hi {user.first_name},<br><br>"
                "Your MyFund Ambassador status has been removed from your account.<br><br>"
                "If you believe this was done in error, please contact support.<br><br>"
                "MyFund Team"
            )

            data = {
                "type": "AMBASSADOR_REVOKED",
                "is_ambassador": False,
            }

        # Push
        try:
            send_push_notification(
                user=user,
                title=push_title,
                message=push_message,
                data=data,
                notif_type="SYSTEM",
            )
        except Exception as push_error:
            logger.error(
                f"Failed to send ambassador push to {user.email}: {push_error}"
            )

        # Email
        try:
            send_generic_email(
                subject=email_subject,
                message=email_message,
                from_email="MyFund <info@mg.myfundmobile.com>",
                recipient_list=[user.email],
            )
        except Exception as email_error:
            logger.error(
                f"Failed to send ambassador email to {user.email}: {email_error}"
            )

    except Exception as e:
        logger.error(f"Ambassador notification error for {user.email}: {e}")


def grant_user_ambassador_status(user):
    """
    Grant ambassador status and notify the user.
    Returns True if the status changed.
    """
    if user.is_ambassador:
        return False

    user.is_ambassador = True
    user.save(update_fields=["is_ambassador"])

    send_ambassador_status_notification(
        user=user,
        became_ambassador=True,
    )

    return True


def revoke_user_ambassador_status(user):
    """
    Revoke ambassador status and notify the user.
    Returns True if the status changed.
    """
    if not user.is_ambassador:
        return False

    user.is_ambassador = False
    user.save(update_fields=["is_ambassador"])

    send_ambassador_status_notification(
        user=user,
        became_ambassador=False,
    )

    return True


from django.utils import timezone
from .models import AmbassadorAttendanceSubmission


def get_user_monthly_attendance_count(user):
    now = timezone.now()
    current_month = now.strftime("%Y-%m")
    return AmbassadorAttendanceSubmission.objects.filter(
        user=user,
        month=current_month,
    ).count()


from datetime import timedelta
from decimal import Decimal
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from .models import (
    CustomUser,
    AmbassadorMonthlyReport,
    AmbassadorAttendanceSubmission,
    Transaction,
)


def autosubmit_missing_ambassador_reports_for_previous_month():
    """
    Auto-submit ambassador monthly reports for the PREVIOUS month
    using PREFILLED METRICS ONLY.

    Manual / evidence-based fields are forced to 0.
    Safe to run multiple times because it skips users who already have a report.
    """
    now = timezone.localtime(timezone.now())

    current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    previous_month_end = current_month_start - timedelta(seconds=1)
    previous_month_start = previous_month_end.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )

    target_month_key = previous_month_start.strftime("%Y-%m")
    year = previous_month_start.year
    month = previous_month_start.month

    ambassadors = CustomUser.objects.filter(
        is_ambassador=True,
        is_active=True,
    )

    created_count = 0
    skipped_count = 0
    errors = []

    for user in ambassadors:
        try:
            if AmbassadorMonthlyReport.objects.filter(
                user=user,
                month=target_month_key,
            ).exists():
                skipped_count += 1
                continue

            # 1. Signups for previous month
            signups_submitted = CustomUser.objects.filter(
                referral=user,
                date_joined__gte=previous_month_start,
                date_joined__lte=previous_month_end,
            ).count()

            # 2. Confirmed referrals for previous month
            confirmed_submitted = CustomUser.objects.filter(
                referral=user,
                referral_reward_confirmed_at__gte=previous_month_start,
                referral_reward_confirmed_at__lte=previous_month_end,
                referral_reward_granted=True,
            ).count()

            # 3. Attendance count for previous month
            attendance_submitted = AmbassadorAttendanceSubmission.objects.filter(
                user=user,
                month=target_month_key,
            ).count()

            # 4. Savings + Investment credited this month
            savings_submitted = Transaction.objects.filter(
                user=user,
                date__year=year,
                date__month=month,
                status="confirmed",
                transaction_type="credit",
                credited_to__in=["SAVINGS", "INVESTMENT"],
            ).aggregate(total=Sum("amount")).get("total") or Decimal("0.00")

            # 5. Others
            # Keep zero unless you later connect this to a real backend source
            others_submitted = 0

            with transaction.atomic():
                report = AmbassadorMonthlyReport.objects.create(
                    user=user,
                    month=target_month_key,
                    signups_submitted=signups_submitted,
                    confirmed_submitted=confirmed_submitted,
                    savings_submitted=savings_submitted,
                    attendance_submitted=attendance_submitted,
                    others_submitted=others_submitted,
                    # manual / optional fields forced to zero on system autosubmit
                    coursera_submitted=0,
                    social_media_submitted=0,
                    abroad_confirmed_submitted=0,
                    events_submitted=0,
                    notes="Auto-submitted by system using prefilled metrics only.",
                )

                report.copy_submitted_to_approved_defaults()
                report.recalculate_points()
                report.save()

            created_count += 1

        except Exception as e:
            errors.append(f"{user.email}: {str(e)}")

    return {
        "month": target_month_key,
        "created": created_count,
        "skipped": skipped_count,
        "errors": errors,
    }


from decimal import Decimal
from django.db import transaction as db_transaction
from .models import Transaction


def create_transaction(
    *,
    user,
    amount,
    transaction_type,
    status="confirmed",
    source=None,
    credited_to=None,
    description="",
    service_charge=0,
    reference=None,
):
    from decimal import Decimal
    from django.db import transaction as db_transaction

    amount = Decimal(str(amount))
    service_charge = Decimal(str(service_charge or 0))

    # 🔍 Determine which balance we are touching
    if credited_to == "SAVINGS" or source == "SAVINGS":
        balance_field = "savings"
    elif credited_to == "INVESTMENT" or source == "INVESTMENT":
        balance_field = "investment"
    elif credited_to == "WALLET" or source == "WALLET":
        balance_field = "wallet"
    else:
        raise ValueError("Cannot determine balance source")

    previous_balance = getattr(user, balance_field)

    # 💰 Compute new balance
    if transaction_type == "credit":
        new_balance = previous_balance + amount
    else:
        total_deduction = amount + service_charge
        new_balance = previous_balance - total_deduction

    # ✅ NOW log correctly
    print("\n=== CREATE TRANSACTION DEBUG ===")
    print("User:", user.id)
    print("Type:", transaction_type)
    print("Account:", balance_field)
    print("Amount:", amount)
    print("Before:", previous_balance)
    print("After:", new_balance)
    print("================================\n")

    with db_transaction.atomic():
        setattr(user, balance_field, new_balance)
        user.save(update_fields=[balance_field])

        transaction_data = {
            "user": user,
            "amount": amount,
            "transaction_type": transaction_type,
            "status": status,
            "source": source,
            "credited_to": credited_to,
            "description": description,
            "service_charge": service_charge,
            "balance_before": previous_balance,
            "balance_after": new_balance,
        }

        # Only set transaction_id when a reference was actually supplied.
        if reference:
            transaction_data["transaction_id"] = reference

        tx = Transaction.objects.create(**transaction_data)

        print("✅ TX SAVED:", tx.balance_before, tx.balance_after)

    return tx


# GroupBuy minimum duration is 3 months (enforced in create_groupbuy). A
# GroupBuy that reaches its deadline without hitting 100% funding is expired
# here: every confirmed contributor is refunded (minus a 1% service charge),
# the group is marked failed, and the property's unit is released so a new
# GroupBuy can be started against it. Shared by both the management command
# (authentication/management/commands/expire_groupbuys.py) and the Celery
# task (authentication.tasks.expire_groupbuys_task) so there's one source of
# truth for the sweep logic regardless of how it's triggered.
def expire_overdue_groupbuys(dry_run=False):
    from decimal import Decimal, ROUND_HALF_UP

    from django.utils import timezone

    from .models import Group, Contribution, GroupOwnership

    SERVICE_CHARGE_RATE = Decimal("0.01")  # 1%

    now = timezone.now()
    overdue_groups = Group.objects.filter(
        status__in=["Active", "active"],
        deadline__lt=now,
    ).select_related("property")

    expired_groups = []
    total_refunded = Decimal("0")
    total_service_charge = Decimal("0")

    for group in overdue_groups:
        # Fully (or over-)funded by the deadline is a success, not an
        # expiry - leave it for the normal completion flow to handle.
        if group.total_raised >= group.goal_amount:
            continue

        contributions = Contribution.objects.filter(
            group=group, payment_status="Confirmed"
        ).select_related("user")

        contributor_details = []

        for contribution in contributions:
            amount = contribution.amount
            service_charge = (amount * SERVICE_CHARGE_RATE).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            refund_amount = amount - service_charge

            contributor_details.append(
                {
                    "email": contribution.user.email,
                    "amount": amount,
                    "service_charge": service_charge,
                    "refund_amount": refund_amount,
                    "source": contribution.source,
                }
            )

            if not dry_run:
                create_transaction(
                    user=contribution.user,
                    amount=refund_amount,
                    transaction_type="credit",
                    credited_to=contribution.source.upper(),
                    status="confirmed",
                    service_charge=service_charge,
                    description=(
                        f"GroupBuy expired - refund for {group.property.name} "
                        f"(1% service charge of ₦{service_charge} applied)"
                    ),
                )
                contribution.payment_status = "Refunded"
                contribution.save()

                try:
                    send_push_notification(
                        user=contribution.user,
                        title="GroupBuy Expired - Refunded",
                        message=(
                            f"The GroupBuy for {group.property.name} didn't reach its "
                            f"goal before the deadline. ₦{refund_amount:,.2f} has been "
                            f"refunded to your {contribution.source} account (1% "
                            f"service charge applied)."
                        ),
                        notif_type="CREDIT",
                        data={"group_id": str(group.id), "type": "GROUPBUY_EXPIRED"},
                    )
                except Exception:
                    pass

            total_refunded += refund_amount
            total_service_charge += service_charge

        if not dry_run:
            group.status = "failed"
            group.save()

            GroupOwnership.objects.filter(group=group).delete()

            # Release the unit so the property is available to start again.
            property_obj = group.property
            property_obj.units_available += 1
            property_obj.save()

        expired_groups.append(
            {
                "group_id": str(group.id),
                "property": group.property.name,
                "contributors": contributor_details,
            }
        )

    return {
        "expired_count": len(expired_groups),
        "total_refunded": total_refunded,
        "total_service_charge": total_service_charge,
        "groups": expired_groups,
    }
