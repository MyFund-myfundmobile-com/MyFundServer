import requests
from .models import PushNotifications, TopSaverHistory, Transaction
from .models import PushNotifications
from django.utils import timezone
from django.core.mail import send_mail
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

logger = logging.getLogger(__name__)

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"

ADMIN_PUSH_EMAILS = [
    "tolulopeahmed@gmail.com",
    "ceo@myfundmobile.com",
]


def send_push_notification(user, title, message, data=None, notif_type="SYSTEM"):
    """Send a push notification to a user via Expo and store in DB."""
    data = data or {}
    tokens = getattr(user, "expo_push_tokens", []) or []

    notification = PushNotifications.objects.create(
        user=user,
        title=title,
        message=message,
        notification_type=notif_type,
        data=data,
    )
    logger.info(f"Created notification ID {notification.id} for {user.email}")

    if not tokens:
        logger.warning(f"No push tokens for {user.email}")
        return {"sent": 0, "total": 0}

    sent_count = 0
    for token_entry in tokens:
        token = token_entry.get("token")
        if not token:
            continue

        payload = {
            "to": token,
            "sound": "default",
            "title": title,
            "body": message,
            "data": {**data, "notification_id": str(notification.id)},
            "channelId": "default",
            "priority": "high",
        }

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        try:
            resp = requests.post(
                EXPO_PUSH_URL, json=payload, headers=headers, timeout=10
            )
            res_data = resp.json()
            if res_data.get("data", {}).get("status") == "ok":
                sent_count += 1
            else:
                logger.warning(f"Failed sending push to {token}: {res_data}")
        except Exception as e:
            logger.error(f"Error sending push to {token}: {e}")

    return {"sent": sent_count, "total": len(tokens)}


def send_admin_push_notification(title, message, data=None, notif_type="ADMIN_ALERT"):
    """Send push notifications to all admin users."""
    User = get_user_model()
    admins = User.objects.filter(email__in=ADMIN_PUSH_EMAILS)
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
            )
            if result and result.get("sent", 0) > 0:
                sent_count += 1
                logger.info(f"Admin push sent to {admin.email}")
        else:
            logger.warning(f"No push tokens for admin {admin.email}")

    return {"sent": sent_count, "total": admins.count()}


import logging
import re
from datetime import date
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from .models import CustomUser, ROITransaction

logger = logging.getLogger(__name__)


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
):
     
    """
    Smart, universal email sender:

    - ≤use_celery_threshold recipients → send inline immediately
    - >use_celery_threshold → send via Celery worker (batch)
    - Always renders message with template for header/footer
    - Supports string message or dict context
    - Performs user-level personalization
    """
    
    if isinstance(recipient_list, str):
        recipient_list = [recipient_list]

    if not recipient_list:
        return {
            "status": "error",
            "reason": "No recipients provided",
        }

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
        return {
            "status": "error",
            "reason": "No valid emails",
            "invalid": invalid_recipients,
        }

    from_email = from_email or settings.DEFAULT_FROM_EMAIL
    total_valid = len(valid_recipients)

    logger.info(f"📧 Preparing to send '{subject}' to {total_valid} recipients")

    # ---------- Personalization ----------
    def personalize(email_addr):
        try:
            user = CustomUser.objects.filter(email=email_addr).first()

            today = timezone.now().date()
            year, month = today.year, today.month
            if month <= 3:
                qs, qe, ql = date(year - 1, 10, 1), date(year - 1, 12, 31), f"Q4 {year-1}"
            elif month <= 6:
                qs, qe, ql = date(year, 1, 1), date(year, 3, 31), f"Q1 {year}"
            elif month <= 9:
                qs, qe, ql = date(year, 4, 1), date(year, 6, 30), f"Q2 {year}"
            else:
                qs, qe, ql = date(year, 7, 1), date(year, 9, 30), f"Q3 {year}"

            roi_qs = (
                ROITransaction.objects.filter(
                    user=user,
                    accrued_date__range=[qs, qe],
                    is_paid_out=True,
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

            p_subject = subject
            p_message = message if isinstance(message, str) else message.get("message", "")

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
            except Exception:
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
            raise

    payloads = []
    failed_emails = []

    for email in valid_recipients:
        try:
            payloads.append(personalize(email))
        except Exception:
            failed_emails.append(email)

    # ---------- INLINE SEND ----------
    if len(payloads) <= use_celery_threshold:
        sent = 0
        failed = 0

        for p in payloads:
            try:
                send_mail(
                    subject=p["subject"],
                    message=p["plain_message"],
                    from_email=from_email,
                    recipient_list=[p["to"]],
                    html_message=p["html_message"],
                    fail_silently=False,
                )
                sent += 1
                logger.info(f"✅ Inline email sent to {p['to']}")
            except Exception as e:
                failed += 1
                failed_emails.append(p["to"])
                logger.error(f"❌ Email failed for {p['to']}: {e}")

        return {
            "status": "completed",
            "sent": sent,
            "failed": failed,
            "invalid_skipped": len(invalid_recipients),
            "failed_emails": failed_emails,
        }

    # ---------- CELERY BATCH SEND ----------
    from .tasks import send_bulk_email_task

    send_bulk_email_task.delay(payloads, from_email)

    logger.info(
        f"📦 Emails queued for Celery batch processing ({len(payloads)} recipients)"
    )

    return {
        "status": "queued",
        "queued": len(payloads),
        "invalid_skipped": len(invalid_recipients),
    }


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
from phonenumbers.phonenumberutil import number_type, PhoneNumberType
import urllib.parse

logger = logging.getLogger(__name__)


def send_sms_via_payless(phone_number, message):
    """
    Send SMS via Payless SPC API.
    Returns True if SMS delivered successfully, False otherwise.
    """
    base_url = settings.PAYLESS_SMS_URL
    username = settings.PAYLESS_SMS_USERNAME
    password = settings.PAYLESS_SMS_PASSWORD
    sender = settings.PAYLESS_SMS_SENDER_ID

    encoded_message = urllib.parse.quote(message)
    recipients = phone_number.replace(" ", "")

    full_url = (
        f"{base_url}?option=com_spc&comm=spc_api"
        f"&username={username}"
        f"&password={password}"
        f"&sender={sender}"
        f"&recipient={recipients}"
        f"&message={encoded_message}"
    )

    logger.info(f"🔗 Sending SMS via: {full_url}")

    try:
        response = requests.get(full_url, timeout=20)
        text = response.text.strip()
        logger.info(f"✅ Payless Response: {text}")

        return text.upper().startswith("OK")
    except Exception as e:
        logger.error(f"❌ Error sending SMS: {e}")
        return False


def validate_phone_number(phone_number, region="NG"):
    """
    Validate and normalize phone number using Google's libphonenumber.
    Always returns E.164 format (+234...) if valid.
    """
    try:
        # Clean up common formatting issues
        phone_number = phone_number.strip().replace(" ", "").replace("-", "")

        # If user entered 080..., add +234 manually for Nigerian defaults
        if phone_number.startswith("0") and region.upper() == "NG":
            phone_number = "+234" + phone_number[1:]

        # Parse the number
        parsed = phonenumbers.parse(phone_number, region)
        if not phonenumbers.is_valid_number(parsed):
            return {"valid": False, "error": "Invalid phone number format."}

        formatted = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )

        line_type = number_type(parsed)
        is_mobile = line_type in [
            PhoneNumberType.MOBILE,
            PhoneNumberType.FIXED_LINE_OR_MOBILE,
        ]

        if not is_mobile:
            return {"valid": False, "error": "Only mobile numbers are allowed."}

        return {"valid": True, "formatted": formatted, "error": None}

    except phonenumbers.NumberParseException:
        return {"valid": False, "error": "Could not parse phone number."}


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
from django.db.models.functions import Coalesce, Rank
from django.db import transaction
from django.db import connection


def _update_top_savers_worker():
    """
    Worker function that performs the actual top savers update.
    Runs in a separate thread.
    """
    # Close the existing database connection to avoid threading issues
    connection.close()

    try:
        now = timezone.now()
        current_month = now.month
        current_year = now.year

        logger.info(f"Starting top savers update for {current_month}/{current_year}")

        # Aggregate total savings per user
        user_amounts = (
            Transaction.objects.filter(
                date__month=current_month,
                date__year=current_year,
            )
            .filter(
                Q(status="confirmed", transaction_type="credit")
                | Q(description__in=["AutoSave (Confirmed)", "AutoInvest (Confirmed)"])
            )
            .values("user_id")
            .annotate(total=Coalesce(Sum("amount"), 0, output_field=DecimalField()))
            .filter(total__gt=0)
            .annotate(rank=Window(expression=Rank(), order_by=F("total").desc()))
            .order_by("rank")
        )

        ranked = list(user_amounts)
        if not ranked:
            logger.info("No users to rank for this month")
            return

        top_amount = ranked[0]["total"] or 1
        user_ids = [r["user_id"] for r in ranked]
        users = {u.id: u for u in CustomUser.objects.filter(id__in=user_ids)}

        # Prepare bulk upsert
        updated_count = 0
        with transaction.atomic():
            for r in ranked:
                user = users.get(r["user_id"])
                if not user:
                    continue
                TopSaverHistory.objects.update_or_create(
                    month=current_month,
                    year=current_year,
                    rank=r["rank"],
                    defaults={"user": user, "total_savings": r["total"]},
                )
                updated_count += 1

        logger.info(f"Successfully updated {updated_count} top savers")

    except Exception as exc:
        logger.error(f"Error updating top savers: {str(exc)}", exc_info=True)
    finally:
        # Close database connection after thread completes
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


from django.db import transaction
from django.utils import timezone
from decimal import Decimal


def process_scheduled_withdrawal(withdrawal):
    """
    Credits wallet for completed scheduled withdrawal
    + sends push & email notifications
    """
    user = withdrawal.user
    amount = withdrawal.amount  # net amount

    with transaction.atomic():
        # Lock user
        user = CustomUser.objects.select_for_update().get(pk=user.pk)

        # 1️⃣ Credit wallet
        user.wallet += amount
        user.save()

        # 2️⃣ Create credit transaction
        Transaction.objects.create(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=amount,
            source="WALLET",
            description="Scheduled withdrawal completed – wallet credited",
        )

        # 3️⃣ Mark withdrawal processed
        withdrawal.is_approved = True
        withdrawal.is_processed = True
        withdrawal.save()

    # 4️⃣ Push notification (user)
    send_push_notification(
        user=user,
        title="Withdrawal Ready 🎉",
        message=(
            f"Hi {user.first_name}, your scheduled withdrawal of ₦{amount:,.2f} is complete. "
            "Your wallet has been credited and you can withdraw now with no charges."
        ),
        data={
            "amount": str(amount),
            "type": "ScheduledWithdrawalCompleted",
        },
        notif_type="CREDIT",
    )

    # 5️⃣ Email user
    user_subject = "Scheduled Withdrawal Completed"
    user_message = (
        f"Hi {user.first_name},<br><br>"
        f"Your scheduled withdrawal of ₦{amount:,.2f} has been completed successfully.<br>"
        "The funds have been credited to your MyFund wallet and you can now withdraw "
        "without any charges.<br><br>"
        "Thank you for trusting MyFund."
    )

    send_generic_email(
        user_subject,
        user_message,
        "MyFund <info@myfundmobile.com>",
        [user.email],
    )

    # 6️⃣ Email CEO
    admin_subject = "[AUTO] Scheduled Withdrawal Completed"
    admin_message = (
        f"Scheduled withdrawal completed automatically.<br><br>"
        f"User: {user.full_name} ({user.email})<br>"
        f"Amount: ₦{amount:,.2f}<br>"
        f"Source: {withdrawal.source_account}<br>"
        f"Scheduled Date: {withdrawal.scheduled_processing_date}<br>"
    )

    send_generic_email(
        admin_subject,
        admin_message,
        "MyFund <info@myfundmobile.com>",
        ["tolulopeahmed@gmail.com"],
    )


from datetime import date


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

    # If we've passed Oct 1, next payout is Jan 1 of next year
    return date(year + 1, 1, 1)
