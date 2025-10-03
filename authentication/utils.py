import requests
from .models import PushNotifications
from .models import PushNotifications
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import threading
import logging
import smtplib

# Set up logging (make sure logging is configured in your settings or app)
logger = logging.getLogger(__name__)
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import threading
import logging

# Set up logging (make sure logging is configured in your settings or app)
logger = logging.getLogger(__name__)

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"


def send_push_notification(user, title, message, data=None, notif_type="SYSTEM"):
    data = data or {}
    tokens = user.expo_push_tokens or []

    tokens = user.expo_push_tokens or []

    notification = PushNotifications.objects.create(
        user=user,
        title=title,
        message=message,
        notification_type=notif_type,
        data=data,
    )
    print(f"📝 Created notification ID {notification.id} for {user.email}")

    if not tokens:
        print(f"❌ No push tokens for {user.email}")
        return None

    success_count = 0
    for token_entry in tokens:
        token = token_entry.get("token")
        if not token:
            continue

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
            "data": {**data, "notification_id": str(notification.id)},
            "channelId": "default",
            "priority": "high",
        }

        headers = {
            "Accept": "application/json",
            "Accept-encoding": "gzip, deflate",
            "Content-Type": "application/json",
        }

        headers = {
            "Accept": "application/json",
            "Accept-encoding": "gzip, deflate",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                EXPO_PUSH_URL, json=payload, headers=headers, timeout=10
            )
            res_data = response.json()
            print(f"📤 Sent to {token}: {res_data}")

            if res_data.get("data", {}).get("status") != "ok":
                print(f"❌ Failed for token: {token}")
            if res_data.get("data", {}).get("status") != "ok":
                print(f"❌ Failed for token: {token}")
            else:
                success_count += 1

        except Exception as e:
            print(f"🔥 Error sending to {token}: {str(e)}")

    return {"sent": success_count, "total": len(tokens)}
    return {"sent": success_count, "total": len(tokens)}


def send_generic_email(
    subject,
    message,
    from_email=None,
    recipient_list=None,
):
    if recipient_list is None:
        recipient_list = []
    elif isinstance(recipient_list, str):
        recipient_list = [recipient_list]

    if from_email is None:
        from django.conf import settings
        from_email = settings.DEFAULT_FROM_EMAIL

    def send_email_task():
        try:
            context = {"subject": subject, "message": message}
            html_message = render_to_string("email/email.html", context=context)
            plain_message = strip_tags(html_message)

            send_mail(
                subject,
                plain_message,
                from_email,
                recipient_list,
                html_message=html_message,
                fail_silently=False,
            )

            logger.info(f"📧 Sent email to {recipient_list} with subject: {subject}")

        except smtplib.SMTPRecipientsRefused as e:
            # Log detailed info about rejected recipients
            logger.error(f"❌ Email rejected by recipient's server: {e.recipients}")
        except Exception as e:
            # Log any other error that may occur
            logger.exception("❌ Failed to send email due to an unexpected error.")

    threading.Thread(target=send_email_task, daemon=True).start()


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