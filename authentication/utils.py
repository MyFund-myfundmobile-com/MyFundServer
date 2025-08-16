# app/utils.py (updated)
import requests
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import PushNotifications, DevicePushToken

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"


def send_push_notification(user, title, message, data=None, notif_type="SYSTEM"):
    data = data or {}
    # create DB notification record
    notification = PushNotifications.objects.create(
        user=user,
        title=title,
        message=message,
        notification_type=notif_type,
        data=data,
    )
    print(f"📝 Created notification ID {notification.id} for {user.email}")

    tokens_qs = DevicePushToken.objects.filter(user=user)
    tokens = list(tokens_qs)

    if not tokens:
        print(f"❌ No push tokens for {user.email}")
        return None

    success_count = 0
    total = len(tokens)

    # ensure the client can filter notifications for the current user
    payload_data = {
        **data,
        "notification_id": str(notification.id),
        "to_user_id": str(user.id),
    }

    headers = {
        "Accept": "application/json",
        "Accept-encoding": "gzip, deflate",
        "Content-Type": "application/json",
    }

    for token_obj in tokens:
        token = token_obj.token
        payload = {
            "to": token,
            "sound": "default",
            "title": title,
            "body": message,
            "data": payload_data,
            "channelId": "default",
            "priority": "high",
        }

        try:
            response = requests.post(
                EXPO_PUSH_URL, json=payload, headers=headers, timeout=10
            )
            res_data = response.json()
            print(f"📤 Sent to {token}: {res_data}")

            ok = False
            if isinstance(res_data, dict):
                if res_data.get("data", {}).get("status") == "ok":
                    ok = True
                if res_data.get("errors"):
                    ok = False
                if (
                    res_data.get("data", {}).get("details", {}).get("expoPushToken")
                    == "DeviceNotRegistered"
                ):
                    ok = False
            else:
                ok = response.status_code >= 200 and response.status_code < 300

            if ok:
                success_count += 1
                token_obj.last_seen = timezone.now()
                token_obj.save(update_fields=["last_seen"])
            else:
                errors = res_data.get("errors") if isinstance(res_data, dict) else None
                if errors:
                    should_delete = any(
                        "DeviceNotRegistered" in str(err)
                        or "not registered" in str(err).lower()
                        for err in errors
                    )
                    if should_delete:
                        print(
                            f"🧹 Removing invalid token for user {user.email}: {token}"
                        )
                        try:
                            token_obj.delete()
                        except Exception:
                            pass

        except Exception as e:
            print(f"🔥 Error sending to {token}: {str(e)}")

    return {"sent": success_count, "total": total}


def send_generic_email(subject, message, recipient_list, from_email=None):
    """
    Simple wrapper around Django's send_mail for generic notifications.
    """
    if from_email is None:
        from_email = settings.DEFAULT_FROM_EMAIL

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
