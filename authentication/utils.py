import requests
import logging
import socket

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"


def send_push_notification(user, title, message, data={}, notif_type="SYSTEM"):
    if not user.expo_push_token:
        return

    prefs = user.notification_preferences or {}
    if not prefs.get(notif_type.lower(), True):
        return

    from .models import PushNotifications

    PushNotifications.objects.create(
        user=user,
        title=title,
        message=message,
        notification_type=notif_type,
        data=data,
    )

    # 🔒 Avoid Expo push during local development
    if socket.gethostbyname(socket.gethostname()).startswith("172."):
        print("🚫 Skipping Expo push in local environment.")
        return

    payload = {
        "to": user.expo_push_token,
        "sound": "default",
        "title": title,
        "body": message,
        "data": data,
    }

    try:
        response = requests.post(EXPO_PUSH_URL, json=payload, timeout=5)
        if response.status_code != 200:
            logging.warning(
                f"Expo push failed: {response.status_code} - {response.text}"
            )
    except requests.exceptions.RequestException as e:
        logging.error(f"Expo push request failed: {str(e)}")
