from authentication.models import CustomUser
from authentication.utils import send_push_notification

ADMIN_EMAILS = [
    "tolulopeahmed@gmail.com",
    "ceo@mg.myfundmobile.com",
    "janet.adegbenro@gmail.com",
]


def send_metrics_push(snapshot):
    admins = CustomUser.objects.filter(email__in=ADMIN_EMAILS)

    title = f"📊 {snapshot.period_type.capitalize()} MyFund Metrics"

    message = (
        f"Users: {snapshot.total_users}\n"
        f"New Users: {snapshot.new_users}\n"
        f"Retention: {snapshot.retention_rate:.2f}%\n"
        f"LTV: ₦{snapshot.ltv:,.2f}\n"
        f"Float Revenue: ₦{snapshot.estimated_float_revenue:,.2f}"
    )

    data = {
        "type": "metrics_report",
        "period": snapshot.period_type,
        "snapshot_id": snapshot.id,
    }

    for admin in admins:

        if admin.expo_push_tokens:

            send_push_notification(
                user=admin,
                title=title,
                message=message,
                data=data,
                notif_type="ADMIN",
            )
