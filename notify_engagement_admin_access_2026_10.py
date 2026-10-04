# notify_engagement_admin_access_2026_10.py
#
# One-off: tells the three active Engagement team members (all already
# is_staff, see Employee.department="Engagement") about their new Engagement
# section of the MyFund Admin dashboard - by email (cc'd to the founders, so
# replies stay visible) and push - then confirms to the founders via push.
#
# Run only AFTER the mobile update that adds them to adminAccess.js
# (isEngagementOnly) is live - before that, two of them can't see Admin at
# all. Safe to re-run: it only sends messages, changes no data.

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from authentication.models import CustomUser, Employee
from authentication.utils import send_transactional_email, send_push_notification

FOUNDER_EMAILS = [
    "tolulopeahmed@gmail.com",
    "janet.adegbenro@gmail.com",
]

EMAIL_MESSAGE_TEMPLATE = """
Hi {first_name},<br><br>
You now have access to the Engagement section of the MyFund Admin dashboard. From there you can:<br><br>
&bull; View live signup and user activity metrics<br>
&bull; Submit your weekly Engagement report (community activities, referrals, confirmed sign-ups, campaigns, results and blockers)<br>
&bull; Send emails to users and segments<br><br>
To access it, update the MyFund app if prompted, log in, then tap <strong>Admin</strong> from the sidebar menu, or the small metrics icon in the top header.<br><br>
This is scoped specifically to the Engagement view - not full admin access.<br><br>
If you run into any trouble getting in, just reply to this email.<br><br>
MyFund
"""

PUSH_TITLE = "Engagement Admin Access ✅"
PUSH_MESSAGE_TEMPLATE = (
    "Hi {first_name}, you can now submit Engagement reports and send emails "
    "in Admin - tap Admin on the sidebar or the metrics icon on the header."
)


def main():
    founders = list(CustomUser.objects.filter(email__in=FOUNDER_EMAILS))
    if len(founders) != len(FOUNDER_EMAILS):
        found = {u.email.lower() for u in founders}
        missing = [e for e in FOUNDER_EMAILS if e.lower() not in found]
        raise SystemExit(f"Founder account(s) not found, aborting: {missing}")

    members = Employee.objects.filter(department="Engagement", is_active=True)
    notified = []
    for member in members:
        user = CustomUser.objects.filter(email__iexact=member.email).first()
        if not user or not user.is_staff:
            print(f"SKIP - {member.email}: no account or not staff")
            continue

        first_name = user.first_name or member.name or "there"

        send_transactional_email(
            subject="You now have Engagement Admin Access on MyFund 🎉",
            message=EMAIL_MESSAGE_TEMPLATE.format(first_name=first_name),
            recipient_list=[user.email],
            cc=FOUNDER_EMAILS,
            from_email="MyFund <info@myfundmobile.com>",
        )
        print(f"Email sent to {user.email} (cc: {', '.join(FOUNDER_EMAILS)})")

        push_result = send_push_notification(
            user=user,
            title=PUSH_TITLE,
            message=PUSH_MESSAGE_TEMPLATE.format(first_name=first_name),
            data={"type": "ENGAGEMENT_ADMIN_ACCESS_GRANTED"},
            notif_type="SYSTEM",
        )
        print(f"Push to {user.email}: {push_result}")

        notified.append(f"{user.first_name} {user.last_name}".strip() or user.email)

    if not notified:
        print("No Engagement members were notified - skipping founder confirmation push.")
        return

    confirmation_message = (
        f"{', '.join(notified)} {'has' if len(notified) == 1 else 'have'} been "
        f"notified of Engagement admin access by email + push."
    )
    for founder in founders:
        result = send_push_notification(
            user=founder,
            title="Engagement Team Notified",
            message=confirmation_message,
            data={"type": "ENGAGEMENT_ADMIN_ACCESS_CONFIRMATION"},
            notif_type="SYSTEM",
        )
        print(f"Confirmation push to {founder.email}: {result}")


if __name__ == "__main__":
    main()
