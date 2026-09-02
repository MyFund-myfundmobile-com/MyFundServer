# grant_cx_admin_access_2026_09.py
#
# One-off: grants is_staff (real backend admin access - the CX-restricted
# view they'll actually see is already gated client-side by adminAccess.js's
# isCxOnly, which hides Transactions/Finance and only shows Signups/User
# Activity + the CX weekly report form) to the three CX team members, then
# notifies each of them by email (cc'd to the founders, so replies stay
# visible) and push, and confirms to the founders via push that it's done.

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from authentication.models import CustomUser
from authentication.utils import send_transactional_email, send_push_notification

CX_EMAILS = [
    "arowoloibukun670@gmail.com",
    "uyannajeremiah@gmail.com",
    "eoluwatoyin128@gmail.com",
]
FOUNDER_EMAILS = [
    "tolulopeahmed@gmail.com",
    "janet.adegbenro@gmail.com",
]

EMAIL_MESSAGE_TEMPLATE = """
Hi {first_name},<br><br>
You've been given access to the CX section of the MyFund Admin dashboard. From there you can:<br><br>
&bull; View live signup metrics<br>
&bull; Submit your weekly CX report<br><br>
To access it, open the MyFund app, log in, then tap <strong>Admin</strong> from the sidebar menu, or the small metrics icon in the top header.<br><br>
This is scoped specifically to the CX view - not full admin access.<br><br>
If you run into any trouble getting in, just reply to this email.<br><br>
MyFund
"""

PUSH_TITLE = "CX Admin Access Granted ✅"
PUSH_MESSAGE_TEMPLATE = (
    "Hi {first_name}, you can now access CX admin - tap Admin on the sidebar "
    "or the metrics icon on the header to check it out."
)


def main():
    founders = list(CustomUser.objects.filter(email__in=FOUNDER_EMAILS))
    if len(founders) != len(FOUNDER_EMAILS):
        found = {u.email.lower() for u in founders}
        missing = [e for e in FOUNDER_EMAILS if e.lower() not in found]
        raise SystemExit(f"Founder account(s) not found, aborting: {missing}")

    notified = []
    for email in CX_EMAILS:
        user = CustomUser.objects.filter(email__iexact=email).first()
        if not user:
            print(f"SKIP - no account found for {email}")
            continue

        if not user.is_staff:
            user.is_staff = True
            user.save(update_fields=["is_staff"])
            print(f"Granted is_staff to {email} (id={user.id})")
        else:
            print(f"{email} already had is_staff=True")

        first_name = user.first_name or "there"

        send_transactional_email(
            subject="You now have CX Admin Access on MyFund 🎉",
            message=EMAIL_MESSAGE_TEMPLATE.format(first_name=first_name),
            recipient_list=[user.email],
            cc=FOUNDER_EMAILS,
            from_email="MyFund <info@myfundmobile.com>",
        )
        print(f"Email sent to {email} (cc: {', '.join(FOUNDER_EMAILS)})")

        push_result = send_push_notification(
            user=user,
            title=PUSH_TITLE,
            message=PUSH_MESSAGE_TEMPLATE.format(first_name=first_name),
            data={"type": "CX_ADMIN_ACCESS_GRANTED"},
            notif_type="SYSTEM",
        )
        print(f"Push to {email}: {push_result}")

        notified.append(f"{user.first_name} {user.last_name}".strip() or email)

    if not notified:
        print("No CX members were notified - skipping founder confirmation push.")
        return

    confirmation_message = (
        f"{', '.join(notified)} {'has' if len(notified) == 1 else 'have'} been "
        f"granted CX admin access and notified by email + push."
    )
    for founder in founders:
        result = send_push_notification(
            user=founder,
            title="CX Team Notified",
            message=confirmation_message,
            data={"type": "CX_ADMIN_ACCESS_CONFIRMATION"},
            notif_type="SYSTEM",
        )
        print(f"Confirmation push to {founder.email}: {result}")


if __name__ == "__main__":
    main()
