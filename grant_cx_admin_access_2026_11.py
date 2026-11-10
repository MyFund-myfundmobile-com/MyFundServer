# grant_cx_admin_access_2026_11.py
#
# One-off: gives Onyinyechi Otum (CX intern, also a Cohort 4 ambassador) the
# CX admin view. Two changes, both needed:
#   - is_staff=True: the real backend boundary on /api/admin/* calls.
#   - an active Employee row in "CX": get-user-profile returns it as
#     staff_team, which the app's adminAccess.js uses to show the Admin entry
#     with the trimmed CX view (no Transactions/Finance) - no app release.
# monthly_amount is 0 (intern; payroll only pays rows someone selects, and the
# amount can be edited in Admin > Payroll). Then notifies her by email (cc'd
# to the founders) and push, and confirms to the founders by push.
# Safe to re-run: existing rows/flags are left as they are, messages resend.

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from authentication.models import CustomUser, Employee
from authentication.utils import send_transactional_email, send_push_notification

EMAIL = "onyinyechiotum@gmail.com"
FOUNDER_EMAILS = ["tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com"]

EMAIL_MESSAGE = """
Hi {first_name},<br><br>
Welcome to the MyFund CX team! 🎉 You've been given access to the CX section of the MyFund Admin dashboard. From there you can:<br><br>
&bull; View live signup and user activity metrics<br>
&bull; Submit your weekly CX report<br><br>
To open it, log in to the MyFund app, then tap <strong>Admin</strong> in the sidebar menu, or the small metrics icon in the top header. If you don't see it yet, log out and back in once.<br><br>
This is scoped to the CX view - not full admin access. Your ambassador dashboard stays exactly as it is.<br><br>
If you run into any trouble getting in, just reply to this email.<br><br>
MyFund
"""

PUSH_TITLE = "CX Admin Access Granted ✅"
PUSH_MESSAGE = (
    "Hi {first_name}, welcome to the CX team! Tap Admin on the sidebar or the "
    "metrics icon on the header to open your CX dashboard."
)


def main():
    founders = list(CustomUser.objects.filter(email__in=FOUNDER_EMAILS))
    if len(founders) != len(FOUNDER_EMAILS):
        raise SystemExit("Founder account(s) not found, aborting.")

    user = CustomUser.objects.filter(email__iexact=EMAIL).first()
    if not user:
        raise SystemExit(f"No account found for {EMAIL}, nothing done.")
    full_name = f"{user.first_name} {user.last_name}".strip() or EMAIL
    first_name = user.first_name or "there"

    if not user.is_staff:
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        print(f"Granted is_staff to {EMAIL} (id={user.id})")
    else:
        print(f"{EMAIL} already had is_staff=True")

    employee = Employee.objects.filter(email__iexact=EMAIL).first()
    if employee is None:
        employee = Employee.objects.create(
            name=full_name, email=user.email, monthly_amount=0,
            department="CX", is_active=True,
        )
        print(f"Created Employee row: {employee} in CX")
    elif employee.department != "CX" or not employee.is_active:
        raise SystemExit(
            f"Employee row already exists as {employee.department} "
            f"(active={employee.is_active}) - not changing it; check with the founders."
        )
    else:
        print(f"Employee row already in CX: {employee}")

    send_transactional_email(
        subject="You now have CX Admin Access on MyFund 🎉",
        message=EMAIL_MESSAGE.format(first_name=first_name),
        recipient_list=[user.email],
        cc=FOUNDER_EMAILS,
        from_email="MyFund <info@myfundmobile.com>",
    )
    print(f"Email sent to {EMAIL} (cc: {', '.join(FOUNDER_EMAILS)})")

    result = send_push_notification(
        user=user,
        title=PUSH_TITLE,
        message=PUSH_MESSAGE.format(first_name=first_name),
        data={"type": "CX_ADMIN_ACCESS_GRANTED"},
        notif_type="SYSTEM",
    )
    print(f"Push to {EMAIL}: {result}")

    for founder in founders:
        r = send_push_notification(
            user=founder,
            title="CX Team Notified",
            message=f"{full_name} (CX intern) has been granted CX admin access and notified by email + push.",
            data={"type": "CX_ADMIN_ACCESS_CONFIRMATION"},
            notif_type="SYSTEM",
        )
        print(f"Confirmation push to {founder.email}: {r}")


if __name__ == "__main__":
    main()
