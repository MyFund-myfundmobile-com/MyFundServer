from decimal import Decimal
from django.db import transaction as db_transaction
from django.utils import timezone

from authentication.models import (
    CustomUser,
    Transaction,
    Employee,
    PayrollRun,
    PayrollEntry,
)
from authentication.utils import send_generic_email, send_push_notification, send_transactional_email


def create_draft_entries(employees_qs, month_label, executed_by=""):
    run = PayrollRun.objects.create(month_label=month_label, executed_by=executed_by)
    description = f"{month_label} Allowance"
    for emp in employees_qs:
        # A repeat click on "PAY Selected Employees" used to create a whole
        # new run (and pay everyone again) - skip anyone who already has a
        # pending or paid entry for this month.
        if PayrollEntry.objects.filter(
            employee=emp,
            description=description,
            status__in=["pending", "credited"],
        ).exists():
            continue
        PayrollEntry.objects.create(
            run=run,
            employee=emp,
            email=emp.email,
            name=emp.name,
            amount=emp.monthly_amount,
            description=description,
            status="pending",
        )
    return run


def send_pending_entries(
    entries_qs, test=False, test_email="valueplusrecords@gmail.com"
):
    results = []

    for entry_id in list(entries_qs.filter(status="pending").values_list("id", flat=True)):
        if not test:
            # Claim the entry and credit the wallet in one locked transaction,
            # marking it "credited" before any email/push goes out. Previously
            # the status only flipped after the (slow) email + push, so a
            # second click on "Send LIVE"/"PAY" in admin while the first was
            # still running saw the entry as pending and paid it again - on
            # the Oct 1 2026 run that credited 5 people 2-3x.
            with db_transaction.atomic():
                entry = PayrollEntry.objects.select_for_update().get(id=entry_id)
                if entry.status != "pending":
                    continue

                email = entry.email.strip().lower()
                amount = Decimal(entry.amount)
                description = entry.description or "MyFund Allowance"

                user = (
                    CustomUser.objects.select_for_update()
                    .filter(email__iexact=email)
                    .first()
                )
                if user is None:
                    entry.status = "user_not_found"
                    entry.save(update_fields=["status"])
                    results.append({"email": email, "status": "user_not_found"})
                    continue

                balance_before = Decimal(str(user.wallet or 0))
                balance_after = balance_before + amount
                user.wallet = balance_after
                user.save(update_fields=["wallet"])

                Transaction.objects.create(
                    user=user,
                    transaction_type="credit",
                    status="confirmed",
                    source="WALLET",
                    credited_to="WALLET",
                    amount=amount,
                    total_amount=amount,
                    service_charge=Decimal("0.00"),
                    balance_before=balance_before,
                    balance_after=balance_after,
                    description=description,
                    date=timezone.now(),
                )

                entry.balance_before = balance_before
                entry.balance_after = balance_after
                entry.status = "credited"
                entry.save(update_fields=["balance_before", "balance_after", "status"])
        else:
            entry = PayrollEntry.objects.get(id=entry_id)
            email = entry.email.strip().lower()
            amount = Decimal(entry.amount)
            description = entry.description or "MyFund Allowance"
            user = CustomUser.objects.filter(email__iexact=email).first()
            if user is None:
                results.append({"email": email, "status": "user_not_found"})
                continue

        first_name = user.first_name or entry.name or "there"

        subject = f"🎉 ₦{amount:,.2f} Credited To Your Wallet"
        message = f"""
        <p>Hi {first_name},</p>
        <p>Your MyFund wallet has been credited with <strong>₦{amount:,.2f}</strong> for <strong>{description}</strong>.</p>
        <p>Thank you for your work and consistency.</p>
        <p>— MyFund</p>
        """

        send_generic_email(
            subject=subject,
            message=message,
            recipient_list=[test_email if test else user.email],
        )

        if not test:
            try:
                send_push_notification(
                    user=user,
                    title=subject,
                    message=f"Hi {first_name}, ₦{amount:,.2f} credited to your wallet for {description}. Thank you for your work and consistency.",
                    data={"type": "wallet_credit", "amount": str(amount)},
                )
            except Exception:
                pass

        if test:
            # Unchanged from before: a test send marks the entry so it
            # can't then be paid live by accident.
            entry.status = "test_run"
            entry.save(update_fields=["status"])

        results.append({"email": email, "status": entry.status})

    return results


def notify_employee_change(employee, old_status=None, old_department=None, old_amount=None):
    """
    Push + email an employee after they're added, (de)activated, or their
    department/allowance changes. Shared by EmployeeAdmin (Django admin) and
    the mobile admin payroll screen, so both send the same messages.
    Returns None when nothing relevant changed, False when no MyFund account
    matches the email, True once sent.
    """

    user = CustomUser.objects.filter(email__iexact=employee.email).first()
    if user is None:
        return False

    # NOTE: this used to also sync user.is_staff = employee.is_active,
    # silently granting real Django admin/API access to anyone
    # marked as an active payroll employee. That's what caused
    # ordinary staff to start receiving admin-only push
    # notifications (other users' transaction alerts). Payroll
    # status must never grant admin/API access - is_staff is set
    # manually per-account when someone is actually made an admin.

    status_changed = old_status is None or old_status != employee.is_active

    department_changed = (
        old_department is not None and old_department != employee.department
    )

    amount_changed = old_amount is not None and old_amount != employee.monthly_amount

    # No employee details changed
    if not (status_changed or department_changed or amount_changed):
        return None

    # ==============================
    # EMPLOYEE ACTIVATED / ADDED
    # ==============================

    if status_changed and employee.is_active:

        title = "🎉 Welcome to the MyFund Team!"

        message = (
            "Hi {first_name}, "
            "welcome to the MyFund team! "
            "You have joined the {department} department "
            "with a monthly allowance of ₦{monthly_amount}. "
            "We are excited to have you onboard. 🚀"
        )

        email_subject = "🎉 Welcome to MyFund, {first_name}!"

        email_message = """
    <p>
    Hi <strong>{first_name}</strong>,
    </p>

    <p>
    Congratulations and welcome to the <strong>MyFund team! 🎉</strong>
    </p>

    <p>
    You have officially joined the 
    <strong>{department} department</strong>.
    </p>

    <p>
    Your employee access has been activated.
    </p>

    <p>
    Your monthly team allowance is:
    </p>

    <p>
    <strong>₦{monthly_amount}</strong>
    </p>

    <p>
    You are now part of a team building solutions that make property ownership
    and wealth creation more accessible across Africa.
    </p>

    <p>
    We are excited about the skills, ideas, and energy you will bring to the
    MyFund journey.
    </p>

    <p>
    Welcome aboard! 🚀
    </p>

    <p>
    Warm regards,<br>
    <strong>The MyFund Team</strong>
    </p>
    """

    # ==============================
    # EMPLOYEE DEACTIVATED
    # ==============================

    elif status_changed and not employee.is_active:

        title = "Update on your MyFund team role"

        message = (
            "Hi {first_name}, your role on the MyFund {department} team has ended "
            "and you've been removed from team payroll. Thank you for your contributions. "
            "If you think this is an error, please email company@myfundmobile.com."
        )

        email_subject = "Update on your role with the MyFund {department} team"

        email_message = """
    <p>
    Hi <strong>{first_name}</strong>,
    </p>

    <p>
    Thank you for your time and contributions to the MyFund {department} team.
    This is to let you know that your role on the team has now ended, and you
    have been removed from the MyFund team payroll.
    </p>

    <p>
    Your personal MyFund account is not affected - you can keep saving and
    using the app as usual.
    </p>

    <p>
    <strong>If you believe this is an error</strong>, or you would like to
    discuss it, please email
    <a href="mailto:company@myfundmobile.com">company@myfundmobile.com</a>.
    </p>

    <p>
    We appreciate the impact you have made and wish you all the best.
    </p>

    <p>
    Warm regards,<br>
    <strong>The MyFund Team</strong>
    </p>
    """

    # ==============================
    # EMPLOYEE PROFILE UPDATED
    # ==============================

    else:

        title = "MyFund Employee Profile Updated"

        message = (
            "Hi {first_name}, "
            "your MyFund employee profile has been updated. "
            "Department: {department}. "
            "Monthly allowance: ₦{monthly_amount}."
        )

        email_subject = "MyFund Employee Details Updated"

        email_message = """
    <p>
    Hi <strong>{first_name}</strong>,
    </p>

    <p>
    Your MyFund employee details have been updated successfully.
    </p>

    <p>
    Here are your updated details:
    </p>

    <p>
    <strong>Department:</strong> {department}
    </p>

    <p>
    <strong>Monthly Allowance:</strong> ₦{monthly_amount}
    </p>

    <p>
    Your employee access remains active, and we appreciate your continued
    contribution to the MyFund journey.
    </p>

    <p>
    If you have any questions about this update, please contact the MyFund team.
    </p>

    <p>
    Warm regards,<br>
    <strong>The MyFund Team</strong>
    </p>
    """

    # ==============================
    # SEND PUSH NOTIFICATION
    # ==============================

    send_push_notification(
        user=user,
        title=title,
        message=message,
        notif_type="STAFF_STATUS",
        extra_context={
            "department": employee.department,
            "monthly_amount": f"{employee.monthly_amount:,.2f}",
        },
    )

    # ==============================
    # SEND EMAIL
    # ==============================

    send_transactional_email(
        subject=email_subject,
        message=email_message,
        recipient_list=[user.email],
        extra_context={
            "department": employee.department,
            "monthly_amount": f"{employee.monthly_amount:,.2f}",
        },
    )

    return True
