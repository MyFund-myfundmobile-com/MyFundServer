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
from authentication.utils import send_generic_email, send_push_notification


def create_draft_entries(employees_qs, month_label, executed_by=""):
    run = PayrollRun.objects.create(month_label=month_label, executed_by=executed_by)
    for emp in employees_qs:
        PayrollEntry.objects.create(
            run=run,
            employee=emp,
            email=emp.email,
            name=emp.name,
            amount=emp.monthly_amount,
            description=f"{month_label} Allowance",
            status="pending",
        )
    return run


def send_pending_entries(
    entries_qs, test=False, test_email="valueplusrecords@gmail.com"
):
    results = []

    for entry in entries_qs.filter(status="pending"):
        email = entry.email.strip().lower()
        amount = Decimal(entry.amount)
        description = entry.description or "MyFund Allowance"

        try:
            user = CustomUser.objects.get(email__iexact=email)
        except CustomUser.DoesNotExist:
            entry.status = "user_not_found"
            entry.save(update_fields=["status"])
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

        balance_before = Decimal(str(user.wallet or 0))

        if not test:
            with db_transaction.atomic():
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
        else:
            balance_after = balance_before

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

        entry.balance_before = balance_before
        entry.balance_after = balance_after
        entry.status = "credited" if not test else "test_run"
        entry.save(update_fields=["balance_before", "balance_after", "status"])

        results.append({"email": email, "status": entry.status})

    return results
