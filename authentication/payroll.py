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
