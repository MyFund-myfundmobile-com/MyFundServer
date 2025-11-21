# tasks.py
from celery import shared_task
from django.utils import timezone
from .models import TargetSavings
import logging
from django.db import models
from .utils import send_generic_email, send_push_notification
from datetime import timedelta
from django.conf import settings

logger = logging.getLogger(__name__)


@shared_task
def refund_contributions_if_goal_not_reached():
    """
    Refund users whose target savings goals were not reached by the end date.
    """
    from django.utils import timezone

    now = timezone.now()
    overdue_targets = TargetSavings.objects.filter(
        is_active=False,
        is_cancelled=False,
        current_amount__lt=models.F("target_amount"),
        end_date__lt=now,
    ).select_related("user")

    refunded_count = 0

    for target in overdue_targets:
        try:
            user = target.user
            refund_amount = target.current_amount

            if refund_amount > 0:
                # Credit user wallet
                user.wallet += refund_amount
                user.save(update_fields=["wallet"])

                # Mark target as refunded
                target.is_cancelled = True
                target.save(update_fields=["is_cancelled"])

                # Log or create transaction record
                Transaction.objects.create(
                    user=user,
                    transaction_type="CREDIT",
                    amount=refund_amount,
                    source="TARGET_REFUND",
                    description=f"Refund for incomplete target '{target.name}'",
                )

                send_push_notification(
                    user,
                    title="Refund Processed 💸",
                    message=f"₦{refund_amount:,.2f} refunded for incomplete target '{target.name}'.",
                    data={"target_id": target.id, "type": "TARGET_REFUND"},
                )

                refunded_count += 1

        except Exception as e:
            logger.error(f"Error refunding target {target.id}: {e}")

    logger.info(f"✅ Processed refunds for {refunded_count} targets.")
    return f"{refunded_count} refunds processed."


@shared_task
def process_target_savings_deductions():
    """Celery task to process all due target savings deductions"""
    now = timezone.now()
    logger.info(f"🕒 Processing target savings at {now}")

    # Add debug logging to see what's happening
    logger.info(f"🔍 Checking for due targets with next_deduction <= {now}")

    due_targets = TargetSavings.objects.filter(
        is_active=True,
        is_cancelled=False,
        next_deduction__lte=now,
        current_amount__lt=models.F("target_amount"),
    ).select_related("user")

    logger.info(f"📊 Found {due_targets.count()} target savings due for processing")

    # Log details about each due target
    for target in due_targets:
        logger.info(
            f"   - Target: {target.name}, Next deduction: {target.next_deduction}, Current: {target.current_amount}/{target.target_amount}"
        )

    success_count = 0
    failure_count = 0

    for target in due_targets:
        user = target.user
        try:
            success = target.process_deduction()
            if success:
                success_count += 1
                logger.info(
                    f"✅ Successfully processed deduction for target {target.id}"
                )

                # Notifications are now handled inside the process_deduction method.
                # No need to duplicate them here.

            else:
                failure_count += 1
                logger.warning(f"⚠️ Failed to process deduction for target {target.id}")
                # Failure notifications are also handled inside process_deduction.

        except Exception as e:
            failure_count += 1
            logger.error(f"🔥 Error processing target {target.id}: {str(e)}")

    logger.info(
        f"Target savings processing completed: {success_count} successes, {failure_count} failures"
    )
    return {
        "total_processed": due_targets.count(),
        "success_count": success_count,
        "failure_count": failure_count,
    }


@shared_task
def check_completed_targets():
    """Check and mark completed targets"""
    completed_targets = TargetSavings.objects.filter(
        is_active=True,
        is_cancelled=False,
        current_amount__gte=models.F("target_amount"),
    ).select_related("user")

    for target in completed_targets:
        user = target.user
        target.is_active = False
        target.save()

        # Email user
        subject = f"Target Savings '{target.name}' Completed! 🎉"
        message = (
            f"Hi {user.first_name},<br><br>"
            f"Congratulations! You’ve successfully completed your Target Savings plan "
            f"'{target.name}' with ₦{target.current_amount:,.2f}.<br><br>"
            "You can now withdraw or reinvest these funds. 🥂"
        )
        send_generic_email(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        # Push notification
        send_push_notification(
            user,
            title="🎉 Target Savings Completed!",
            message=f"Congrats! '{target.name}' reached ₦{target.current_amount:,.2f}.",
            data={"target_id": target.id, "type": "TARGET_COMPLETED"},
        )

    return {"completed_count": completed_targets.count()}


@shared_task
def retry_failed_deductions():
    """Retry targets that failed deductions but are still active"""
    now = timezone.now()
    retry_targets = TargetSavings.objects.filter(
        is_active=True,
        is_cancelled=False,
        deduction_attempts__gt=0,
        deduction_attempts__lt=models.F("max_attempts"),
        next_retry__lte=now,
    ).select_related("user")

    logger.info(f"Found {retry_targets.count()} targets due for retry processing")

    for target in retry_targets:
        user = target.user
        success = target.process_deduction()
        if success:
            subject = f"Autosave Retry for {target.name} Target Successful ✅"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"We retried your Target Savings for '{target.name}' "
                f"and successfully autosaved ₦{target.monthly_payment:,.2f} for it.<br><br>"
                f"New balance: ₦{target.current_amount:,.2f}.\n\n "
                "Keep going! You're doing great. 🚀"
            )
            send_generic_email(
                subject, message, settings.DEFAULT_FROM_EMAIL, [user.email]
            )

            send_push_notification(
                user,
                title="Retry Successful ✅",
                message=f"Hi {user.first_name}, ₦{target.monthly_payment:,.2f} was successfully Autosaved for your '{target.name}' plan. Keep growing your funds to achieve your goals! 🚀",
                data={"target_id": target.id, "type": "RETRY_SUCCESS"},
            )

    return {"retry_count": retry_targets.count()}


from .models import CustomUser, Transaction
from .utils import calculate_daily_roi, send_push_notification
from django.db import transaction as db_transaction


# tasks.py - Replace the ROI tasks
@shared_task
def calculate_daily_roi_task():
    today = timezone.now().date()

    # Prevent duplicates for the day
    from .models import ROITransaction  # ← ADD THIS IMPORT

    if ROITransaction.objects.filter(accrued_date=today).exists():
        return "✅ ROI already calculated for today."

    users = CustomUser.objects.filter(is_active=True, is_banned=False)
    processed_count = 0

    for user in users.iterator():
        try:
            total_roi, savings_roi, investment_roi = calculate_daily_roi(user, today)
            if total_roi > 0:
                send_push_notification(
                    user,
                    title="💹 Your Funds Have Grown!",
                    message=(
                        f"Hi {user.first_name}, your funds have earned returns. "
                        f"Savings: ₦{savings_roi:,.2f}, Investment: ₦{investment_roi:,.2f}. "
                        "Keep growing your funds for more returns!"
                    ),
                    data={
                        "type": "DAILY_ROI",
                        "total_roi": float(total_roi),
                        "date": today.isoformat(),
                    },
                )
                processed_count += 1
        except Exception as e:
            logger.error(f"ROI error for user {user.id}: {e}")

    return f"✅ Daily ROI accrued for {processed_count} users."


from decimal import Decimal
from datetime import date


@shared_task
def process_quarterly_payouts_task():
    """Process quarterly ROI payouts"""
    from datetime import date  # ← ADD THIS IMPORT
    from .models import ROITransaction  # ← ADD THIS IMPORT

    today = timezone.now().date()

    # Calculate quarter start and end dates
    if today.month in [1, 2, 3]:
        quarter_start = date(today.year, 1, 1)
        quarter_end = date(today.year, 3, 31)
    elif today.month in [4, 5, 6]:
        quarter_start = date(today.year, 4, 1)
        quarter_end = date(today.year, 6, 30)
    elif today.month in [7, 8, 9]:
        quarter_start = date(today.year, 7, 1)
        quarter_end = date(today.year, 9, 30)
    else:
        quarter_start = date(today.year, 10, 1)
        quarter_end = date(today.year, 12, 31)

    users = CustomUser.objects.filter(is_active=True, is_banned=False)

    for user in users:
        try:
            # Get all unpaid ROI transactions for the quarter
            unpaid_roi = ROITransaction.objects.filter(
                user=user,
                accrued_date__range=[quarter_start, quarter_end],
                is_paid_out=False,
            )

            total_payout = sum(transaction.amount for transaction in unpaid_roi)

            if total_payout > 0:
                with db_transaction.atomic():
                    # Credit wallet
                    user.wallet += total_payout
                    user.save(update_fields=["wallet"])

                    # Mark ROI transactions as paid
                    unpaid_roi.update(is_paid_out=True, payout_date=today)

                    # Create transaction record
                    savings_roi_total = sum(
                        t.amount for t in unpaid_roi if t.roi_type == "SAVINGS"
                    )
                    investment_roi_total = sum(
                        t.amount for t in unpaid_roi if t.roi_type == "INVESTMENT"
                    )

                    today = date.today()
                    quarter = (today.month - 1) // 3 + 1

                    Transaction.objects.create(
                        user=user,
                        transaction_type="credit",
                        source="INVESTMENT",
                        status="confirmed",
                        amount=Decimal(total_payout),
                        service_charge=Decimal("0.00"),
                        total_amount=Decimal(total_payout),
                        description=f"Quarterly ROI Q{quarter} {today.year}",
                    )

                    # Send notification
                    send_push_notification(
                        user,
                        title="🎉 You Have Received Your Quarterly ROI!",
                        message=f"Congratulations! A total payout of ₦{total_payout:,.2f} has been credited to your wallet. (Savings: ₦{savings_roi_total:,.2f}, Investment: ₦{investment_roi_total:,.2f}). Keep growing your funds to earn more returns!",
                        data={
                            "type": "QUARTERLY_PAYOUT",
                            "amount": float(total_payout),
                            "period": f"Q{(today.month-1)//3 + 1} {today.year}",
                        },
                    )

        except Exception as e:
            logger.error(f"Error processing payout for user {user.id}: {str(e)}")

    return "✅ Quarterly ROI payouts processed"


# ✅ tasks.py
from celery import shared_task
from django.utils import timezone
from .models import CustomUser, TopSaverHistory
from .utils import send_push_notification, send_generic_email
import datetime
import logging

logger = logging.getLogger(__name__)

GOOGLE_FORM_TEMPLATE = (
    "https://docs.google.com/forms/d/e/1FAIpQLSfHbVd5EtzSyJskgdvCRfGfYrdGaTw3RwCvnkk7pjl6LvS59A/"
    "viewform?usp=pp_url&entry.1884265043={name}&entry.390969690={email}"
)


@shared_task
def reward_top_savers_of_month():
    now = timezone.now()
    prev_month = 12 if now.month == 1 else now.month - 1
    year = now.year - 1 if now.month == 1 else now.year
    prev_month_name = datetime.date(year, prev_month, 1).strftime("%B")

    top_savers = TopSaverHistory.objects.filter(month=prev_month, year=year).order_by(
        "rank"
    )[:10]

    if not top_savers.exists():
        msg = f"[TOP_SAVER_TASK] No top savers found for {prev_month_name} {year}"
        logger.info(msg)
        return msg

    for entry in top_savers:
        user = entry.user
        rank = entry.rank
        pre_filled_link = GOOGLE_FORM_TEMPLATE.format(
            name=f"{user.first_name} {user.last_name}", email=user.email
        )

        try:
            if rank <= 3:
                has_been_top3_before = (
                    TopSaverHistory.objects.filter(user=user, rank__lte=3)
                    .exclude(id=entry.id)
                    .exists()
                )

                send_push_notification(
                    user,
                    title=f"🎉 You're the #{rank} Top Saver for {prev_month_name}!",
                    message=(
                        f"🎉 Congrats {user.first_name}! You're one of the Top Savers for the month of {prev_month_name} and we'd like to hear from you. "
                        "Kindly check your email for details. Well done!"
                    ),
                    data={"type": "TOP_SAVER_CONGRATS", "rank": rank},
                )

                if not has_been_top3_before:
                    email_message = f"""
                    Hi {user.first_name},<br><br>
                    🎉 Congratulations! You are the <b>#{rank}</b> Top Savers for <b>{prev_month_name}</b>!<br><br>
                    You’ve officially qualified for a <b>MyFund Branded T-Shirt</b> 👕 as a first-time Top Saver!<br><br>
                    Please fill out this form so we can send your T-Shirt and get your quick feedback:<br>
                    <a href="{pre_filled_link}">MyFund Top Saver Form</a><br><br>
                    — The MyFund Team
                    """
                else:
                    email_message = f"""
                    Hi {user.first_name},<br><br>
                    🎉 Congratulations! You are the <b>#{rank}</b> Top Savers for <b>{prev_month_name}</b>!<br><br>
                    Thank you for your consistency — we’d love your quick feedback to help us improve. Kindly fill this form:<br>
                    <a href="{pre_filled_link}"><b>MyFund Top Saver Feedback Form</b></a><br><br>
                    — The MyFund Team
                    """

                send_generic_email(
                    subject=f"🏆 Congrats! You are the #{rank} Top Saver for {prev_month_name}!",
                    message=email_message,
                    from_email="MyFund <info@myfundmobile.com>",
                    recipient_list=[user.email],
                )
                logger.info(
                    f"[TOP_SAVER_TASK] Email sent to {user.email} for rank {rank}"
                )

            else:
                send_push_notification(
                    user,
                    title=f"You're the #{rank} Top Saver for {prev_month_name}! 🚀",
                    message=(
                        f"Congrats {user.first_name}! You're the #{rank} Top Saver for {prev_month_name}! Keep growing your funds to earn more rewards as one of the top savers for this month. "
                        f"Well done!"
                    ),
                    data={"type": "TOP_SAVER_ENCOURAGE", "rank": rank},
                )

                email_message = f"""
                Hi {user.first_name},<br><br>
                You are the <b>#{rank}</b> Top Saver for <b>{prev_month_name}</b>!<br>
                Keep growing your funds to earn more rewards as one of the top savers for this month.<br><br>
                Well done! <br><br>
                — The MyFund Team
                """

                send_generic_email(
                    subject=f"You're the #{rank} Top Saver for {prev_month_name}! 🚀",
                    message=email_message,
                    from_email="MyFund <info@myfundmobile.com>",
                    recipient_list=[user.email],
                )
                logger.info(
                    f"[TOP_SAVER_TASK] Encouragement email sent to {user.email} (rank {rank})"
                )

        except Exception as e:
            logger.error(f"[TOP_SAVER_TASK][ERROR] Failed for {user.email}: {e}")

    return f"Top Saver notifications for {prev_month_name} {year} sent successfully."


@shared_task
def send_birthday_greetings():
    """Send birthday emails and push notifications to users celebrating today"""
    from django.utils import timezone
    from datetime import date
    from .models import CustomUser
    from .utils import send_generic_email, send_push_notification

    today = date.today()
    users = CustomUser.objects.filter(
        is_active=True,
        is_banned=False,
        date_of_birth__month=today.month,
        date_of_birth__day=today.day,
    )

    if not users.exists():
        return "No birthdays today 🎈"

    for user in users:
        try:
            # 🎉 Email
            subject = "🎂 Happy Birthday from MyFund!"
            message = f"""
            Hi {user.first_name},<br><br>
            🎉 The entire MyFund team wishes you a wonderful birthday! <br>
            May your new year bring you growth, success, and more financial wins.<br><br>
            🥳 Keep saving and keep shining!<br><br>
            — The MyFund Team
            """
            send_generic_email(
                subject, message, "MyFund <info@myfundmobile.com>", [user.email]
            )

            # 🎊 Push notification
            send_push_notification(
                user,
                title=f"🎂 Happy Birthday, {user.first_name}!",
                message=f"Hi {user.first_name}, the MyFund team wishes you a Happy and memorable Birthday today! Long life and prosperity! 🎉",
                data={"type": "BIRTHDAY"},
            )

        except Exception as e:
            logger.error(f"Failed to send birthday message to {user.email}: {str(e)}")

    return f"🎂 Birthday messages sent to {users.count()} users."

from django.db.models import Sum, F, DecimalField, Q, Window
from django.db.models.functions import Coalesce, Rank
from django.db import transaction
from django.utils import timezone

@shared_task(bind=True, max_retries=3)
def update_top_savers():
    now = timezone.now()
    current_month = now.month
    current_year = now.year

    # Aggregate total savings per user
    user_amounts = (
        Transaction.objects
        .filter(
            date__month=current_month,
            date__year=current_year,
        )
        .filter(
            Q(status="confirmed", transaction_type="credit") |
            Q(description__in=["AutoSave (Confirmed)", "AutoInvest (Confirmed)"])
        )
        .values("user_id")
        .annotate(
            total=Coalesce(
                Sum("amount"),
                0,
                output_field=DecimalField()
            )
        )
        .filter(total__gt=0)
        .annotate(
            rank=Window(
                expression=Rank(),
                order_by=F('total').desc()
            )
        )
        .order_by("rank")
    )

    ranked = list(user_amounts)
    if not ranked:
        return

    top_amount = ranked[0]['total'] or 1
    user_ids = [r["user_id"] for r in ranked]
    users = {u.id: u for u in CustomUser.objects.filter(id__in=user_ids)}

    # Prepare bulk upsert
    with transaction.atomic():
        for r in ranked:
            user = users.get(r["user_id"])
            if not user:
                continue
            TopSaverHistory.objects.update_or_create(
                month=current_month,
                year=current_year,
                user=user,
                defaults={
                    "rank": r["rank"],
                    "total_savings": r["total"]
                }
            )
