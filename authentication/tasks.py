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
    Optimized: Uses bulk_update and bulk_create for performance.
    """
    from django.utils import timezone
    from decimal import Decimal

    now = timezone.now()
    overdue_targets = TargetSavings.objects.filter(
        is_active=False,
        is_cancelled=False,
        current_amount__lt=models.F("target_amount"),
        end_date__lt=now,
    ).select_related("user")

    if not overdue_targets.exists():
        return "No overdue targets to refund."

    # Collect data for bulk operations
    users_to_update = []
    targets_to_update = []
    transactions_to_create = []
    notifications_to_send = []
    refunded_count = 0

    for target in overdue_targets:
        try:
            if target.current_amount <= 0:
                continue

            # Collect user update
            user = target.user
            user.wallet = models.F("wallet") + Decimal(target.current_amount)
            users_to_update.append(user)

            # Collect target update
            target.is_cancelled = True
            targets_to_update.append(target)

            # Collect transaction to create
            transactions_to_create.append(
                Transaction(
                    user=user,
                    transaction_type="CREDIT",
                    amount=target.current_amount,
                    source="TARGET_REFUND",
                    description=f"Refund for incomplete target '{target.name}'",
                )
            )

            # Collect notification data
            notifications_to_send.append(
                {
                    "user": user,
                    "title": "Refund Processed 💸",
                    "message": f"₦{target.current_amount:,.2f} refunded for incomplete target '{target.name}'.",
                    "data": {"target_id": target.id, "type": "TARGET_REFUND"},
                }
            )

            refunded_count += 1

        except Exception as e:
            logger.error(f"Error processing target {target.id}: {e}")

    # Bulk operations
    if users_to_update:
        CustomUser.objects.bulk_update(users_to_update, ["wallet"], batch_size=500)
        logger.info(f"✅ Updated wallets for {len(users_to_update)} users")

    if targets_to_update:
        TargetSavings.objects.bulk_update(
            targets_to_update, ["is_cancelled"], batch_size=500
        )
        logger.info(f"✅ Marked {len(targets_to_update)} targets as cancelled")

    if transactions_to_create:
        Transaction.objects.bulk_create(transactions_to_create, batch_size=500)
        logger.info(f"✅ Created {len(transactions_to_create)} transaction records")

    # Send notifications asynchronously
    for notification in notifications_to_send:
        try:
            send_push_notification(
                notification["user"],
                title=notification["title"],
                message=notification["message"],
                data=notification["data"],
            )
        except Exception as e:
            logger.error(
                f"Error sending notification for user {notification['user'].id}: {e}"
            )

    logger.info(f"✅ Processed refunds for {refunded_count} targets (OPTIMIZED)")
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


from celery import shared_task
from django.utils import timezone
from django.db import transaction as db_transaction
from django.db import IntegrityError
import logging
from django.db.models import Sum

logger = logging.getLogger(__name__)

from .models import CustomUser, ROITransaction, Transaction, DailyROIAccrual
from .utils import get_next_payout_date, calculate_daily_roi, send_push_notification
from django.db.models import Q


@shared_task
def calculate_daily_roi_task():
    """
    Calculate and accrue daily ROI only for active users with savings or investment balance above zero.
    """
    today = timezone.now().date()

    users_data = (
        CustomUser.objects.filter(
            is_active=True,
            is_banned=False,
        )
        .filter(Q(savings__gt=0) | Q(investment__gt=0))
        .values_list("id", "first_name", "expo_push_tokens")
    )

    processed_count = 0
    skipped_count = 0
    error_count = 0
    batch_size = 100
    notifications_batch = []

    logger.info(f"Starting calculate_daily_roi_task for {today}")

    for user_id, first_name, expo_tokens in users_data:
        try:
            if DailyROIAccrual.objects.filter(user_id=user_id, date=today).exists():
                skipped_count += 1
                logger.info(f"Skipping user {user_id}: ROI already exists for {today}")
                continue

            user = CustomUser.objects.get(id=user_id)

            total_roi, savings_roi, investment_roi = calculate_daily_roi(user, today)

            if total_roi > 0:
                next_payout = get_next_payout_date(today)

                start_of_month = today.replace(day=1)
                month_name = today.strftime("%B")

                month_earnings = (
                    DailyROIAccrual.objects.filter(
                        user_id=user_id, date__range=[start_of_month, today]
                    ).aggregate(total=Sum("total_roi"))["total"]
                    or 0
                )

                notifications_batch.append(
                    {
                        "user_id": user_id,
                        "title": "💹 Your Funds Have Grown!",
                        "message": (
                            f"Hi {first_name or 'there'}, your funds have earned returns. "
                            f"Savings: ₦{savings_roi:,.2f}, "
                            f"Investment: ₦{investment_roi:,.2f}. "
                            f"{month_name} earnings: ₦{month_earnings:,.2f}. "
                            f"Next payout: {next_payout.strftime('%d %B %Y')} 🎉"
                        ),
                        "data": {
                            "type": "DAILY_ROI",
                            "total_roi": float(total_roi),
                            "savings_roi": float(savings_roi),
                            "investment_roi": float(investment_roi),
                            "month_earnings": float(month_earnings),
                            "date": today.isoformat(),
                            "next_payout": next_payout.isoformat(),
                        },
                    }
                )

                processed_count += 1
                logger.info(f"Processed ROI for user {user_id}")

                if len(notifications_batch) >= batch_size:
                    batch_result = send_batch_roi_notifications(notifications_batch)
                    logger.info(
                        f"Batch ROI notifications sent. "
                        f"Sent: {batch_result['sent']}, Failed: {batch_result['failed']}"
                    )
                    notifications_batch = []

            else:
                logger.info(f"No ROI accrued for user {user_id}")

        except IntegrityError as e:
            skipped_count += 1
            logger.warning(f"Duplicate ROI prevented for user {user_id}: {e}")

        except Exception as e:
            error_count += 1
            logger.error(f"ROI error for user {user_id}: {e}")

    if notifications_batch:
        batch_result = send_batch_roi_notifications(notifications_batch)
        logger.info(
            f"Final ROI notification batch sent. "
            f"Sent: {batch_result['sent']}, Failed: {batch_result['failed']}"
        )

    logger.info(
        f"✅ Daily ROI task complete. Processed: {processed_count}, "
        f"Skipped: {skipped_count}, Errors: {error_count}"
    )

    return (
        f"✅ Daily ROI task complete. Processed: {processed_count}, "
        f"Skipped: {skipped_count}, Errors: {error_count}"
    )


def send_batch_roi_notifications(notifications):
    """Send ROI notifications one by one with safe logging."""
    sent_count = 0
    failed_count = 0

    for notification in notifications:
        try:
            result = send_push_notification(
                user_id=notification["user_id"],
                title=notification["title"],
                message=notification["message"],
                data=notification["data"],
                notif_type="DAILY_ROI",
            )

            if result.get("success"):
                sent_count += 1
                logger.info(f"ROI push sent to user {notification['user_id']}")
            else:
                failed_count += 1
                logger.warning(
                    f"ROI push not sent to user {notification['user_id']} "
                    f"(no tokens or Expo rejected it)"
                )

        except Exception as e:
            failed_count += 1
            logger.error(
                f"Error sending ROI notification to user {notification['user_id']}: {e}"
            )

    logger.info(
        f"ROI notification batch complete. Sent: {sent_count}, Failed: {failed_count}"
    )

    return {"sent": sent_count, "failed": failed_count}


@shared_task
def process_quarterly_payouts_task_fixed():
    """
    Process quarterly ROI payouts for the previous quarter.
    Optimized: Uses database aggregation, bulk_update, and batch operations.
    """
    from django.utils import timezone
    from decimal import Decimal
    from django.db.models import Sum, Q
    from datetime import date
    import logging

    logger = logging.getLogger(__name__)

    today = timezone.now().date()
    current_year = today.year
    current_month = today.month

    # Determine previous quarter
    if current_month in [1, 2, 3]:
        quarter_start = date(current_year - 1, 10, 1)
        quarter_end = date(current_year - 1, 12, 31)
        quarter_label = f"Q4 {current_year - 1}"
    elif current_month in [4, 5, 6]:
        quarter_start = date(current_year, 1, 1)
        quarter_end = date(current_year, 3, 31)
        quarter_label = f"Q1 {current_year}"
    elif current_month in [7, 8, 9]:
        quarter_start = date(current_year, 4, 1)
        quarter_end = date(current_year, 6, 30)
        quarter_label = f"Q2 {current_year}"
    else:
        quarter_start = date(current_year, 7, 1)
        quarter_end = date(current_year, 9, 30)
        quarter_label = f"Q3 {current_year}"

    # 🎯 OPTIMIZED: Use database aggregation to get all payouts at once
    user_payouts = (
        ROITransaction.objects.filter(
            accrued_date__range=[quarter_start, quarter_end],
            is_paid_out=False,
        )
        .values("user_id")
        .annotate(total_payout=Sum("amount"))
        .filter(total_payout__gt=0)
    )

    total_paid_users = 0
    total_amount = Decimal("0.00")

    # Collect data for bulk operations
    users_to_update = []
    transactions_to_create = []
    emails_to_send = []
    roi_to_mark_paid = []

    logger.info(f"📊 Processing quarterly payouts for {len(user_payouts)} users")

    for payout_data in user_payouts:
        try:
            user_id = payout_data["user_id"]
            total_payout = Decimal(str(payout_data["total_payout"]))

            if total_payout <= 0:
                continue

            # Get user object for notifications
            user = CustomUser.objects.get(id=user_id)

            # Collect user wallet update
            user.wallet = models.F("wallet") + total_payout
            users_to_update.append(user)

            # Collect transaction record
            transactions_to_create.append(
                Transaction(
                    user_id=user_id,
                    transaction_type="credit",
                    source="INVESTMENT",
                    status="confirmed",
                    amount=total_payout,
                    service_charge=Decimal("0.00"),
                    total_amount=total_payout,
                    description=f"Dividends: {quarter_label} ROI",
                )
            )

            # Get ROI breakdown for email
            roi_breakdown = (
                ROITransaction.objects.filter(
                    user_id=user_id,
                    accrued_date__range=[quarter_start, quarter_end],
                    is_paid_out=False,
                )
                .values("roi_type")
                .annotate(total=Sum("amount"))
            )

            savings_roi = next(
                (
                    Decimal(str(r["total"]))
                    for r in roi_breakdown
                    if r["roi_type"] == "SAVINGS"
                ),
                Decimal("0"),
            )
            investment_roi = next(
                (
                    Decimal(str(r["total"]))
                    for r in roi_breakdown
                    if r["roi_type"] == "INVESTMENT"
                ),
                Decimal("0"),
            )

            # Collect email data
            emails_to_send.append(
                {
                    "email": user.email,
                    "first_name": user.first_name,
                    "total_payout": total_payout,
                    "savings_roi": savings_roi,
                    "investment_roi": investment_roi,
                    "quarter_label": quarter_label,
                    "user": user,
                }
            )

            # Mark ROI records for update
            roi_records = ROITransaction.objects.filter(
                user_id=user_id,
                accrued_date__range=[quarter_start, quarter_end],
                is_paid_out=False,
            )
            for roi in roi_records:
                roi.is_paid_out = True
                roi.payout_date = today
                roi_to_mark_paid.append(roi)

            total_paid_users += 1
            total_amount += total_payout

        except Exception as e:
            logger.error(f"Error processing payout for user {user_id}: {e}")
            continue

    # 🚀 BULK OPERATIONS
    if users_to_update:
        CustomUser.objects.bulk_update(users_to_update, ["wallet"], batch_size=500)
        logger.info(f"✅ Updated wallets for {len(users_to_update)} users")

    if transactions_to_create:
        Transaction.objects.bulk_create(transactions_to_create, batch_size=500)
        logger.info(f"✅ Created {len(transactions_to_create)} transaction records")

    if roi_to_mark_paid:
        ROITransaction.objects.bulk_update(
            roi_to_mark_paid, ["is_paid_out", "payout_date"], batch_size=500
        )
        logger.info(f"✅ Marked {len(roi_to_mark_paid)} ROI records as paid")

    # 📧 Send emails and notifications
    for email_data in emails_to_send:
        try:
            user = email_data["user"]

            # Push notification
            send_push_notification(
                user,
                title=f"🎉 {email_data['quarter_label']} Dividends Paid! (₦{email_data['total_payout']:,.2f})",
                message=(
                    f"{user.first_name}, ₦{email_data['total_payout']:,.2f} has been added to your wallet as dividends! "
                    f"(Savings: ₦{email_data['savings_roi']:,.2f}, Investment: ₦{email_data['investment_roi']:,.2f})"
                ),
                data={
                    "type": "QUARTERLY_PAYOUT",
                    "amount": float(email_data["total_payout"]),
                    "period": email_data["quarter_label"],
                },
            )

            # Send email via utility (handles batching)
            send_generic_email(
                subject=f"🎉 {email_data['first_name']}, ₦{email_data['total_payout']:,.2f} Has Been Added to Your Wallet!",
                message=(
                    f"Hi {email_data['first_name']},<br><br>"
                    f"Your ROI of ₦{email_data['total_payout']:,.2f} has been credited to your MyFund wallet for ({email_data['quarter_label']})!<br>"
                    f"(Savings: ₦{email_data['savings_roi']:,.2f}, Investment: ₦{email_data['investment_roi']:,.2f})<br><br>"
                    "Thank you for using MyFund. Keep growing your funds to earn more in the next quarter! 🚀"
                ),
                recipient_list=[email_data["email"]],
                from_email="MyFund <info@myfundmobile.com>",
            )
        except Exception as e:
            logger.error(f"Error processing user {user.email}: {e}")
            continue

    return f"✅ Quarterly ROI processed for {total_paid_users} users, total ₦{total_amount:,.2f}, period {quarter_label}"


@shared_task
def process_quarterly_payout_single_user(email):
    from django.utils import timezone
    from .models import CustomUser, ROITransaction, Transaction
    from .utils import send_push_notification
    from decimal import Decimal
    from django.db import transaction as db_transaction
    from datetime import date

    today = timezone.now().date()
    current_year = today.year
    current_month = today.month

    # Previous quarter logic same as fixed task
    if current_month in [1, 2, 3]:
        quarter_start = date(current_year - 1, 10, 1)
        quarter_end = date(current_year - 1, 12, 31)
        quarter_label = f"Q4 {current_year - 1}"
    elif current_month in [4, 5, 6]:
        quarter_start = date(current_year, 1, 1)
        quarter_end = date(current_year, 3, 31)
        quarter_label = f"Q1 {current_year}"
    elif current_month in [7, 8, 9]:
        quarter_start = date(current_year, 4, 1)
        quarter_end = date(current_year, 6, 30)
        quarter_label = f"Q2 {current_year}"
    else:
        quarter_start = date(current_year, 7, 1)
        quarter_end = date(current_year, 9, 30)
        quarter_label = f"Q3 {current_year}"

    user = CustomUser.objects.filter(email=email).first()
    if not user:
        return f"User {email} not found"

    unpaid_roi = ROITransaction.objects.filter(
        user=user, accrued_date__range=[quarter_start, quarter_end], is_paid_out=False
    )
    total_payout = sum(t.amount for t in unpaid_roi)

    if total_payout <= 0:
        return f"No unpaid ROI for {email}"

    with db_transaction.atomic():
        user.wallet += total_payout
        user.save(update_fields=["wallet"])
        unpaid_roi.update(is_paid_out=True, payout_date=today)
        Transaction.objects.create(
            user=user,
            transaction_type="credit",
            source="INVESTMENT",
            status="confirmed",
            amount=Decimal(total_payout),
            service_charge=Decimal("0.00"),
            total_amount=Decimal(total_payout),
            description=f"Dividends: {quarter_label} ROI",
        )

        send_push_notification(
            user,
            title=f"🎉 Quarterly ROI Paid! ({quarter_label})",
            message=f"Hi {user.first_name}, Your ROI of ₦{total_payout:,.2f} has been credited to your Wallet for {quarter_label}! Keep growing your funds to earn more in the next quarter.",
            data={
                "type": "QUARTERLY_PAYOUT",
                "amount": float(total_payout),
                "period": quarter_label,
            },
        )

        # Send email notification
        savings_roi = sum(t.amount for t in unpaid_roi if t.roi_type == "SAVINGS")
        investment_roi = sum(t.amount for t in unpaid_roi if t.roi_type == "INVESTMENT")

        send_generic_email(
            subject=f"🎉 Quarterly ROI Paid! ({quarter_label})",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Your ROI of ₦{total_payout:,.2f} has been credited to your MyFund Wallet for {quarter_label}!<br>"
                f"(Savings: ₦{savings_roi:,.2f}, Investment: ₦{investment_roi:,.2f})<br><br>"
                "Thank you for using MyFund. Keep growing your funds to earn more in the next quarter! 🚀"
            ),
            recipient_list=[user.email],
            from_email="MyFund <info@myfundmobile.com>",
        )

    return f"✅ Paid ₦{total_payout:,.2f} to {email}"


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


# tasks.py
from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
import time

logger = logging.getLogger(__name__)


@shared_task(rate_limit="20/m")
def send_single_email_task(email, subject, message, from_email):
    try:
        html_message = render_to_string(
            "email/email.html", {"subject": subject, "message": message}
        )
        plain_message = strip_tags(html_message)
        send_mail(
            subject,
            plain_message,
            from_email,
            [email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info(f"📧 Sent (Celery) email to {email}")
    except Exception as e:
        logger.error(f"❌ Failed to send Celery email to {email}: {e}")


@shared_task
def send_email_batch_task(batches, from_email):
    """
    Batches = [{"email": ..., "subject": ..., "message": ...}, ...]
    Send in groups of 50, sleep 5 minutes between batches.
    """
    BATCH_SIZE = 50
    DELAY_SECONDS = 300

    for i in range(0, len(batches), BATCH_SIZE):
        batch = batches[i : i + BATCH_SIZE]
        for entry in batch:
            try:
                html_message = render_to_string(
                    "email/email.html",
                    {"subject": entry["subject"], "message": entry["message"]},
                )
                plain_message = strip_tags(html_message)
                send_mail(
                    entry["subject"],
                    plain_message,
                    from_email,
                    [entry["email"]],
                    html_message=html_message,
                    fail_silently=False,
                )
                logger.info(f"📧 Sent batch email to {entry['email']}")
            except Exception as e:
                logger.error(f"❌ Failed batch email to {entry['email']}: {e}")

        if i + BATCH_SIZE < len(batches):
            logger.info(f"⏳ Sleeping {DELAY_SECONDS}s before next batch...")
            time.sleep(DELAY_SECONDS)


@shared_task
def send_large_email_batch_task(batches, from_email, batch_size=50, delay_seconds=300):
    """
    Send large email lists (>500) safely using Celery + Redis,
    batching and delaying between groups to avoid Namecheap limits.
    """
    import time
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    from django.utils.html import strip_tags
    import logging

    logger = logging.getLogger(__name__)

    for i in range(0, len(batches), batch_size):
        batch = batches[i : i + batch_size]
        for entry in batch:
            try:
                html_message = render_to_string(
                    "email/email.html",
                    {"subject": entry["subject"], "message": entry["message"]},
                )
                plain_message = strip_tags(html_message)
                send_mail(
                    entry["subject"],
                    plain_message,
                    from_email,
                    [entry["email"]],
                    html_message=html_message,
                    fail_silently=False,
                )
                logger.info(f"📧 Sent large batch email to {entry['email']}")
            except Exception as e:
                logger.error(f"❌ Failed large batch email to {entry['email']}: {e}")

        if i + batch_size < len(batches):
            logger.info(f"⏳ Sleeping {delay_seconds}s before next batch...")
            time.sleep(delay_seconds)


from django.utils import timezone
from celery import shared_task
from authentication.models import WithdrawalsRequestToAdmin
from .utils import process_scheduled_withdrawal


@shared_task
def process_due_scheduled_withdrawals():
    today = timezone.now().date()

    withdrawals = WithdrawalsRequestToAdmin.objects.filter(
        withdrawal_type="scheduled",
        scheduled_processing_date__lte=today,
        is_processed=False,
    )

    for withdrawal in withdrawals:
        try:
            process_scheduled_withdrawal(withdrawal)
        except Exception as e:
            logger.error(
                f"Failed to process scheduled withdrawal {withdrawal.id}: {str(e)}"
            )


from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
import time

logger = logging.getLogger(__name__)


@shared_task
def send_single_email_task(email, subject, message, from_email):
    """
    Single email task - used by send_generic_email when >30 recipients
    """
    try:
        # Create HTML content
        try:
            html_content = render_to_string(
                "email/email.html",
                {"subject": subject, "message": message, "user_email": email},
            )
        except Exception as e:
            logger.warning(f"Template error for {email}: {e}")
            html_content = f"<html><body>{message}</body></html>"

        # Send email
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=from_email,
            recipient_list=[email],
            html_message=html_content,
            fail_silently=False,
        )

        logger.info(f"✅ Celery single email sent to {email}")
        return {"status": "sent", "email": email}

    except Exception as e:
        logger.error(f"❌ Celery single email failed for {email}: {e}")
        return {"status": "failed", "email": email, "error": str(e)}


from celery import shared_task
import time
import logging
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)
from celery import shared_task
from django.core.mail import send_mail, get_connection
from django.conf import settings
import time
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_namecheap_safe_email_task(
    self, emails, from_email, reuse_connection=False, batch_size=15, delay_seconds=2
):
    """
    Namecheap-safe email sending with single SMTP connection per batch.
    """
    total_emails = len(emails)
    sent_count = 0
    failed_emails = []

    logger.info(
        f"🛡️ Namecheap-safe: Processing {total_emails} emails in ultra-safe mode"
    )

    # Open SMTP connection if reuse_connection is True
    connection = None
    if reuse_connection:
        connection = get_connection(
            username=from_email,
            password=settings.EMAIL_HOST_PASSWORD,
            fail_silently=False,
        )
        connection.open()

    try:
        for i, email_data in enumerate(emails):
            try:
                to_email = email_data.get("to", "")
                subject = email_data.get("subject", "")
                plain_message = email_data.get("plain_message", "")
                html_message = email_data.get("html_message", "")

                if not to_email:
                    logger.warning("Skipping email with no recipient")
                    continue

                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[to_email],
                    html_message=html_message,
                    fail_silently=False,
                    connection=connection,  # <-- USE the connection here
                    timeout=30,  # optional, prevents hanging
                )

                sent_count += 1

                if (i + 1) % 5 == 0:
                    logger.info(f"✅ Sent {i+1}/{total_emails} emails in this batch")

                time.sleep(delay_seconds)

            except Exception as e:
                error_info = {"email": to_email, "error": str(e)}
                failed_emails.append(error_info)
                logger.error(f"❌ Email failed for {to_email}: {e}")

                # Retry if rate limit
                if "rate limit" in str(e).lower() or "quota" in str(e).lower():
                    logger.warning(f"⚠️ Rate limit detected, waiting 5 minutes...")
                    time.sleep(300)
                    try:
                        self.retry(countdown=300, max_retries=2)
                    except self.MaxRetriesExceededError:
                        logger.error(f"Max retries exceeded for {to_email}")
                        continue

    finally:
        if connection:
            connection.close()  # <-- close connection at the end

    logger.info(f"📊 Namecheap-safe batch complete: {sent_count}/{total_emails} sent")

    return {
        "sent": sent_count,
        "failed": len(failed_emails),
        "total": total_emails,
        "batch_size": batch_size,
        "delay_seconds": delay_seconds,
        "failed_emails": failed_emails if failed_emails else None,
    }


from celery import shared_task
import time
import logging
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, queue="email_queue")
def send_bulk_email_task(self, emails, from_email, batch_size=45, delay_seconds=300):
    total = len(emails)
    sent = 0
    failed = []

    logger.info(f"📦 Sending {total} emails in batches of {batch_size}")

    for i in range(0, total, batch_size):
        batch = emails[i : i + batch_size]

        logger.info(f"🚀 Processing batch {i//batch_size + 1}")

        for e in batch:
            try:
                send_mail(
                    subject=e["subject"],
                    message=e["plain_message"],
                    from_email=from_email,
                    recipient_list=[e["to"]],
                    html_message=e["html_message"],
                    fail_silently=False,
                )
                sent += 1
            except Exception as ex:
                failed.append({"email": e["to"], "error": str(ex)})
                logger.error(f"❌ Failed {e['to']}: {ex}")

        if i + batch_size < total:
            logger.info(f"⏳ Sleeping {delay_seconds}s before next batch")
            time.sleep(delay_seconds)

    logger.info(f"📊 Done: {sent}/{total} sent")
    return {"sent": sent, "failed": len(failed)}


from datetime import date
from decimal import Decimal
from celery import shared_task
from django.db import transaction
from django.utils import timezone
from django.db.models import Sum, Q

from authentication.models import CustomUser, ROITransaction, Transaction
from authentication.utils import send_generic_email, send_push_notification


@shared_task(bind=True)
def backfill_q3_2025_roi_from_transactions(self, email=None, test_only=False):
    """
    Backfill and payout Q3 2025 ROI by recalculating balances from Transaction history.
    - Savings ROI: 13% annual
    - Investment ROI: 20% annual
    - Includes QuickSave, AutoSave, QuickInvest, AutoInvest confirmed transactions only
      (based on description field)
    - Prevents duplicate payouts for normal users
    - Always processes test accounts
    - Credits wallets, creates ROITransaction & Transaction records
    - Sends email via Celery & push notification
    """

    Q3_START = date(2025, 7, 1)
    Q3_END = date(2025, 9, 30)
    quarter_label = "Q3 2025"

    TEST_EMAILS = [
        "tolulopeahmed@gmail.com",
        "info@myfundmobile.com",
        "company@myfundmobile.com",
        "valueplusrecords@gmail.com",
        "valuepluspublishing@gmail.com",
    ]

    users = CustomUser.objects.filter(is_active=True)
    if test_only:
        users = users.filter(email__in=TEST_EMAILS)
    elif email:
        users = users.filter(email=email)

    if not users.exists():
        print("[INFO] No users found for the given filter.")
        return

    for user in users:
        # Skip if ROI already paid (except test accounts)
        if user.email not in TEST_EMAILS:
            if ROITransaction.objects.filter(
                user=user,
                accrued_date__gte=Q3_START,
                accrued_date__lte=Q3_END,
                roi_type__in=["SAVINGS", "INVESTMENT"],
            ).exists():
                print(f"[SKIP] ROI already paid for {user.email}")
                continue

        # Define queries based on description for savings and investment
        savings_q = Q(description__icontains="QuickSave") | Q(
            description__icontains="AutoSave"
        )
        investment_q = Q(description__icontains="QuickInvest") | Q(
            description__icontains="AutoInvest"
        )

        # Savings: credits minus debits
        savings_credits = Transaction.objects.filter(
            user=user,
            transaction_type="credit",
            status="confirmed",
            date__date__gte=Q3_START,
            date__date__lte=Q3_END,
        ).filter(savings_q).aggregate(total=Sum("amount"))["total"] or Decimal("0.00")
        savings_debits = Transaction.objects.filter(
            user=user,
            transaction_type="debit",
            status="confirmed",
            date__date__gte=Q3_START,
            date__date__lte=Q3_END,
        ).filter(savings_q).aggregate(total=Sum("amount"))["total"] or Decimal("0.00")
        savings_balance_q3 = (savings_credits - savings_debits).quantize(
            Decimal("0.01")
        )

        # Investment: credits minus debits
        investment_credits = Transaction.objects.filter(
            user=user,
            transaction_type="credit",
            status="confirmed",
            date__date__gte=Q3_START,
            date__date__lte=Q3_END,
        ).filter(investment_q).aggregate(total=Sum("amount"))["total"] or Decimal(
            "0.00"
        )
        investment_debits = Transaction.objects.filter(
            user=user,
            transaction_type="debit",
            status="confirmed",
            date__date__gte=Q3_START,
            date__date__lte=Q3_END,
        ).filter(investment_q).aggregate(total=Sum("amount"))["total"] or Decimal(
            "0.00"
        )
        investment_balance_q3 = (investment_credits - investment_debits).quantize(
            Decimal("0.01")
        )

        # Compute ROI
        savings_roi = (savings_balance_q3 * Decimal("0.13") / Decimal("4")).quantize(
            Decimal("0.01")
        )
        investment_roi = (
            investment_balance_q3 * Decimal("0.2") / Decimal("4")
        ).quantize(Decimal("0.01"))
        total_payout = (savings_roi + investment_roi).quantize(Decimal("0.01"))

        if total_payout <= 0:
            print(f"[SKIP] Total payout is zero for {user.email}")
            continue

        with transaction.atomic():
            if savings_roi > 0:
                ROITransaction.objects.create(
                    user=user,
                    amount=savings_roi,
                    roi_type="SAVINGS",
                    accrued_date=Q3_END,
                    payout_date=timezone.now().date(),
                    is_paid_out=True,
                )
            if investment_roi > 0:
                ROITransaction.objects.create(
                    user=user,
                    amount=investment_roi,
                    roi_type="INVESTMENT",
                    accrued_date=Q3_END,
                    payout_date=timezone.now().date(),
                    is_paid_out=True,
                )

            user.savings += savings_roi
            user.investment += investment_roi
            user.save(update_fields=["savings", "investment"])

            Transaction.objects.create(
                user=user,
                transaction_type="credit",
                source="ROI_Q3_2025",
                status="confirmed",
                amount=total_payout,
                service_charge=Decimal("0.00"),
                total_amount=total_payout,
                description=f"Dividends: {quarter_label} ROI",
            )

        # --- FORCE EMAIL VIA CELERY ---
        send_generic_email(
            subject=f"🎉 ₦{total_payout:,.2f} Has Been Credited to Your Wallet",
            message=(
                f"<p>Hi {user.first_name},</p>"
                f"<p>Your quarterly ROI has been added to your MyFund Wallet as dividends for <b>{quarter_label}</b>.</p>"
                f"<p><b>Total ROI credited:</b> ₦{total_payout:,.2f}<br>"
                f"<b>Savings ROI:</b> ₦{savings_roi:,.2f}<br>"
                f"<b>Investment ROI:</b> ₦{investment_roi:,.2f}</p>"
                f"<p>This payout covers your earnings for {quarter_label}.</p>"
                f"<p>Thank you for using MyFund.</p>"
                f"<p>The MyFund Team</p>"
            ),
            recipient_list=[user.email],
            from_email="MyFund <info@myfundmobile.com>",
            use_celery_threshold=0,  # <--- force Celery even for single user
        )

        # Push notification
        send_push_notification(
            user=user,
            title=f"🎉 ₦{total_payout:,.2f} Has Been Added to Your Wallet",
            message=(
                f"{user.first_name}, a total of ₦{total_payout:,.2f} has been credited to your Wallet as dividends for {quarter_label}.\n"
                f"Savings: ₦{savings_roi:,.2f} + Investment: ₦{investment_roi:,.2f}\n"
                f"Keep growing your funds to earn more in the next quarter! 🚀"
            ),
        )

        print(f"[Q3 2025 ROI BACKFILL] {user.email} → ₦{total_payout:,.2f}")

    return f"✅ Backfill completed for {users.count()} user(s)."


from celery import shared_task
from django.conf import settings
from .models import CustomUser
from .utils import send_generic_email
import logging

logger = logging.getLogger(__name__)


@shared_task
def send_namecheap_safe_email_task_v2(test_mode=False, from_email=None):
    """
    Send MyFund email safely via Namecheap.
    Usage:
      - test_mode=True to send only to exec emails
      - test_mode=False (or omitted) to send to all active users
    """

    from_email = from_email or settings.DEFAULT_FROM_EMAIL

    SUBJECT = (
        "NEW TAX GUIDELINES for Savings/Investment Earnings (Starting Feb 1st, 2026)"
    )

    MESSAGE = """
<p>Dear {first_name},</p>

<p>We would like to inform you of an important update regarding your savings and investment payouts on MyFund.</p>

<p>In line with current Nigerian Tax Laws, all financial platforms are required to apply statutory taxes on earnings and service charges.
To comply with these regulations, MyFund will be updating its transaction system to reflect these taxes.</p>

<p>Although the regulatory deadline for this update was January 19, 2026, implementation on MyFund will now take effect from:</p>

<p><strong>📅 February 1st, 2026</strong></p>

<hr>

<p><strong>What This Means for You</strong></p>

<ul>
  <li>VAT on Service Charges – <strong>7.5%</strong></li>
  <li>Withholding Tax on Interest (Dividends) – <strong>10%</strong></li>
</ul>

<p>These charges are mandated by Nigerian tax authorities and are not MyFund charges.</p>

<p><strong>Simple Illustration</strong></p>

<p>If your dividend or interest payout is ₦10,000:</p>

<ul>
  <li>10% Withholding Tax = ₦1,000</li>
  <li>7.5% VAT on applicable service charges</li>
</ul>

<p>Your final payout will be after these statutory charges.</p>

<p><strong>Important to Note</strong></p>

<ul>
  <li>These charges apply to transactions from February 1st, 2026</li>
  <li>Your next dividends payout in April will reflect this updates</li>
  <li>This ensures MyFund remains compliant with Nigerian regulations</li>
</ul>

<p>If you need clarification, our support team is available via email at care@myfundmobile.com.</p>



<p>
Warm regards,<br>
<strong>Chubi</strong><br>
DME, MyFund
</p>
"""

    # Recipient selection
    TEST_EXEC_EMAILS = [
        "dme@myfundmobile.com",
        "janet.adegbenro@gmail.com",
        "patrickmundi1@myfundmobile.com",
        "valueplusrecords@gmail.com",
    ]

    if test_mode:
        recipients = TEST_EXEC_EMAILS
        logger.warning(
            "🧪 TEST MODE ENABLED — sending tax update email ONLY to exec team"
        )
    else:
        recipients = list(
            CustomUser.objects.filter(is_active=True)
            .exclude(email__isnull=True)
            .exclude(email__exact="")
            .values_list("email", flat=True)
        )
        logger.warning(
            f"🚀 LIVE MODE ENABLED — sending tax update email to {len(recipients)} users"
        )

    # Send via Namecheap-safe utility
    result = send_generic_email(
        subject=SUBJECT,
        message=MESSAGE,
        recipient_list=recipients,
        from_email=from_email,
    )

    logger.info(f"📊 Tax update email task result: {result}")
    return result


from celery import shared_task
from .models import AmbassadorMonthlyReport, CustomUser
from .utils import send_push_notification, send_generic_email
from datetime import datetime


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_ambassador_report_notifications_task(self, report_id, user_id):
    try:
        report = AmbassadorMonthlyReport.objects.select_related("user").get(
            id=report_id
        )
        user = CustomUser.objects.get(id=user_id)

        formatted_month = report.month
        try:
            formatted_month = datetime.strptime(report.month, "%Y-%m").strftime("%B %Y")
        except Exception:
            pass
        # USER EMAIL
        send_generic_email(
            subject="Ambassador Report Received... 🕒",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"We’ve received your ambassador report for {report.month}. "
                "It is now under review. We’ll notify you once it has been approved.<br><br>"
                "Thank you for using MyFund.<br><br>"
            ),
            from_email="MyFund <info@myfundmobile.com>",
            recipient_list=[user.email],
        )

        # USER PUSH
        send_push_notification(
            user=user,
            title="Ambassador Report Submitted 🕒",
            message=f"Your report for {report.month} is under review.",
            data={
                "report_id": report.id,
                "month": report.month,
                "status": report.status,
            },
            notif_type="SYSTEM",
        )

        # ADMIN EMAIL
        send_generic_email(
            subject=f"Ambassador Report - {user.first_name} {user.last_name}",
            message=(
                f"Hello Admin,<br><br>"
                f"{user.first_name} {user.last_name} ({user.email}) submitted an ambassador report for {report.month}. "
                "Please review it in Django admin.<br><br>"
            ),
            from_email="MyFund <info@myfundmobile.com>",
            recipient_list=["info@myfundmobile.com", "company@myfundmobile.com"],
        )

        # ADMIN PUSH
        admin_users = CustomUser.objects.filter(
            email__in=[
                "tolulopeahmed@gmail.com",
                "ceo@myfundmobile.com",
                "janet.adegbenro@gmail.com",
            ]
        )

        for admin_user in admin_users:
            if getattr(admin_user, "expo_push_tokens", []):
                send_push_notification(
                    user=admin_user,
                    title="📋 Ambassador Report Submitted",
                    message=f"{user.first_name} {user.last_name} submitted a report for {report.month}.",
                    data={
                        "report_id": report.id,
                        "user_email": user.email,
                        "month": report.month,
                        "type": "admin_ambassador_report_alert",
                    },
                    notif_type="ADMIN_ALERT",
                )

        return f"Notifications sent successfully for report {report.id}"

    except Exception as exc:
        raise self.retry(exc=exc)


import logging
import re

from django.conf import settings

from authentication.models import CustomUser
from authentication.utils import send_generic_email

logger = logging.getLogger(__name__)


AMBASSADOR_GROUP_LINK = "https://chat.whatsapp.com/K6ydqeE0zKuGX0Sek87tkW"

TEST_AMBASSADOR_EMAILS = [
    "dme@myfundmobile.com",
    "janet.adegbenro@gmail.com",
    "janet.adegbenro@gmail.com",
    "patrickmundi1@myfundmobile.com",
    "valueplusrecords@gmail.com",
]

SHORTLISTED_EMAILS = [
    "sopiribi.fenibo76@gmail.com",
    "developermykel@gmail.com",
    "eyibiootu001@gmail.com",
    "chiomahappiness2006@gmail.com",
    "treasurepre06@gmail.com",
    "akoredeboluwatife09@gmail.com",
    "amosanyebe700@gmail.com",
    "treasuryboxnosa@gmail.com",
    "zainabishola@gmail.com",
    "osobukolasemilore@gmail.com",
    "mahmoudteslim5@gmail.com",
    "opesunday21@gmail.com",
]

SECOND_CATEGORY_EMAILS = [
    "jamestobiloba6@gmail.com",
    "faithyemisi58@gmail.com",
    "afsatadeyemi@gmail.com",
    "olorodeayomide320@gmail.com",
    "pleasantdinehin@gmail.com",
    "uyannajeremiah@gmail.com",
    "idowuayomideemmanuel@gmail.com",
    "okoigunehino829@gmail.com",
    "petrusbabalola08@gmail.com",
    "adebayogafar43@gmail.com",
    "ogunniyiezekiel79@gmail.com",
    "adeoyetemiloluwa33@gmail.com",
    "eoluwatoyin128@gmail.com",
    "olawunmikofoworola2019@gmail.com",
    "lydiaekeabor@gmail.com",
    "justinafolabi2006@gmail.com",
    "adeolasamuel2017@gmail.com",
    "idunnuarowolo@gmail.com",
    "adeoyeoyinkansola57@gmail.com",
    "obadimuesther22@gmail.com",
    "bamigboyeesther2022@gmail.com",
    "tomisax04@gmail.com",
    "adewumie61@gmail.com",
    "thomasesther545@gmail.com",
    "deborahakomolafe260@gmail.com",
    "joodajuliana4@gmail.com",
    "johnadefolu992@gmail.com",
    "banjoboluwatife182@gmail.com",
    "favoureffiong2008@gmail.com",
]


def _is_valid_email(email):
    if not email:
        return False
    email = str(email).strip()
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.match(pattern, email))


def _clean_recipient_list(email_list):
    cleaned = []
    seen = set()

    for email in email_list:
        if not email:
            continue

        email = str(email).strip().lower()

        if not _is_valid_email(email):
            logger.warning(f"Skipping invalid email: {email}")
            continue

        if email in seen:
            continue

        seen.add(email)
        cleaned.append(email)

    return cleaned


def _guess_first_name_from_email(email):
    try:
        local_part = email.split("@")[0]
        local_part = local_part.replace(".", " ").replace("_", " ").replace("-", " ")
        first_name = local_part.split()[0].strip()
        return first_name.capitalize() if first_name else "Applicant"
    except Exception:
        return "Applicant"


def _get_first_name(email):
    user = (
        CustomUser.objects.filter(email__iexact=email)
        .only("first_name", "email")
        .first()
    )

    if user and user.first_name and user.first_name.strip():
        return user.first_name.strip()

    return _guess_first_name_from_email(email)


def _shortlist_email_html(first_name):
    return f"""
<p>Hi {first_name},</p>

<p><strong>Congratulations!</strong></p>

<p>We’re excited to inform you that you have been shortlisted for the <strong>MyFund Ambassador Program (Cohort 3)</strong>.</p>

<p>After carefully reviewing all applications, your profile stood out based on your potential, clarity, and alignment with what we are building at MyFund; a community of individuals committed to smarter financial habits and long-term wealth creation.</p>

<p>Being shortlisted means you are one step closer to joining a group of ambassadors who will:</p>

<ul>
  <li>Drive meaningful impact through financial education</li>
  <li>Build and influence communities</li>
  <li>Grow personally while earning and gaining real-world experience</li>
</ul>

<p><strong>Next Steps:</strong></p>

<ul>
  <li>Join the official shortlisted candidates group</li>
  <li>Ensure you are signed up on MyFund</li>
  <li>Ensure your KYC is updated/completed</li>
</ul>

<p>Use the button below to join the group:</p>

<p style="margin: 24px 0;">
  <a href="{AMBASSADOR_GROUP_LINK}"
     style="
        background-color: #4c28BC;
        color: #ffffff !important;
        text-decoration: none;
        padding: 14px 18px;
        border-radius: 8px;
        display: block;
        width: 100%;
        max-width: 100%;
        box-sizing: border-box;
        text-align: center;
        font-weight: 700;
        white-space: nowrap;
     ">
     Join Group
  </a>
</p>

<p>Further details about the next stage of the selection process will be shared in the group.</p>

<p>We’re excited about the possibility of having you on this journey with us.</p>

<p>Welcome to the next stage.</p>

<p>
Best regards,<br>
<strong>Chubi</strong><br>
DME MyFund
</p>
"""


def _second_category_email_html():
    return """
<p>Hello,</p>

<p>Thank you for taking the time to apply for the <strong>MyFund Ambassador Program (Cohort 3)</strong>.</p>

<p>We received a strong number of applications, and while you were not included in the first batch of shortlisted candidates, we’re pleased to let you know that you are being considered for the <strong>second batch</strong> of the selection process.</p>

<p>This means your application is still very much active, and we see potential in your profile.</p>

<p>You will receive a follow-up email with details on how to proceed to the next stage in 
April. We encourage you to stay prepared and keep an eye on your inbox.</p>

<p>We appreciate your interest in building with MyFund and look forward to what’s ahead.</p>

<p>
Best regards,<br>
<strong>Chubi</strong><br>
DME MyFund
</p>
"""


def send_shortlisted_ambassador_emails(test_mode=True, only_email=None):
    """
    Sends shortlisted emails directly without Celery.

    Usage:
        send_shortlisted_ambassador_emails(test_mode=True)
        send_shortlisted_ambassador_emails(test_mode=False)
        send_shortlisted_ambassador_emails(only_email="someone@gmail.com")
    """

    subject = (
        "Congratulations! You’ve Been Shortlisted as a MyFund Ambassador (Cohort 3)"
    )
    from_email = getattr(
        settings,
        "DEFAULT_FROM_EMAIL",
        "MyFund <info@myfundmobile.com>",
    )

    if only_email:
        recipients = [only_email]
        logger.warning(f"Single email mode for shortlisted send: {only_email}")
    elif test_mode:
        recipients = TEST_AMBASSADOR_EMAILS
        logger.warning(
            "TEST MODE ENABLED — sending shortlisted email to test emails only"
        )
    else:
        recipients = SHORTLISTED_EMAILS
        logger.warning(
            "LIVE MODE ENABLED — sending shortlisted email to all shortlisted candidates"
        )

    recipients = _clean_recipient_list(recipients)

    if not recipients:
        logger.warning("No valid recipients found for shortlisted email send.")
        return {"success": False, "sent": 0, "failed": 0, "details": []}

    sent_count = 0
    failed_count = 0
    details = []

    for email in recipients:
        try:
            first_name = _get_first_name(email)
            message = _shortlist_email_html(first_name=first_name)

            result = send_generic_email(
                subject=subject,
                message=message,
                recipient_list=[email],
                from_email=from_email,
                use_celery_threshold=999999,
            )

            sent_count += 1
            details.append(
                {
                    "email": email,
                    "status": "sent",
                    "first_name": first_name,
                    "result": result,
                }
            )
            logger.info(f"Shortlisted email sent to {email}")

        except Exception as e:
            failed_count += 1
            details.append(
                {
                    "email": email,
                    "status": "failed",
                    "error": str(e),
                }
            )
            logger.exception(f"Failed to send shortlisted email to {email}: {str(e)}")

    summary = {
        "success": failed_count == 0,
        "sent": sent_count,
        "failed": failed_count,
        "details": details,
    }

    logger.info(f"Shortlisted ambassador email summary: {summary}")
    return summary


def send_second_batch_ambassador_emails(test_mode=True, only_email=None):
    """
    Sends second category emails directly without Celery.

    Usage:
        send_second_batch_ambassador_emails(test_mode=True)
        send_second_batch_ambassador_emails(test_mode=False)
        send_second_batch_ambassador_emails(only_email="someone@gmail.com")
    """

    subject = "Update on Your MyFund Ambassador Application (Cohort 3)"
    from_email = getattr(
        settings,
        "DEFAULT_FROM_EMAIL",
        "MyFund <info@myfundmobile.com>",
    )

    if only_email:
        recipients = [only_email]
        logger.warning(f"Single email mode for second batch send: {only_email}")
    elif test_mode:
        recipients = TEST_AMBASSADOR_EMAILS
        logger.warning(
            "TEST MODE ENABLED — sending second batch email to test emails only"
        )
    else:
        recipients = SECOND_CATEGORY_EMAILS
        logger.warning(
            "LIVE MODE ENABLED — sending second batch email to second category candidates"
        )

    recipients = _clean_recipient_list(recipients)

    if not recipients:
        logger.warning("No valid recipients found for second batch email send.")
        return {"success": False, "sent": 0, "failed": 0, "details": []}

    sent_count = 0
    failed_count = 0
    details = []

    for email in recipients:
        try:
            message = _second_category_email_html()

            result = send_generic_email(
                subject=subject,
                message=message,
                recipient_list=[email],
                from_email=from_email,
                use_celery_threshold=999999,
            )

            sent_count += 1
            details.append(
                {
                    "email": email,
                    "status": "sent",
                    "result": result,
                }
            )
            logger.info(f"Second batch email sent to {email}")

        except Exception as e:
            failed_count += 1
            details.append(
                {
                    "email": email,
                    "status": "failed",
                    "error": str(e),
                }
            )
            logger.exception(f"Failed to send second batch email to {email}: {str(e)}")

    summary = {
        "success": failed_count == 0,
        "sent": sent_count,
        "failed": failed_count,
        "details": details,
    }

    logger.info(f"Second batch ambassador email summary: {summary}")
    return summary
