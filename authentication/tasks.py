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
from .utils import get_next_payout_date, calculate_daily_roi, send_push_notification
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
                next_payout = get_next_payout_date(today)

                send_push_notification(
                    user,
                    title="💹 Your Funds Have Grown!",
                    message=(
                        f"Hi {user.first_name}, your funds have earned returns. "
                        f"Savings: ₦{savings_roi:,.2f}, Investment: ₦{investment_roi:,.2f}. "
                        f"Next payout: {next_payout.day}{'st' if next_payout.day == 1 else 'th'} "
                        f"{next_payout.strftime('%B %Y')} 🎉"
                    ),
                    data={
                        "type": "DAILY_ROI",
                        "total_roi": float(total_roi),
                        "date": today.isoformat(),
                        "next_payout": next_payout.isoformat(),
                    },
                )

                processed_count += 1
        except Exception as e:
            logger.error(f"ROI error for user {user.id}: {e}")

    return f"✅ Daily ROI accrued for {processed_count} users."


@shared_task
def process_quarterly_payouts_task_fixed():
    """
    Process quarterly ROI payouts for the previous quarter.
    Uses the new send_generic_email which handles batching automatically.
    """
    from django.utils import timezone
    from .models import CustomUser, ROITransaction, Transaction
    from .utils import send_push_notification, send_generic_email
    from decimal import Decimal
    from django.db import transaction as db_transaction
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

    users = CustomUser.objects.filter(is_active=True, is_banned=False)

    total_paid_users = 0
    total_amount = Decimal("0.00")

    # Collect all recipients for batch sending
    all_recipients = []

    for user in users.iterator():
        try:
            unpaid_roi = ROITransaction.objects.filter(
                user=user,
                accrued_date__range=[quarter_start, quarter_end],
                is_paid_out=False,
            )

            total_payout = sum(t.amount for t in unpaid_roi)
            if total_payout <= 0:
                continue

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

                # Send push notification immediately
                savings_roi = sum(
                    t.amount for t in unpaid_roi if t.roi_type == "SAVINGS"
                )
                investment_roi = sum(
                    t.amount for t in unpaid_roi if t.roi_type == "INVESTMENT"
                )

                send_push_notification(
                    user,
                    title=f"🎉 {quarter_label} Dividends Paid! (₦{total_payout:,.2f})",
                    message=f"{user.first_name}, ₦{total_payout:,.2f} has been added to your wallet as dividends for {quarter_label}!"
                    f"(Savings: ₦{savings_roi:,.2f}, Investment: ₦{investment_roi:,.2f})",
                    data={
                        "type": "QUARTERLY_PAYOUT",
                        "amount": float(total_payout),
                        "period": quarter_label,
                    },
                )

                total_paid_users += 1
                total_amount += Decimal(total_payout)

                # Add to batch list
                all_recipients.append(
                    {
                        "email": user.email,
                        "subject": f"🎉 {user.first_name}, ₦{total_payout:,.2f} Has Been Added to Your Wallet!",
                        "message": (
                            f"Hi {user.first_name},<br><br>"
                            f"Your ROI of ₦{total_payout:,.2f} has been credited to your MyFund wallet for ({quarter_label})!<br>"
                            f"(Savings: ₦{savings_roi:,.2f}, Investment: ₦{investment_roi:,.2f})<br><br>"
                            "Thank you for using MyFund. Keep growing your funds to earn more in the next quarter! 🚀"
                        ),
                    }
                )

        except Exception as e:
            logger.error(f"Error processing user {user.email}: {e}")
            continue

    # Send all emails using the smart function (will batch if >30)
    if all_recipients:
        logger.info(
            f"📧 Preparing to send quarterly payout emails to {len(all_recipients)} users"
        )

        # Send emails in one go - send_generic_email will handle batching
        # We need to send individually since each has personalized subject/message
        email_results = []
        for recipient_data in all_recipients:
            result = send_generic_email(
                subject=recipient_data["subject"],
                message=recipient_data["message"],
                recipient_list=[recipient_data["email"]],
                from_email="MyFund <info@myfundmobile.com>",
            )
            email_results.append(result)

        # Log summary
        successful_sends = sum(
            1 for r in email_results if r.get("status") in ["completed", "queued"]
        )
        logger.info(
            f"📊 Quarterly payout: {successful_sends}/{len(all_recipients)} email sends initiated"
        )

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


@shared_task(bind=True, max_retries=3, rate_limit="45/h")  # ← RATE LIMIT ADDED HERE
def send_namecheap_safe_email_task(
    self, emails, from_email, batch_size=15, delay_seconds=2
):
    """
    Namecheap-safe email sending: MAX 45 emails per hour
    For 3000 users: Will take ~67 hours (2.8 days)
    """
    total_emails = len(emails)
    sent_count = 0
    failed_emails = []

    logger.info(
        f"🛡️ Namecheap-safe: Processing {total_emails} emails in ultra-safe mode"
    )

    # Process emails one by one with delays
    for i, email_data in enumerate(emails):
        try:
            # Extract email data
            to_email = email_data.get("to", "")
            subject = email_data.get("subject", "")
            plain_message = email_data.get("plain_message", "")
            html_message = email_data.get("html_message", "")

            if not to_email:
                logger.warning("Skipping email with no recipient")
                continue

            # Send email
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=from_email,
                recipient_list=[to_email],
                html_message=html_message,
                fail_silently=False,
            )

            sent_count += 1

            # Log progress every 5 emails
            if (i + 1) % 5 == 0:
                logger.info(f"✅ Sent {i+1}/{total_emails} emails in this batch")

            # Critical: Delay between emails to stay under Namecheap limit
            # 2 seconds between emails = 30 emails/minute max = safe
            time.sleep(delay_seconds)

        except Exception as e:
            error_info = {"email": to_email, "error": str(e)}
            failed_emails.append(error_info)
            logger.error(f"❌ Email failed for {to_email}: {e}")

            # If it's a rate limit error, wait longer and retry
            if "rate limit" in str(e).lower() or "quota" in str(e).lower():
                logger.warning(f"⚠️ Rate limit detected, waiting 5 minutes...")
                time.sleep(300)  # Wait 5 minutes

                try:
                    # Retry this specific email
                    self.retry(countdown=300, max_retries=2)
                except self.MaxRetriesExceededError:
                    logger.error(f"Max retries exceeded for {to_email}")
                    continue

    logger.info(f"📊 Namecheap-safe batch complete: {sent_count}/{total_emails} sent")

    return {
        "sent": sent_count,
        "failed": len(failed_emails),
        "total": total_emails,
        "batch_size": batch_size,
        "delay_seconds": delay_seconds,
        "failed_emails": failed_emails if failed_emails else None,
    }


@shared_task(bind=True, max_retries=3, rate_limit="100/h")  # For small batches
def send_bulk_email_task(self, emails, from_email, batch_size=30, delay_seconds=60):
    """
    For smaller batches (<100): Faster but still Namecheap-safe
    """
    total_emails = len(emails)
    sent_count = 0
    failed_emails = []

    logger.info(f"📦 Processing {total_emails} emails (small batch mode)")

    # Process in very small batches for Namecheap
    for i in range(0, total_emails, batch_size):
        batch = emails[i : i + batch_size]
        batch_number = (i // batch_size) + 1
        total_batches = (total_emails - 1) // batch_size + 1

        logger.info(
            f"📬 Processing batch {batch_number}/{total_batches} ({len(batch)} emails)"
        )

        batch_sent = 0
        batch_failed = []

        for email_data in batch:
            try:
                to_email = email_data.get("to", "")
                subject = email_data.get("subject", "")
                plain_message = email_data.get("plain_message", "")
                html_message = email_data.get("html_message", "")

                if not to_email:
                    continue

                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[to_email],
                    html_message=html_message,
                    fail_silently=False,
                )

                sent_count += 1
                batch_sent += 1

                # Delay between emails within batch
                time.sleep(2)  # 2 seconds between emails

            except Exception as e:
                error_info = {"email": to_email, "error": str(e)}
                failed_emails.append(error_info)
                batch_failed.append(error_info)
                logger.error(f"❌ Email failed for {to_email}: {e}")

        logger.info(f"✅ Batch {batch_number} complete: {batch_sent}/{len(batch)} sent")

        # Long delay between batches for Namecheap safety
        if i + batch_size < total_emails:
            logger.info(f"⏳ Waiting {delay_seconds}s before next batch...")
            time.sleep(delay_seconds)

    logger.info(f"📊 Bulk email complete: {sent_count}/{total_emails} sent")

    result = {
        "sent": sent_count,
        "failed": len(failed_emails),
        "total": total_emails,
        "batch_size": batch_size,
        "delay_seconds": delay_seconds,
    }

    if failed_emails:
        result["failed_emails"] = failed_emails

    return result


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
