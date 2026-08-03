# tasks.py
from celery import shared_task
from django.utils import timezone
from .models import TargetSavings
import logging
from django.db import models
from .utils import send_generic_email, send_push_notification, create_transaction
from datetime import timedelta
from django.conf import settings
from .utils import create_transaction

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

            user = target.user

            create_transaction(
                user=user,
                amount=target.current_amount,
                transaction_type="credit",
                status="confirmed",
                source="WALLET",
                credited_to="WALLET",
                description=f"Refund for incomplete target '{target.name}'",
            )

            target.is_cancelled = True
            targets_to_update.append(target)

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
    if targets_to_update:
        TargetSavings.objects.bulk_update(
            targets_to_update, ["is_cancelled"], batch_size=500
        )
        logger.info(f"✅ Marked {len(targets_to_update)} targets as cancelled")

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
def expire_groupbuys_task():
    """
    Celery counterpart to `python manage.py expire_groupbuys`. Scheduled
    daily via app.conf.beat_schedule in myfundproject/celery.py
    ("expire-overdue-groupbuys-daily") - runs on the existing Beat/worker,
    no extra infrastructure. Can also be triggered manually via the
    management command or the staff-only admin endpoint for testing.
    """
    from .utils import expire_overdue_groupbuys

    result = expire_overdue_groupbuys(dry_run=False)
    logger.info(
        f"✅ Expired {result['expired_count']} GroupBuy(s), "
        f"refunded ₦{result['total_refunded']:,.2f}, "
        f"₦{result['total_service_charge']:,.2f} service charge collected."
    )
    return result["expired_count"]


@shared_task
def auto_distribute_groupbuy_income_task():
    """
    Scheduled daily via app.conf.beat_schedule ("auto-distribute-groupbuy-
    income-daily"). Cheap to run daily even though payouts are monthly: the
    sweep itself checks each completed Group's last GroupIncomeEvent and
    only actually creates a new event (and moves money) once that group's
    monthly period has elapsed, so most days it's a fast no-op query.
    """
    from .utils import auto_distribute_groupbuy_income

    result = auto_distribute_groupbuy_income(dry_run=False)
    for event in result["events"]:
        if event.get("event_id"):
            distribute_groupbuy_income_notifications.delay(event["event_id"])

    logger.info(
        f"✅ Auto-distributed GroupBuy income for {result['distributed_count']} "
        f"group(s), ₦{result['total_distributed']:,.2f} total."
    )
    return result["distributed_count"]


@shared_task
def send_groupbuy_deadline_reminders_task():
    """
    Scheduled daily via app.conf.beat_schedule ("groupbuy-deadline-reminders-
    daily"). Group.reminder_sent guards against re-notifying the same group
    on subsequent daily runs within its 3-day pre-deadline window.
    """
    from .utils import send_groupbuy_deadline_reminders

    result = send_groupbuy_deadline_reminders(dry_run=False)
    logger.info(
        f"✅ Sent GroupBuy deadline reminders for {result['groups_notified']} "
        f"group(s), {result['total_notified']} push(es) sent."
    )
    return result["groups_notified"]


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
    """Safety-net sweep for targets that reached their goal amount without
    going through process_target_savings_deductions - e.g. a target fully
    funded by a single upfront payment at creation, which that task's query
    skips (current_amount is not < target_amount, so there's nothing to
    "deduct"). Delegates to target.process_deduction(), which now detects
    the already-funded state and completes it via the shared
    _complete_target() method - this must never independently flip
    is_active without awarding the 15% completion bonus the way it
    previously did here.
    """
    completed_targets = TargetSavings.objects.filter(
        is_active=True,
        is_cancelled=False,
        current_amount__gte=models.F("target_amount"),
    ).select_related("user")

    processed_count = 0
    for target in completed_targets:
        try:
            if target.process_deduction():
                processed_count += 1
        except Exception as e:
            logger.error(
                f"Error completing target {target.id} via safety-net sweep: {e}"
            )

    return {"completed_count": processed_count}


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
                subject=subject,
                message=message,
                recipient_list=[user.email],
                from_email=settings.DEFAULT_FROM_EMAIL,
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


# HELPER FOR RELEASE_QUARTERLY_ROI
from datetime import date


def get_previous_quarter():
    """
    Returns:
        (quarter_start, quarter_end, quarter_label)

    Examples:
        Jul 1 2026 -> (Apr 1 2026, Jun 30 2026, "Q2 2026")
        Oct 1 2026 -> (Jul 1 2026, Sep 30 2026, "Q3 2026")
        Jan 1 2027 -> (Oct 1 2026, Dec 31 2026, "Q4 2026")
        Apr 1 2026 -> (Jan 1 2026, Mar 31 2026, "Q1 2026")
    """

    today = date.today()

    if today.month in (1, 2, 3):
        year = today.year - 1
        quarter = 4
    elif today.month in (4, 5, 6):
        year = today.year
        quarter = 1
    elif today.month in (7, 8, 9):
        year = today.year
        quarter = 2
    else:
        year = today.year
        quarter = 3

    if quarter == 1:
        return (
            date(year, 1, 1),
            date(year, 3, 31),
            f"Q1 {year}",
        )

    if quarter == 2:
        return (
            date(year, 4, 1),
            date(year, 6, 30),
            f"Q2 {year}",
        )

    if quarter == 3:
        return (
            date(year, 7, 1),
            date(year, 9, 30),
            f"Q3 {year}",
        )

    return (
        date(year, 10, 1),
        date(year, 12, 31),
        f"Q4 {year}",
    )


@shared_task
def release_quarterly_roi(test_mode=True):
    """
    Release accrued quarterly ROI to users' wallets.
    Only credits ROITransaction records that have been calculated but not yet paid out.
    Emails are staggered via Celery to avoid Namecheap rate limits.
    """
    from decimal import Decimal
    from datetime import date
    from django.db import transaction as db_transaction
    from django.db.models import Sum
    from .models import CustomUser, ROITransaction, Transaction
    from .utils import send_push_notification
    from .tasks import send_single_email_task

    from datetime import date

    QUARTER_START = date(2026, 4, 1)
    QUARTER_END = date(2026, 6, 30)
    from datetime import date

    today = date.today()
    year = today.year

    # Determine quarter being paid (based on fixed accrual window)
    if QUARTER_START.month == 4:
        QUARTER_LABEL = f"Q2 {QUARTER_START.year}"
        NEXT_PAYOUT_LABEL = f"October {QUARTER_START.year}"

    elif QUARTER_START.month == 1:
        QUARTER_LABEL = f"Q1 {QUARTER_START.year}"
        NEXT_PAYOUT_LABEL = f"July {QUARTER_START.year}"

    elif QUARTER_START.month == 7:
        QUARTER_LABEL = f"Q3 {QUARTER_START.year}"
        NEXT_PAYOUT_LABEL = f"January {QUARTER_START.year + 1}"

    elif QUARTER_START.month == 10:
        QUARTER_LABEL = f"Q4 {QUARTER_START.year}"
        NEXT_PAYOUT_LABEL = f"April {QUARTER_START.year + 1}"

    TEST_EMAILS = [
        # "valuepluspublishing@gmail.com",
        # "valueplusrecords@gmail.com",
        "tolulopeahmed@gmail.com",
    ]

    logger.info(f"🚀 release_quarterly_roi started. test_mode={test_mode}")

    qs = (
        ROITransaction.objects.filter(
            accrued_date__range=[QUARTER_START, QUARTER_END],
            is_paid_out=False,
        )
        .values("user_id")
        .annotate(
            total_payout=Sum("amount"),
            savings_roi=Sum("amount", filter=models.Q(roi_type="SAVINGS")),
            investment_roi=Sum("amount", filter=models.Q(roi_type="INVESTMENT")),
        )
        .filter(total_payout__gt=0)
    )

    if test_mode:
        test_user_ids = CustomUser.objects.filter(email__in=TEST_EMAILS).values_list(
            "id", flat=True
        )
        qs = qs.filter(user_id__in=test_user_ids)
        logger.info(f"🧪 TEST MODE — restricted to {TEST_EMAILS}")

    if not qs.exists():
        msg = "No unpaid ROI found for the quarter."
        logger.info(msg)
        return msg

    processed = 0
    skipped = 0
    errors = 0

    for row in qs:
        user_id = row["user_id"]
        total_payout = Decimal(str(row["total_payout"] or 0))
        savings_roi = Decimal(str(row["savings_roi"] or 0))
        investment_roi = Decimal(str(row["investment_roi"] or 0))

        if total_payout <= 0:
            skipped += 1
            continue

        try:
            user = CustomUser.objects.get(id=user_id)

            with db_transaction.atomic():
                # 1. Credit wallet
                create_transaction(
                    user=user,
                    amount=total_payout,
                    transaction_type="credit",
                    source="WALLET",
                    credited_to="WALLET",
                    status="confirmed",
                    service_charge=Decimal("0.00"),
                    description=f"Dividends: {QUARTER_LABEL} ROI",
                )

                # 3. Mark ROI records as paid
                ROITransaction.objects.filter(
                    user=user,
                    accrued_date__range=[QUARTER_START, QUARTER_END],
                    is_paid_out=False,
                ).update(is_paid_out=True, payout_date=date.today())

            # 4. Push notification (immediate)
            send_push_notification(
                user=user,
                title=f"🎉 {QUARTER_LABEL} Dividends Paid!",
                message=(
                    f"Congratulations {user.first_name}, ₦{total_payout:,.2f} has been added to "
                    f"your wallet as dividends for {QUARTER_LABEL}! "
                    f"(Savings: ₦{savings_roi:,.2f}, Investment: ₦{investment_roi:,.2f}). "
                    f"Keep growing your funds for better ROI by the next payout by {NEXT_PAYOUT_LABEL}."
                ),
                data={
                    "type": "QUARTERLY_PAYOUT",
                    "amount": float(total_payout),
                    "period": QUARTER_LABEL,
                },
            )

            # 5. Email (staggered via Celery — 72s apart = ~50/hour, safe for Namecheap)
            email_body = (
                f"Hi {user.first_name},<br><br>"
                f"Your quarterly ROI has been added to your MyFund Wallet as dividends for <b>{QUARTER_LABEL}</b>.<br><br>"
                f"<b>Total ROI credited:</b> ₦{total_payout:,.2f}<br>"
                f"<b>Savings ROI:</b> ₦{savings_roi:,.2f}<br>"
                f"<b>Investment ROI:</b> ₦{investment_roi:,.2f}<br><br>"
                f"This payout covers your earnings for {QUARTER_LABEL}.<br><br>"
                f"The next payout will be in {NEXT_PAYOUT_LABEL}. Keep growing your funds.<br><br>"
                f"Thank you for using MyFund.<br><br>"
                f"The MyFund Team"
            )

            send_generic_email(
                subject=f"Quarterly ROI Paid! ({QUARTER_LABEL})",
                message=email_body,
                recipient_list=[user.email],
                from_email="MyFund <noreply@mg.myfundmobile.com>",
                use_celery_threshold=0,  # force direct send
            )

            processed += 1
            logger.info(
                f"✅ Credited & email queued for {user.email} (countdown: {processed * 72}s)"
            )

        except Exception as e:
            errors += 1
            logger.exception(f"❌ FULL ERROR for user {user_id}: {e}")
            print(f"❌ FULL ERROR for user {user_id}: {repr(e)}")

    result = (
        f"✅ release_quarterly_roi complete. "
        f"Processed: {processed}, Skipped: {skipped}, Errors: {errors}"
    )
    logger.info(result)
    return result


@shared_task
def distribute_groupbuy_income_notifications(event_id):
    """
    Sends a push notification for a GroupBuy income distribution that has
    already been credited to members' wallets. Dispatched after the
    money-moving transaction commits (see admin_views.distribute_groupbuy_income
    and utils.auto_distribute_groupbuy_income) so a slow/failed notification
    can never block or roll back a payout.

    Push-only, deliberately: this fires for every member on every monthly
    payout once auto-distribution is live, so it's a routine, expected,
    non-urgent event. Members can always see the full breakdown via
    GET /user/groupbuy/income-history/ - an email per member per month here
    would just be recurring cost/latency for something push already covers.
    """
    from .models import GroupIncomeDistribution
    from .utils import send_push_notification

    distributions = GroupIncomeDistribution.objects.filter(
        income_event_id=event_id
    ).select_related("user", "income_event", "income_event__group__property")

    processed = 0
    errors = 0

    for dist in distributions:
        try:
            user = dist.user
            event = dist.income_event
            property_name = event.group.property.name

            send_push_notification(
                user=user,
                title="💰 GroupBuy Income Received!",
                message=(
                    f"₦{dist.amount:,.2f} has been added to your wallet from "
                    f"{property_name} ({dist.ownership_percentage}% ownership)."
                ),
                data={
                    "type": "GROUPBUY_INCOME",
                    "amount": float(dist.amount),
                    "group_id": str(event.group_id),
                },
            )
            processed += 1
        except Exception as e:
            errors += 1
            logger.exception(
                f"❌ Failed to notify user {dist.user_id} for GroupIncomeDistribution {dist.id}: {e}"
            )

    result = f"✅ distribute_groupbuy_income_notifications complete for event {event_id}. Processed: {processed}, Errors: {errors}"
    logger.info(result)
    return result


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
                    from_email="MyFund <info@mg.myfundmobile.com>",
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
                    from_email="MyFund <info@mg.myfundmobile.com>",
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
                subject, message, "MyFund <info@mg.myfundmobile.com>", [user.email]
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


import logging

from celery import shared_task
from django.utils import timezone

from authentication.models import WithdrawalsRequestToAdmin, CustomUser
from .utils import (
    process_scheduled_withdrawal,
    send_generic_email,
    send_push_notification,
)

logger = logging.getLogger(__name__)

ADMIN_ALERT_EMAILS = [
    "tolulopeahmed@gmail.com",
    "janet.adegbenro@gmail.com",
]


def alert_admins_of_failed_scheduled_withdrawals(failed_withdrawals):
    if not failed_withdrawals:
        return

    failed_count = len(failed_withdrawals)

    rows = []
    for item in failed_withdrawals:
        rows.append(
            f"Transaction ID: {item['transaction_id']}<br>"
            f"User: {item['user_email']}<br>"
            f"Amount: ₦{item['amount']}<br>"
            f"Error: {item['error']}<br>"
            f"<br>"
        )

    message = (
        f"Hello Admin,<br><br>"
        f"{failed_count} scheduled withdrawal(s) failed during Celery processing.<br><br>"
        f"Please check Django Admin, filter by overdue scheduled withdrawals, "
        f"and force credit where necessary.<br><br>"
        f"{''.join(rows)}"
        f"MyFund System"
    )

    try:
        send_generic_email(
            subject="[ACTION REQUIRED] Scheduled Withdrawal Failed",
            message=message,
            from_email="MyFund <info@mg.myfundmobile.com>",
            recipient_list=ADMIN_ALERT_EMAILS,
        )
    except Exception:
        logger.exception("Failed to send scheduled withdrawal failure email to admins")

    admin_users = CustomUser.objects.filter(email__in=ADMIN_ALERT_EMAILS)

    for admin_user in admin_users:
        try:
            send_push_notification(
                user=admin_user,
                title="Scheduled Withdrawal Failed",
                message=(
                    f"{failed_count} scheduled withdrawal(s) failed in Celery. "
                    f"Check overdue withdrawals in admin."
                ),
                data={
                    "type": "scheduled_withdrawal_failed",
                    "failed_count": str(failed_count),
                },
                notif_type="SUCCESS",
            )
        except Exception:
            logger.exception(
                "Failed to send scheduled withdrawal failure push to admin %s",
                admin_user.email,
            )


@shared_task(bind=True, max_retries=3)
def process_due_scheduled_withdrawals(self):
    today = timezone.localdate()

    withdrawals = WithdrawalsRequestToAdmin.objects.select_related("user").filter(
        withdrawal_type="scheduled",
        scheduled_processing_date__lte=today,
        is_processed=False,
    )

    failed_withdrawals = []
    processed_count = 0

    for withdrawal in withdrawals:
        try:
            result = process_scheduled_withdrawal(
                withdrawal,
                triggered_by="celery",
            )

            if result in ["processed", "already_credited", "already_processed"]:
                processed_count += 1

        except Exception as e:
            failed_withdrawals.append(
                {
                    "pk": withdrawal.pk,
                    "transaction_id": withdrawal.transaction_id,
                    "user_email": withdrawal.user.email,
                    "amount": withdrawal.total_amount or withdrawal.amount,
                    "error": str(e),
                }
            )

            logger.exception(
                "Failed scheduled withdrawal %s: %s",
                withdrawal.transaction_id,
                str(e),
            )

    if failed_withdrawals:
        # Alert admins only on the first failed attempt to avoid repeated emails/push alerts.
        if self.request.retries == 0:
            alert_admins_of_failed_scheduled_withdrawals(failed_withdrawals)

        failed_ids = [str(item["pk"]) for item in failed_withdrawals]

        raise self.retry(
            exc=Exception(f"Failed scheduled withdrawals: {', '.join(failed_ids)}"),
            countdown=60,
        )

    return f"Processed {processed_count} due scheduled withdrawal(s)"


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


# from celery import shared_task
# import time
# import logging
# from django.core.mail import send_mail
# from django.template.loader import render_to_string
# from django.utils.html import strip_tags

# logger = logging.getLogger(__name__)
# from celery import shared_task
# from django.core.mail import send_mail, get_connection
# from django.conf import settings
# import time
# import logging

# logger = logging.getLogger(__name__)


# @shared_task(bind=True, max_retries=3)
# def send_namecheap_safe_email_task(
#     self, emails, from_email, reuse_connection=False, batch_size=15, delay_seconds=2
# ):
#     """
#     Namecheap-safe email sending with single SMTP connection per batch.
#     """
#     total_emails = len(emails)
#     sent_count = 0
#     failed_emails = []

#     logger.info(
#         f"🛡️ Namecheap-safe: Processing {total_emails} emails in ultra-safe mode"
#     )

#     # Open SMTP connection if reuse_connection is True
#     connection = None
#     if reuse_connection:
#         connection = get_connection(
#             username=from_email,
#             password=settings.EMAIL_HOST_PASSWORD,
#             fail_silently=False,
#         )
#         connection.open()

#     try:
#         for i, email_data in enumerate(emails):
#             try:
#                 to_email = email_data.get("to", "")
#                 subject = email_data.get("subject", "")
#                 plain_message = email_data.get("plain_message", "")
#                 html_message = email_data.get("html_message", "")

#                 if not to_email:
#                     logger.warning("Skipping email with no recipient")
#                     continue

#                 send_mail(
#                     subject=subject,
#                     message=plain_message,
#                     from_email=from_email,
#                     recipient_list=[to_email],
#                     html_message=html_message,
#                     fail_silently=False,
#                     connection=connection,  # <-- USE the connection here
#                     timeout=30,  # optional, prevents hanging
#                 )

#                 sent_count += 1

#                 if (i + 1) % 5 == 0:
#                     logger.info(f"✅ Sent {i+1}/{total_emails} emails in this batch")

#                 time.sleep(delay_seconds)

#             except Exception as e:
#                 error_info = {"email": to_email, "error": str(e)}
#                 failed_emails.append(error_info)
#                 logger.error(f"❌ Email failed for {to_email}: {e}")

#                 # Retry if rate limit
#                 if "rate limit" in str(e).lower() or "quota" in str(e).lower():
#                     logger.warning(f"⚠️ Rate limit detected, waiting 5 minutes...")
#                     time.sleep(300)
#                     try:
#                         self.retry(countdown=300, max_retries=2)
#                     except self.MaxRetriesExceededError:
#                         logger.error(f"Max retries exceeded for {to_email}")
#                         continue

#     finally:
#         if connection:
#             connection.close()  # <-- close connection at the end

#     logger.info(f"📊 Namecheap-safe batch complete: {sent_count}/{total_emails} sent")

#     return {
#         "sent": sent_count,
#         "failed": len(failed_emails),
#         "total": total_emails,
#         "batch_size": batch_size,
#         "delay_seconds": delay_seconds,
#         "failed_emails": failed_emails if failed_emails else None,
#     }


from celery import shared_task
import time
import logging
from django.core.mail import send_mail

logger = logging.getLogger(__name__)

from celery import shared_task
import logging
import time
import os
import resend

logger = logging.getLogger(__name__)

# ===== RESEND INIT =====
resend.api_key = os.environ.get("RESEND_API_KEY")


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
                # ===== RESEND REPLACEMENT (NO SMTP) =====
                resend.Emails.send(
                    {
                        "from": from_email or "MyFund <noreply@myfundmobile.com>",
                        "to": [e["to"]],
                        "subject": e["subject"],
                        "html": e["html_message"],
                    }
                )

                sent += 1
                logger.info(f"✅ Sent via Resend: {e['to']}")

            except Exception as ex:
                failed.append({"email": e["to"], "error": str(ex)})
                logger.error(f"❌ Failed {e['to']}: {ex}")

        if i + batch_size < total:
            logger.info(f"⏳ Sleeping {delay_seconds}s before next batch")
            time.sleep(delay_seconds)

    logger.info(f"📊 Done: {sent}/{total} sent")

    return {
        "sent": sent,
        "failed": len(failed),
        "failed_emails": failed,
        "total": total,
    }


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


@shared_task
def apply_withholding_tax_q1_2026(test_mode=True):
    """
    Apply 10% Withholding Tax on Q1 2026 dividend payouts.
    Debits wallet and creates a transaction record only — no push, no email.
    """
    from decimal import Decimal, ROUND_HALF_UP
    from datetime import date
    from django.db import transaction as db_transaction
    from django.db.models import Sum
    from .models import CustomUser, Transaction, ROITransaction

    from dateutil.relativedelta import relativedelta

    QUARTER_START = date(2026, 4, 1)
    QUARTER_END = date(2026, 6, 30)
    QUARTER_LABEL = "Q2 2026"
    WHT_RATE = Decimal("0.10")

    TEST_EMAILS = [
        # "company@myfundmobile.com",
        # "valuepluspublishing@gmail.com",
        "tolulopeahmed@gmail.com",
    ]

    logger.info(f"🚀 apply_withholding_tax_q1_2026 started. test_mode={test_mode}")

    # Get all users who were paid out this quarter
    qs = (
        ROITransaction.objects.filter(
            accrued_date__range=[QUARTER_START, QUARTER_END],
            is_paid_out=True,
        )
        .values("user_id")
        .annotate(total_payout=Sum("amount"))
        .filter(total_payout__gt=0)
    )

    if test_mode:
        test_user_ids = CustomUser.objects.filter(email__in=TEST_EMAILS).values_list(
            "id", flat=True
        )
        qs = qs.filter(user_id__in=test_user_ids)
        logger.info(f"🧪 TEST MODE — restricted to {TEST_EMAILS}")

    if not qs.exists():
        msg = "No paid ROI found for the quarter."
        logger.info(msg)
        return msg

    processed = 0
    skipped = 0
    errors = 0

    for row in qs:
        user_id = row["user_id"]
        total_payout = Decimal(str(row["total_payout"] or 0))
        wht_amount = (total_payout * WHT_RATE).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

        if wht_amount <= 0:
            skipped += 1
            continue

        # Skip if WHT already applied for this user this quarter
        already_charged = Transaction.objects.filter(
            user_id=user_id,
            transaction_type="debit",
            status="confirmed",
            source="WALLET",
            description__icontains=f"WHT|{QUARTER_LABEL}",
        ).exists()

        if already_charged:
            logger.info(f"⏭️ WHT already applied for user {user_id}, skipping.")
            skipped += 1
            continue

        try:
            user = CustomUser.objects.get(id=user_id)

            with db_transaction.atomic():
                # 1. Debit wallet
                create_transaction(
                    user=user,
                    amount=wht_amount,
                    transaction_type="debit",
                    source="WALLET",
                    status="confirmed",
                    description=f"WHT|{QUARTER_LABEL}|10%",
                )

            processed += 1
            logger.info(f"✅ WHT ₦{wht_amount:,.2f} debited from {user.email}")

        except Exception as e:
            errors += 1
            logger.error(f"❌ Error applying WHT for user {user_id}: {e}")

    result = (
        f"✅ apply_withholding_tax_q1_2026 complete. "
        f"Processed: {processed}, Skipped: {skipped}, Errors: {errors}"
    )
    logger.info(result)
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
            from_email="MyFund <info@mg.myfundmobile.com>",
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
            from_email="MyFund <info@mg.myfundmobile.com>",
            recipient_list=["info@mg.myfundmobile.com", "company@myfundmobile.com"],
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
        "MyFund <info@mg.myfundmobile.com>",
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
        "MyFund <info@mg.myfundmobile.com>",
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


import logging
from celery import shared_task

from .utils import autosubmit_missing_ambassador_reports_for_previous_month

logger = logging.getLogger(__name__)


@shared_task
def autosubmit_missing_ambassador_reports_task():
    """
    Runs after month rollover and auto-submits missing ambassador reports
    using prefilled metrics only.
    """
    result = autosubmit_missing_ambassador_reports_for_previous_month()
    logger.info(f"Ambassador autosubmit result: {result}")
    return result


def send_batch_b_ambassador_email(test=True):
    from authentication.utils import send_generic_email

    subject = "🎉Congratulations! You’ve Been Selected for MyFund Ambassador Program"

    message = """
    <p>Hi {first_name},</p>

    <p><strong>Congratulations!</strong></p>

    <p>We’re excited to inform you that you have been selected for <strong>Batch B of the MyFund Ambassador Program (Cohort 3)</strong>.</p>

    <p>After reviewing applications, your profile stood out, and we’re confident in your potential to grow, contribute, and make meaningful impact within the MyFund community.</p>

    <p>As part of the next step, you are required to join the official ambassadors group where all updates, onboarding details, and activities will be shared.</p>

    <p>
    <a href="https://chat.whatsapp.com/K6ydqeE0zKuGX0Sek87tkW"
        style="background:#4c28bc;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:8px;display:inline-block;font-weight:600;">
        Join Ambassadors Group
    </a>
    </p>

    <p><strong>Onboarding Video:</strong></p>

    <p>
    <a href="https://youtu.be/bTb3I6GAmFA?feature=shared" target="_blank">
        <img src="https://img.youtube.com/vi/bTb3I6GAmFA/maxresdefault.jpg"
            alt="Watch onboarding video"
            style="width:100%;max-width:500px;border-radius:12px;display:block;margin:auto;" />
    </a>
    </p>

    <p style="text-align:center;">
    <a href="https://youtu.be/bTb3I6GAmFA?feature=shared"
        style="background:#4c28bc;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:8px;display:inline-block;font-weight:600;">
        ▶ Watch Onboarding Video
    </a>
    </p>

    <p>Further details and the meeting link will be shared in the group.</p>

    <p>We look forward to having you actively participate as we begin this journey together.</p>

    <p>Welcome on board.</p>

    <p>Best regards,<br>
    Chubi<br>
    DME, MyFund</p>
    """

    test_emails = [
        "josephgideon95@gmail.com",
        "valueplusrecords@gmail.com",
        "janet.adegbenro@gmail.com",
    ]

    batch_b_emails = [
        "ijiwandepaul2020@gmail.com",
        "ozegesilverdiamond@gmail.com",
        "annaliu352@gmail.com",
        "owolabitt@yahoo.com",
    ]

    recipients = test_emails if test else batch_b_emails

    return send_generic_email(
        subject=subject,
        message=message,
        recipient_list=recipients,
        use_celery_threshold=0,
    )


from datetime import timedelta
from django.utils import timezone
from .models import BankTransferRequest, Transaction


def cleanup_abandoned_manual_quicksaves():
    cutoff = timezone.now() - timedelta(hours=24)

    old_requests = BankTransferRequest.objects.filter(
        is_approved=False,
        created_at__lt=cutoff,
    )

    cleaned_count = 0

    for req in old_requests:
        transaction = Transaction.objects.filter(
            user=req.user,
            transaction_id=req.transaction_id,
            status__iexact="pending",
            description__icontains="QuickSave",
        ).first()

        if transaction:
            transaction.status = "abandoned"
            transaction.description = "QuickSave (Abandoned)"
            transaction.save(update_fields=["status", "description"])
            cleaned_count += 1

    return cleaned_count


from celery import shared_task

from authentication.metrics.services import (
    generate_metric_snapshot,
)

from authentication.metrics.push import (
    send_metrics_push,
)


@shared_task
def daily_metrics_task():

    snapshot = generate_metric_snapshot(period_type="daily")

    send_metrics_push(snapshot)


@shared_task
def weekly_metrics_task():

    snapshot = generate_metric_snapshot(period_type="weekly")

    send_metrics_push(snapshot)


@shared_task
def monthly_metrics_task():

    snapshot = generate_metric_snapshot(period_type="monthly")

    send_metrics_push(snapshot)


@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def sync_user_to_brevo(self, user_id):

    from authentication.models import CustomUser
    from authentication.services.brevo_service import sync_contact_to_brevo

    try:
        user = CustomUser.objects.get(id=user_id)

        response = sync_contact_to_brevo(user)

        if response:
            return {"status": "success", "email": user.email}

        raise Exception("Brevo sync failed")

    except Exception as exc:
        raise self.retry(exc=exc)
