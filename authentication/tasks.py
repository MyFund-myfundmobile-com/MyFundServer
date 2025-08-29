# tasks.py
from celery import shared_task
from django.utils import timezone
from .models import TargetSavings
import logging
from django.db import models
from .utils import send_generic_email, send_push_notification
from datetime import timedelta

logger = logging.getLogger(__name__)


@shared_task
def process_target_savings_deductions():
    """Celery task to process all due target savings deductions"""
    now = timezone.now()

    # Get targets that are due for processing based on next_deduction
    due_targets = TargetSavings.objects.filter(
        is_active=True,
        is_cancelled=False,
        next_deduction__lte=now,
        current_amount__lt=models.F("target_amount"),
    ).select_related("user")

    logger.info(f"Found {due_targets.count()} target savings due for processing")

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
            f"'{target.name}' with ₦{target.current_amount:,}.<br><br>"
            "You can now withdraw or reinvest these funds. 🥂"
        )
        send_generic_email(subject, message, recipient_list=user.email)

        # Push notification
        send_push_notification(
            user,
            title="🎉 Target Savings Completed!",
            message=f"Congrats! '{target.name}' reached ₦{target.current_amount:,}.",
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
            subject = f"Retry Deduction for '{target.name}' Successful ✅"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"We retried your Target Savings deduction for '{target.name}' "
                f"and successfully deducted ₦{target.monthly_payment:,}.<br><br>"
                f"New balance: ₦{target.current_amount:,}."
            )
            send_generic_email(subject, message, recipient_list=user.email)

            send_push_notification(
                user,
                title="Retry Successful ✅",
                message=f"₦{target.monthly_payment:,} was successfully deducted for '{target.name}'.",
                data={"target_id": target.id, "type": "RETRY_SUCCESS"},
            )

    return {"retry_count": retry_targets.count()}
