from celery import shared_task
from django.utils import timezone
from .models import TargetSavings
import logging

logger = logging.getLogger(__name__)


@shared_task
def run_daily_target_savings_deductions():
    """Celery beat task to auto-deduct savings"""
    now = timezone.now()
    due_targets = TargetSavings.objects.filter(
        is_active=True, is_cancelled=False, next_deduction__lte=now
    )

    logger.info(f"Processing {due_targets.count()} due target savings...")

    for target in due_targets:
        success = target.process_deduction()
        if success:
            logger.info(
                f"Deduction success for {target.name} (User: {target.user.email})"
            )
        else:
            logger.warning(
                f"Deduction failed for {target.name} (User: {target.user.email})"
            )
