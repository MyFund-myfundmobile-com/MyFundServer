# myapp/tasks.py

from celery import shared_task
from authentication import models
from datetime import datetime
from django.db.models import F
import logging

logger = logging.getLogger(__name__)

@shared_task
def refund_contributions_if_goal_not_reached():
    current_time = datetime.now()

    # Find groups that didn't reach the goal before the deadline
    groups_to_refund = models.Group.objects.filter(
        total_raised__lt=F('goal_amount'),
        deadline__lt=current_time,
        status="active"
    )

    for group in groups_to_refund:
        # Refund each contribution
        for contribution in group.contributors.all():
            contribution_amount = models.Contribution.objects.filter(group=group, user=contribution).first().amount
            source = models.Contribution.objects.filter(group=group, user=contribution).first().source

            if source == "savings":
                contribution.savings += contribution_amount
            elif source == "investment":
                contribution.investment += contribution_amount
            elif source == "wallet":
                contribution.wallet += contribution_amount

            # Mark as refunded
            models.Contribution.objects.filter(group=group, user=contribution).update(payment_status="Refunded")

        # Reset the group and mark it as failed
        group.total_raised = 0
        group.status = "failed"
        group.save()
    
    logger.info("Refund task completed.")
