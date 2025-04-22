# myapp/tasks.py
from celery import shared_task
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
from decimal import Decimal
import logging
from authentication.models import (
    Group,
    Contribution,
    TargetSavings,
    Transaction,
    CustomUser,
)

logger = logging.getLogger(__name__)


@shared_task
def process_recurring_target_savings():
    """Process recurring deductions for active target savings plans"""
    now = timezone.now()

    active_plans = TargetSavings.objects.filter(
        is_active=True, next_deduction__lte=now, is_cancelled=False
    ).select_related("user")

    for plan in active_plans:
        try:
            with transaction.atomic():
                user = CustomUser.objects.get(id=plan.user.id)
                amount = plan.monthly_payment

                # Check funding source and available balance
                if plan.funding_source == "SAVINGS" and user.savings >= amount:
                    user.savings -= amount
                    source = "savings"
                elif plan.funding_source == "INVESTMENT" and user.investment >= amount:
                    user.investment -= amount
                    source = "investment"
                elif plan.funding_source == "CARD":
                    # Implement your card payment processing logic here
                    # Example: process_card_payment(plan.payment_method, amount)
                    # Temporarily mark as successful for testing
                    card_charge_success = True
                    if not card_charge_success:
                        raise Exception("Card payment failed")
                    source = "card"
                else:
                    logger.warning(f"Insufficient funds for target savings {plan.id}")
                    plan.is_active = False
                    plan.save()
                    continue

                # Update user and plan
                user.save()
                plan.current_amount += amount

                # Create transaction record
                Transaction.objects.create(
                    user=user,
                    transaction_type="debit",
                    status="confirmed",
                    amount=amount,
                    description=f"Recurring {plan.get_frequency_display()} deduction for {plan.name}",
                    service_charge=0,
                    total_amount=amount,
                    target_savings=plan,
                    source=source,
                )

                # Schedule next deduction
                if plan.frequency == "DAILY":
                    plan.next_deduction = now + timedelta(days=1)
                elif plan.frequency == "WEEKLY":
                    plan.next_deduction = now + timedelta(weeks=1)
                else:  # MONTHLY
                    plan.next_deduction = now + timedelta(days=30)

                plan.save()
                logger.info(
                    f"Successfully processed deduction for target savings {plan.id}"
                )

        except Exception as e:
            logger.error(f"Error processing target savings {plan.id}: {str(e)}")
            plan.is_active = False
            plan.save()


@shared_task
def refund_contributions_if_goal_not_reached():
    """Existing group refund task"""
    current_time = timezone.now()

    # Find groups that didn't reach the goal before the deadline
    groups_to_refund = Group.objects.filter(
        total_raised__lt=F("goal_amount"), deadline__lt=current_time, status="active"
    )

    for group in groups_to_refund:
        try:
            with transaction.atomic():
                for contribution in group.contributors.all():
                    contribution_amount = (
                        Contribution.objects.filter(group=group, user=contribution)
                        .first()
                        .amount
                    )

                    source = (
                        Contribution.objects.filter(group=group, user=contribution)
                        .first()
                        .source
                    )

                    user = CustomUser.objects.get(id=contribution.id)
                    if source == "savings":
                        user.savings += contribution_amount
                    elif source == "investment":
                        user.investment += contribution_amount
                    elif source == "wallet":
                        user.wallet += contribution_amount
                    user.save()

                    Contribution.objects.filter(group=group, user=contribution).update(
                        payment_status="Refunded"
                    )

                group.total_raised = 0
                group.status = "failed"
                group.save()

        except Exception as e:
            logger.error(f"Error processing group {group.id}: {str(e)}")

    logger.info("Refund task completed.")
