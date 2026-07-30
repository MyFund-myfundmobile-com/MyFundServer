from decimal import Decimal

from django.db.models import Sum
from django.utils import timezone
from datetime import timedelta

from authentication.models import (
    CustomUser,
    Transaction,
    MetricSnapshot,
)

FLOAT_ANNUAL_RATE = Decimal("0.22")


def get_period_dates(period_type):
    now = timezone.now()

    if period_type == "daily":
        start = now - timedelta(days=1)

    elif period_type == "weekly":
        start = now - timedelta(days=7)

    elif period_type == "monthly":
        start = now - timedelta(days=30)

    else:
        raise ValueError("Invalid period type")

    return start, now


def generate_metric_snapshot(period_type="daily"):
    start, end = get_period_dates(period_type)

    total_users = CustomUser.objects.filter(is_deleted=False).count()

    new_users = CustomUser.objects.filter(
        date_joined__range=(start, end),
        is_deleted=False,
    ).count()

    active_users = (
        Transaction.objects.filter(
            date__range=(start, end),
            status="confirmed",
        )
        .values("user")
        .distinct()
        .count()
    )

    deposits = Transaction.objects.filter(
        date__range=(start, end),
        transaction_type="credit",
        status="confirmed",
    ).aggregate(total=Sum("amount"))["total"] or Decimal("0")

    withdrawals = Transaction.objects.filter(
        date__range=(start, end),
        transaction_type="debit",
        status="confirmed",
    ).aggregate(total=Sum("amount"))["total"] or Decimal("0")

    float_balance = deposits - withdrawals

    estimated_float_revenue = float_balance * FLOAT_ANNUAL_RATE / Decimal("365")

    retention_rate = Decimal("0")

    if new_users > 0:
        retention_rate = (Decimal(active_users) / Decimal(new_users)) * Decimal("100")

    ltv = Decimal("0")

    if total_users > 0:
        ltv = deposits / Decimal(total_users)

    cac_proxy = Decimal("0")

    snapshot = MetricSnapshot.objects.create(
        period_type=period_type,
        snapshot_date=timezone.now().date(),
        total_users=total_users,
        new_users=new_users,
        active_users=active_users,
        retention_rate=retention_rate,
        ltv=ltv,
        cac_proxy=cac_proxy,
        float_balance=float_balance,
        estimated_float_revenue=estimated_float_revenue,
        total_deposits=deposits,
        total_withdrawals=withdrawals,
    )

    return snapshot
