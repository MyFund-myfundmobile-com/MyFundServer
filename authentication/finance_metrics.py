from decimal import Decimal
from datetime import date, timedelta

from django.db.models import Sum, Q
from django.db.models.functions import Coalesce
from django.utils import timezone

from .models import CustomUser, Transaction, FinanceMetricSnapshot


def money(value):
    return (value or Decimal("0.00")).quantize(Decimal("0.01"))


def get_period_range(period_type="monthly", target_date=None):
    target_date = target_date or timezone.now().date()

    if period_type == "daily":
        return target_date, target_date

    if period_type == "yearly":
        return date(target_date.year, 1, 1), date(target_date.year, 12, 31)

    start = target_date.replace(day=1)

    if start.month == 12:
        next_month = date(start.year + 1, 1, 1)
    else:
        next_month = date(start.year, start.month + 1, 1)

    end = next_month - timedelta(days=1)
    return start, end


def sum_service_charge(queryset):
    return money(
        queryset.aggregate(total=Coalesce(Sum("service_charge"), Decimal("0.00")))[
            "total"
        ]
    )


def calculate_finance_metrics(period_type="monthly", target_date=None, save=True):
    period_start, period_end = get_period_range(period_type, target_date)

    confirmed_charged_transactions = Transaction.objects.filter(
        status="confirmed",
        service_charge__gt=0,
        date__gte=period_start,
        date__lte=period_end,
    )

    # 1. Abrupt / immediate withdrawal charges
    abrupt_withdrawal_revenue = sum_service_charge(
        confirmed_charged_transactions.filter(
            Q(description__icontains="Bank") | Q(description__icontains="Withdrawal")
        ).exclude(description__icontains="Cancelled")
    )

    # 2. Target savings cancellation charges
    target_savings_cancellation_revenue = sum_service_charge(
        confirmed_charged_transactions.filter(
            Q(description__icontains="Cancelled"),
            target_savings__isnull=False,
        )
    )

    # 3. Scheduled withdrawal cancellation charges
    scheduled_withdrawal_cancellation_revenue = sum_service_charge(
        confirmed_charged_transactions.filter(
            Q(description__icontains="Cancelled Withdrawal")
            | Q(description__icontains="Scheduled Withdrawal Cancelled")
        )
    )

    # 4. Any other confirmed service charges
    known_charge_ids = confirmed_charged_transactions.filter(
        Q(description__icontains="Bank")
        | Q(description__icontains="Withdrawal")
        | Q(description__icontains="Cancelled")
        | Q(target_savings__isnull=False)
    ).values_list("id", flat=True)

    other_service_charge_revenue = sum_service_charge(
        confirmed_charged_transactions.exclude(id__in=known_charge_ids)
    )

    total_service_charge_revenue = money(
        abrupt_withdrawal_revenue
        + target_savings_cancellation_revenue
        + scheduled_withdrawal_cancellation_revenue
        + other_service_charge_revenue
    )

    balances = CustomUser.objects.filter(
        is_deleted=False,
        is_active=True,
    ).aggregate(
        total_savings=Coalesce(Sum("savings"), Decimal("0.00")),
        total_investment=Coalesce(Sum("investment"), Decimal("0.00")),
    )

    total_savings = money(balances["total_savings"])
    total_investment = money(balances["total_investment"])

    days = (period_end - period_start).days + 1

    myfund_daily_rate = Decimal("0.22") / Decimal("365")
    savings_user_daily_rate = Decimal("0.13") / Decimal("365")
    investment_user_daily_rate = Decimal("0.20") / Decimal("365")

    float_gross_revenue = money(
        (total_savings + total_investment) * myfund_daily_rate * days
    )

    roi_payable_to_users = money(
        (total_savings * savings_user_daily_rate * days)
        + (total_investment * investment_user_daily_rate * days)
    )

    float_net_profit = money(float_gross_revenue - roi_payable_to_users)

    property_sales_revenue = Decimal("0.00")
    rent_commission_revenue = Decimal("0.00")

    total_revenue = money(
        total_service_charge_revenue
        + float_gross_revenue
        + property_sales_revenue
        + rent_commission_revenue
    )

    total_expenses = money(roi_payable_to_users)

    net_profit = money(
        total_service_charge_revenue
        + float_net_profit
        + property_sales_revenue
        + rent_commission_revenue
    )

    profit_margin = Decimal("0.00")
    if total_revenue > 0:
        profit_margin = money((net_profit / total_revenue) * Decimal("100"))

    notes = (
        f"Service charge breakdown: "
        f"Abrupt withdrawals ₦{abrupt_withdrawal_revenue:,.2f}; "
        f"Target savings cancellations ₦{target_savings_cancellation_revenue:,.2f}; "
        f"Scheduled withdrawal cancellations ₦{scheduled_withdrawal_cancellation_revenue:,.2f}; "
        f"Other service charges ₦{other_service_charge_revenue:,.2f}."
    )

    data = {
        "period_type": period_type,
        "period_start": period_start,
        "period_end": period_end,
        # Keeping this field name for now so no migration is needed.
        # It now means TOTAL confirmed service-charge revenue.
        "abrupt_withdrawal_revenue": total_service_charge_revenue,
        "float_gross_revenue": float_gross_revenue,
        "roi_payable_to_users": roi_payable_to_users,
        "float_net_profit": float_net_profit,
        "property_sales_revenue": property_sales_revenue,
        "rent_commission_revenue": rent_commission_revenue,
        "total_revenue": total_revenue,
        "total_expenses": total_expenses,
        "net_profit": net_profit,
        "profit_margin": profit_margin,
        "total_savings_balance": total_savings,
        "total_investment_balance": total_investment,
        "notes": notes,
    }

    if save:
        snapshot, created = FinanceMetricSnapshot.objects.update_or_create(
            period_type=period_type,
            period_start=period_start,
            period_end=period_end,
            defaults=data,
        )
        return snapshot

    return data
