from datetime import timedelta
from decimal import Decimal
from django.db.models import Sum, Count, Q, F
from django.utils import timezone

from .models import (
    CustomUser,
    Transaction,
    TopSaverHistory,
    AmbassadorMonthlyReport,
)


def _safe_decimal(value):
    if value is None:
        return 0.0
    return float(value)


def get_business_snapshot(days=30):
    now = timezone.now()
    start_date = now - timedelta(days=days)

    users_qs = CustomUser.objects.filter(is_deleted=False)

    total_users = users_qs.count()
    new_signups = users_qs.filter(date_joined__gte=start_date).count()
    confirmed_signups = users_qs.filter(
        date_joined__gte=start_date,
        is_confirmed=True,
    ).count()
    ambassadors = users_qs.filter(is_ambassador=True).count()
    active_users = users_qs.filter(is_active=True, is_banned=False).count()
    dormant_users = users_qs.filter(savings=0, investment=0, wallet=0).count()

    top_savers = list(
        users_qs.order_by("-savings").values(
            "id", "email", "is_ambassador", "savings", "investment", "wallet"
        )[:10]
    )

    tx_qs = Transaction.objects.filter(date__gte=start_date)

    transaction_summary = tx_qs.aggregate(
        total_transaction_amount=Sum("amount"),
        total_service_charge=Sum("service_charge"),
        total_total_amount=Sum("total_amount"),
        total_confirmed=Count("id", filter=Q(status="confirmed")),
        total_pending=Count("id", filter=Q(status="pending")),
        total_failed=Count("id", filter=Q(status="failed")),
        total_credit=Count("id", filter=Q(transaction_type="credit")),
        total_debit=Count("id", filter=Q(transaction_type="debit")),
    )

    funding_source_breakdown = list(
        tx_qs.values("source")
        .annotate(
            count=Count("id"),
            total_amount=Sum("amount"),
        )
        .order_by("-total_amount")
    )

    credited_to_breakdown = list(
        tx_qs.values("credited_to")
        .annotate(
            count=Count("id"),
            total_amount=Sum("amount"),
        )
        .order_by("-total_amount")
    )

    referral_leaders = list(
        users_qs.annotate(
            total_referrals=Count("customuser"),  # reverse FK
            confirmed_referrals=Count(
                "customuser",
                filter=Q(customuser__is_confirmed=True),
            ),
            active_referrals=Count(
                "customuser",
                filter=Q(
                    Q(customuser__savings__gt=0) | Q(customuser__investment__gt=0)
                ),
            ),
        )
        .filter(total_referrals__gt=0)
        .order_by("-active_referrals", "-confirmed_referrals", "-total_referrals")[:10]
        .values(
            "id",
            "email",
            "is_ambassador",
            "total_referrals",
            "confirmed_referrals",
            "active_referrals",
        )
    )

    top_saver_history = list(
        TopSaverHistory.objects.order_by("-year", "-month", "rank").values(
            "month", "year", "rank", "total_savings", "user_id"
        )[:20]
    )

    ambassador_reports = list(
        AmbassadorMonthlyReport.objects.order_by("-submitted_at").values(
            "user_id",
            "month",
            "status",
            "signups_submitted",
            "confirmed_submitted",
            "savings_submitted",
            "total_points_awarded",
            "stipend_amount",
            "submitted_at",
        )[:20]
    )

    return {
        "period_days": days,
        "users": {
            "total_users": total_users,
            "new_signups": new_signups,
            "confirmed_signups": confirmed_signups,
            "ambassadors": ambassadors,
            "active_users": active_users,
            "dormant_users": dormant_users,
            "total_balance": float(
                users_qs.aggregate(
                    total=Sum(F("savings") + F("investment") + F("wallet"))
                )["total"]
                or 0
            ),
        },
        "transactions": {
            "total_transaction_amount": _safe_decimal(
                transaction_summary.get("total_transaction_amount")
            ),
            "total_service_charge": _safe_decimal(
                transaction_summary.get("total_service_charge")
            ),
            "total_total_amount": _safe_decimal(
                transaction_summary.get("total_total_amount")
            ),
            "total_confirmed": transaction_summary.get("total_confirmed", 0),
            "total_pending": transaction_summary.get("total_pending", 0),
            "total_failed": transaction_summary.get("total_failed", 0),
            "total_credit": transaction_summary.get("total_credit", 0),
            "total_debit": transaction_summary.get("total_debit", 0),
            "funding_source_breakdown": [
                {
                    "source": item["source"] or "UNKNOWN",
                    "count": item["count"],
                    "total_amount": _safe_decimal(item["total_amount"]),
                }
                for item in funding_source_breakdown
            ],
            "credited_to_breakdown": [
                {
                    "credited_to": item["credited_to"] or "UNKNOWN",
                    "count": item["count"],
                    "total_amount": _safe_decimal(item["total_amount"]),
                }
                for item in credited_to_breakdown
            ],
        },
        "top_savers": [
            {
                "user_id": item["id"],
                "email": item["email"],
                "is_ambassador": item["is_ambassador"],
                "savings": _safe_decimal(item["savings"]),
                "investment": _safe_decimal(item["investment"]),
                "wallet": _safe_decimal(item["wallet"]),
            }
            for item in top_savers
        ],
        "referral_leaders": referral_leaders,
        "top_saver_history": [
            {
                "month": item["month"],
                "year": item["year"],
                "rank": item["rank"],
                "total_savings": _safe_decimal(item["total_savings"]),
                "user_id": item["user_id"],
            }
            for item in top_saver_history
        ],
        "ambassador_reports": [
            {
                "user_id": item["user_id"],
                "month": item["month"],
                "status": item["status"],
                "signups_submitted": item["signups_submitted"],
                "confirmed_submitted": item["confirmed_submitted"],
                "savings_submitted": _safe_decimal(item["savings_submitted"]),
                "total_points_awarded": _safe_decimal(item["total_points_awarded"]),
                "stipend_amount": _safe_decimal(item["stipend_amount"]),
                "submitted_at": (
                    item["submitted_at"].isoformat() if item["submitted_at"] else None
                ),
            }
            for item in ambassador_reports
        ],
    }
