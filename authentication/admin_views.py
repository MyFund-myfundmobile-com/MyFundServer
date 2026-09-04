# admin_views.py - Optimized Admin Dashboard Endpoints with Growth Metrics

import logging

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from django.db.models import Sum, Count, Q, F, Case, When, IntegerField, FloatField,ExpressionWrapper, DecimalField, IntegerField, Prefetch, Case, When, Value
from django.utils import timezone
from datetime import timedelta, datetime
from dateutil.relativedelta import relativedelta
from django.core.cache import cache
from decimal import Decimal
from .models import (
    CustomUser,
    Transaction,
    MonthlySavings,
    TopSaverHistory,
    TargetSavings,
    TargetSavingsCompletion,
    WithdrawalsRequestToAdmin,
    Property,
    EmailCampaign,
    Employee,
    CxWeeklyReport,
)
from .serializers import (
    UserSerializer,
    AdminUserListSerializer,
    AdminTransactionListSerializer,
    EmailCampaignSerializer,
    CxWeeklyReportSerializer,
)
from .utils import (
    grant_user_ambassador_status,
    revoke_user_ambassador_status,
    send_admin_push_notification,
)

logger = logging.getLogger(__name__)
from django.db.models.functions import ExtractMonth, ExtractYear, Coalesce, Cast
 



# ============================================================================
# PRIORITY 1: CRITICAL DASHBOARD DATA (Load first - 2-3 seconds)
# ============================================================================


from dateutil.relativedelta import relativedelta
from django.db.models import Sum, Count, Q, F, Value, DecimalField
from django.db.models.functions import Coalesce
from django.db.models import OuterRef, Subquery, Exists, IntegerField
from django.db.models.functions import TruncMonth

def get_monthly_advanced_metrics(months=12):
    """
    Fully optimized monthly metrics with accurate Total & Confirmed Referrals
    and precise 30-day cohort-based retention.
    """
    now = timezone.now()
    results = []

    # Determine start date for metrics
    cutoff_date = now - relativedelta(months=months)

    # ------------------- USER METRICS -------------------
    users_qs = CustomUser.objects.filter(is_deleted=False, date_joined__lt=now)
    users_by_month = users_qs.annotate(
        month=TruncMonth('date_joined')
    ).values('month').annotate(
        total_users=Count('id'),
        new_users=Count('id', filter=Q(date_joined__gte=cutoff_date)),
        investor_heavy=Count('id', filter=Q(savings__gt=0, investment__gt=F('savings'))),
        savings_heavy=Count('id', filter=Q(savings__gt=0, investment__lte=F('savings'))),
        referrals_count=Count('id', filter=Q(referral_id__isnull=False)),
        influencers_count=Count('id', filter=Q(is_ambassador=True)),
        fum=Coalesce(Sum(F('savings') + F('investment')), Value(0), output_field=DecimalField()),
    ).order_by('month')
    user_metrics_dict = {m['month'].date(): m for m in users_by_month}

    # ------------------- TRANSACTION METRICS -------------------
    tx_qs = Transaction.objects.filter(date__lt=now)
    tx_by_month = tx_qs.annotate(
        month=TruncMonth('date')
    ).values('month').annotate(
        total_tx=Count('id'),
        failed_tx=Count('id', filter=Q(status='failed')),
        mas_users=Count(
            'user_id',
            filter=Q(
                credited_to__in=['SAVINGS', 'INVESTMENT'],
                transaction_type='credit',
                status='confirmed'
            ),
            distinct=True
        ),
        mas_amount=Coalesce(
            Sum('amount', filter=Q(
                credited_to__in=['SAVINGS', 'INVESTMENT'],
                transaction_type='credit',
                status='confirmed'
            )),
            Value(0),
            output_field=DecimalField()
        ),
        total_referrals=Count('id', filter=Q(referral_email__isnull=False)),
        confirmed_referrals=Count('id', filter=Q(status='confirmed', referral_email__isnull=False)),
    ).order_by('month')
    tx_metrics_dict = {m['month'].date(): m for m in tx_by_month}

    # ------------------- COHORT RETENTION SUBQUERY -------------------
    # We want users who joined 30 days before the month and had a confirmed transaction in the month
    cohort_subquery = Transaction.objects.filter(
        user=OuterRef('pk'),
        transaction_type='credit',
        status='confirmed',
        credited_to__in=['SAVINGS', 'INVESTMENT'],
        date__gte=OuterRef('cohort_start'),
        date__lt=OuterRef('cohort_end')
    ).values('user').distinct().values('pk')

    # ------------------- LOOP PER MONTH -------------------
    for i in range(months):
        target_month = now - relativedelta(months=i)
        month_start = target_month.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_end = month_start + relativedelta(months=1)
        cohort_start = month_start - relativedelta(days=30)
        cohort_end = month_start

        month_key = month_start.date()
        user_data = user_metrics_dict.get(month_key, {})
        tx_data = tx_metrics_dict.get(month_key, {})

        total_users = user_data.get('total_users', 0)
        new_users = user_data.get('new_users', 0)
        investor_heavy = user_data.get('investor_heavy', 0)
        savings_heavy = user_data.get('savings_heavy', 0)
        fum = user_data.get('fum', Decimal('0'))
        referrals = user_data.get('referrals_count', 0)
        influencers = user_data.get('influencers_count', 0)

        total_tx = tx_data.get('total_tx', 0)
        failed_tx = tx_data.get('failed_tx', 0)
        mas_users = tx_data.get('mas_users', 0)
        mas_amount = tx_data.get('mas_amount', Decimal('0'))
        total_referrals = tx_data.get('total_referrals', 0)
        confirmed_referrals = tx_data.get('confirmed_referrals', 0)

        # ------------------- CALCULATED METRICS -------------------
        transaction_failure_rate = (failed_tx / total_tx * 100) if total_tx else 0
        activation_rate = (mas_users / new_users * 100) if new_users else 0
        churn_rate = ((total_users - mas_users) / total_users * 100) if total_users else 0
        referrals_pct = (referrals / total_users * 100) if total_users else 0
        influencers_pct = (influencers / total_users * 100) if total_users else 0
        investor_pct = investor_heavy
        saver_pct = savings_heavy

        # ------------------- RETENTION (30D COHORT) -------------------
        cohort_users = CustomUser.objects.filter(
            date_joined__gte=cohort_start,
            date_joined__lt=cohort_end,
            is_deleted=False
        )
        cohort_count = cohort_users.count()
        if cohort_count > 0:
            retained_users = Transaction.objects.filter(
                user__in=cohort_users,
                transaction_type='credit',
                status='confirmed',
                credited_to__in=['SAVINGS', 'INVESTMENT'],
                date__gte=month_start,
                date__lt=month_end
            ).values('user').distinct().count()
            retention_rate = retained_users / cohort_count * 100
        else:
            retention_rate = 0

        results.append({
            "month": month_start.strftime("%Y-%m"),
            "label": month_start.strftime("%b %Y"),
            "monthly_active_savers": {
                "users": mas_users,
                "total_amount": float(mas_amount),
            },
            "activation_rate": round(activation_rate, 2),
            "retention_30d": round(retention_rate, 2),
            "investors_vs_savers": {
                "investor_heavy": investor_heavy,
                "savings_heavy": savings_heavy,
            },
            "transaction_failure_rate": round(transaction_failure_rate, 2),
            "growth_multipliers": {
                "referrals_pct": round(referrals_pct, 2),
                "influencers_pct": round(influencers_pct, 2),
            },
            "financial_health": {
                "fum": float(fum),
                "churn_rate": round(churn_rate, 2),
                "total_referrals": total_referrals,
                "confirmed_referrals": confirmed_referrals,
            }
        })

    return results


@api_view(["GET"])
@permission_classes([IsAdminUser])
def dashboard_summary(request):
    cache_key = "dashboard_summary_v2"  # ✅ real caching
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)

    now = timezone.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    # ================= USER AGGREGATES =================
    user_stats = CustomUser.objects.filter(is_deleted=False).aggregate(
        total_users=Count("id"),
        total_savings=Coalesce(Sum("savings"), Value(0), output_field=DecimalField()),
        total_investments=Coalesce(Sum("investment"), Value(0), output_field=DecimalField()),
        new_users_this_month=Count("id", filter=Q(date_joined__gte=month_start)),
        referral_signups=Count("id", filter=Q(referral_id__isnull=False)),
        influencer_signups=Count("id", filter=Q(is_ambassador=True)),
    )

    # ================= TRANSACTION STATS =================
    tx_stats = Transaction.objects.filter(date__gte=month_start).aggregate(
        total_tx=Count("id"),
        failed_tx=Count("id", filter=Q(status="failed")),
        mas_users=Count(
            "user",
            distinct=True,
            filter=Q(
                credited_to__in=["SAVINGS", "INVESTMENT"],
                transaction_type="credit",
                status="confirmed",
            ),
        ),
        mas_amount=Coalesce(
            Sum(
                "amount",
                filter=Q(
                    credited_to__in=["SAVINGS", "INVESTMENT"],
                    transaction_type="credit",
                    status="confirmed",
                ),
            ),
            Value(0),
            output_field=DecimalField(),
        ),
    )

    total_users = user_stats["total_users"]

    failure_rate = (
        tx_stats["failed_tx"] / tx_stats["total_tx"] * 100
        if tx_stats["total_tx"]
        else 0
    )

    referrals_pct = (
        user_stats["referral_signups"] / total_users * 100 if total_users else 0
    )
    influencers_pct = (
        user_stats["influencer_signups"] / total_users * 100 if total_users else 0
    )

    advanced_metrics_monthly = get_monthly_advanced_metrics(12)

    response_data = {
        "current_month": {
            "total_savings": float(user_stats["total_savings"]),
            "total_investments": float(user_stats["total_investments"]),
        },
        "user_statistics": {
            "total_users": total_users,
            "new_users_this_month": user_stats["new_users_this_month"],
        },
        "advanced_metrics": {
            "monthly_active_savers": {
                "users": tx_stats["mas_users"],
                "total_amount": float(tx_stats["mas_amount"]),
            },
            "transaction_failure_rate": round(failure_rate, 2),
            "growth_multipliers": {
                "referrals_pct": round(referrals_pct, 2),
                "influencers_pct": round(influencers_pct, 2),
            },
        },
        "advanced_metrics_monthly": advanced_metrics_monthly,
    }

    cache.set(cache_key, response_data, 120)
    return Response(response_data)




# ============================================================================
# PRIORITY 2: CHART DATA (Load in background - lazy loaded)
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAdminUser])
def user_growth_chart(request):
    """
    GET /api/admin/charts/user-growth?period=6months
    Cached for 15 minutes
    """
    period = request.GET.get('period', '6months')
    cache_key = f"chart:user-growth:{period}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        months = int(period.replace('months', ''))
        start_date = timezone.now() - relativedelta(months=months)
        
        # Optimized query with window function
        from django.db.models import Window
        from django.db.models.functions import TruncMonth
        
        monthly_data = CustomUser.objects.filter(
            date_joined__gte=start_date,
            is_deleted=False
        ).annotate(
            month=TruncMonth('date_joined')
        ).values('month').annotate(
            new_users=Count('id')
        ).order_by('month')
        
        # Calculate cumulative totals
        data = []
        cumulative = CustomUser.objects.filter(
            date_joined__lt=start_date,
            is_deleted=False
        ).count()
        
        for entry in monthly_data:
            cumulative += entry['new_users']
            data.append({
                "month": entry['month'].strftime('%B %Y'),
                "new_users": entry['new_users'],
                "total_users": cumulative
            })
        
        total_growth = sum(d['new_users'] for d in data)
        avg_growth = total_growth / len(data) if data else 0
        
        # Calculate growth rate
        first_month = data[0]['total_users'] if data else 0
        last_month = data[-1]['total_users'] if data else 0
        growth_rate = calculate_growth_rate(last_month, first_month)
        
        response_data = {
            "period": period,
            "data": data,
            "summary": {
                "total_growth": total_growth,
                "average_monthly_growth": round(avg_growth, 2),
                "growth_rate": f"+{growth_rate}%" if growth_rate > 0 else f"{growth_rate}%"
            }
        }
        
        # Cache for 15 minutes
        cache.set(cache_key, response_data, 900)
        
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def top_savers_chart(request):
    """
    GET /api/admin/charts/top-savers?limit=10&period=all_time
    Cached for 30 minutes
    """
    limit = int(request.GET.get('limit', 10))
    period = request.GET.get('period', 'all_time')
    
    cache_key = f"chart:top-savers:{period}:{limit}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Filter based on period if needed
        queryset = CustomUser.objects.filter(is_deleted=False)
        
        if period == 'this_month':
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            # Use total_savings_and_investments_this_month field
            queryset = queryset.filter(
                total_savings_and_investments_this_month__gt=0
            ).order_by('-total_savings_and_investments_this_month')[:limit]
            
            data = []
            for rank, user in enumerate(queryset, 1):
                data.append({
                    "user_id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "total_savings": float(user.total_savings_and_investments_this_month),
                    "rank": rank,
                    "profile_picture": user.profile_picture or ""
                })
        else:
            # All time top savers
            queryset = queryset.order_by('-savings_and_investments')[:limit]
            
            data = []
            for rank, user in enumerate(queryset, 1):
                data.append({
                    "user_id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "total_savings": float(user.savings_and_investments),
                    "rank": rank,
                    "profile_picture": user.profile_picture or ""
                })
        
        total_top_savings = sum(d['total_savings'] for d in data)
        avg_savings = total_top_savings / len(data) if data else 0
        
        response_data = {
            "period": period,
            "data": data,
            "summary": {
                "total_top_10_savings": round(total_top_savings, 2),
                "average_savings": round(avg_savings, 2)
            }
        }
        
        # Cache for 30 minutes
        cache.set(cache_key, response_data, 1800)
        
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def new_savers_chart(request):
    """
    GET /api/admin/charts/new-savers?period=6months
    Shows users who started saving each month
    """
    period = request.GET.get('period', '6months')
    cache_key = f"chart:new-savers:{period}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        months = int(period.replace('months', ''))
        start_date = timezone.now() - relativedelta(months=months)
        
        from django.db.models.functions import TruncMonth
        
        # Find users who made their first savings transaction in each month
        monthly_data = Transaction.objects.filter(
            date__gte=start_date,
            transaction_type='credit',
            status='confirmed',
            credited_to__in=['SAVINGS', 'INVESTMENT']
        ).values('user').annotate(
            first_save_month=TruncMonth('date')
        ).values('first_save_month').annotate(
            new_savers=Count('user', distinct=True),
            total_savings=Sum('amount')
        ).order_by('first_save_month')
        
        data = []
        for entry in monthly_data:
            avg_per_saver = entry['total_savings'] / entry['new_savers'] if entry['new_savers'] > 0 else 0
            data.append({
                "month": entry['first_save_month'].strftime('%B %Y'),
                "new_savers": entry['new_savers'],
                "total_savings": float(entry['total_savings']),
                "average_per_saver": round(float(avg_per_saver), 2)
            })
        
        response_data = {
            "period": period,
            "data": data
        }
        
        cache.set(cache_key, response_data, 900)
        
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def user_metrics_chart(request):
    """
    GET /api/admin/charts/user-metrics
    For pie charts and user segmentation
    """
    cache_key = "chart:user-metrics"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Active vs inactive users
        active_threshold = timezone.now() - timedelta(days=30)
        
        metrics = CustomUser.objects.filter(is_deleted=False).aggregate(
            active_users=Count('id', filter=Q(updated_at__gte=active_threshold)),
            inactive_users=Count('id', filter=Q(updated_at__lt=active_threshold)),
            users_with_savings=Count('id', filter=Q(savings__gt=0)),
            users_with_investments=Count('id', filter=Q(investment__gt=0)),
            users_with_both=Count('id', filter=Q(savings__gt=0, investment__gt=0))
        )
        
        # Wealth stage distribution
        wealth_stages = []
        for stage in range(1, 10):
            count = CustomUser.objects.filter(
                is_deleted=False
            ).extra(
                where=[f"FLOOR(LOG10(savings_and_investments + 1)) + 1 = {stage}"]
            ).count()
            wealth_stages.append({"stage": stage, "count": count})
        
        response_data = {
            **metrics,
            "wealth_stages": wealth_stages
        }
        
        cache.set(cache_key, response_data, 900)
        
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def financial_history_chart(request):
    """
    GET /api/admin/charts/financial-history?type=savings&period=6months
    Shows monthly financial trends using the Transaction model.
    """
    fin_type = request.GET.get('type', 'savings')  # savings or investment
    period = request.GET.get('period', '6months')

    cache_key = f"chart:financial-history:{fin_type}:{period}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        # Convert period string to months
        months = int(period.replace('months', ''))
        start_date = timezone.now() - relativedelta(months=months)

        # Determine which bucket we're aggregating - credited_to is where
        # the money ended up, not source (which is the funding channel -
        # bank transfer/card/wallet - and would incorrectly exclude nearly
        # every real deposit).
        credited_to_filter = "SAVINGS" if fin_type == "savings" else "INVESTMENT"

        # Only CONFIRMED credit transactions represent money coming in
        queryset = (
            Transaction.objects.filter(
                date__gte=start_date,
                credited_to=credited_to_filter,
                transaction_type="credit",
                status="confirmed",
            )
            .annotate(month=ExtractMonth("date"), year=ExtractYear("date"))
            .values("month", "year")
            .annotate(
                amount=Sum("amount"),
                user_count=Count("user", distinct=True),
            )
            .order_by("year", "month")
        )

        data = []
        prev_amount = None
        highest = {"month": "", "amount": 0}
        lowest = {"month": "", "amount": float("inf")}

        for entry in queryset:
            amount = float(entry["amount"] or 0)
            month_str = datetime(entry["year"], entry["month"], 1).strftime("%B %Y")

            # ---- Growth rate compared to previous month ----
            growth_rate = 0
            if prev_amount and prev_amount > 0:
                growth_rate = ((amount - prev_amount) / prev_amount) * 100

            data.append(
                {
                    "month": month_str,
                    "amount": amount,
                    "growth_rate": f"+{growth_rate:.1f}%" if growth_rate > 0 else f"{growth_rate:.1f}%",
                    "user_count": entry["user_count"],
                }
            )

            # ---- Track highest month ----
            if amount > highest["amount"]:
                highest = {"month": month_str, "amount": amount}

            # ---- Track lowest month (ignore true 0 months) ----
            if 0 < amount < lowest["amount"]:
                lowest = {"month": month_str, "amount": amount}

            prev_amount = amount

        # ---- Summary calculations ----
        total = sum(d["amount"] for d in data)
        avg_monthly = total / len(data) if data else 0

        response_data = {
            "type": fin_type,
            "period": period,
            "data": data,
            "summary": {
                "total": round(total, 2),
                "average_monthly": round(avg_monthly, 2),
                "highest_month": highest["month"],
                "lowest_month": lowest["month"],
            },
        }

        cache.set(cache_key, response_data, 900)  # Cache 15 min
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def withdrawals_trend_chart(request):
    """
    GET /api/admin/charts/withdrawals-trend?period=6months
    Shows monthly withdrawal trends using the Transaction model - confirmed
    debit transactions out of SAVINGS/INVESTMENT, mirroring
    cashflow_summary's and net_fum_change's withdrawal definition. Same
    shape/logic as financial_history_chart, just for money going out
    instead of coming in.
    """
    period = request.GET.get('period', '6months')

    cache_key = f"chart:withdrawals-trend:{period}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        months = int(period.replace('months', ''))
        start_date = timezone.now() - relativedelta(months=months)

        queryset = (
            Transaction.objects.filter(
                date__gte=start_date,
                source__in=["SAVINGS", "INVESTMENT"],
                transaction_type="debit",
                status="confirmed",
            )
            .annotate(month=ExtractMonth("date"), year=ExtractYear("date"))
            .values("month", "year")
            .annotate(
                amount=Sum("amount"),
                user_count=Count("user", distinct=True),
            )
            .order_by("year", "month")
        )

        data = []
        prev_amount = None
        highest = {"month": "", "amount": 0}
        lowest = {"month": "", "amount": float("inf")}

        for entry in queryset:
            amount = float(entry["amount"] or 0)
            month_str = datetime(entry["year"], entry["month"], 1).strftime("%B %Y")

            growth_rate = 0
            if prev_amount and prev_amount > 0:
                growth_rate = ((amount - prev_amount) / prev_amount) * 100

            data.append(
                {
                    "month": month_str,
                    "amount": amount,
                    "growth_rate": f"+{growth_rate:.1f}%" if growth_rate > 0 else f"{growth_rate:.1f}%",
                    "user_count": entry["user_count"],
                }
            )

            if amount > highest["amount"]:
                highest = {"month": month_str, "amount": amount}
            if 0 < amount < lowest["amount"]:
                lowest = {"month": month_str, "amount": amount}

            prev_amount = amount

        total = sum(d["amount"] for d in data)
        avg_monthly = total / len(data) if data else 0

        response_data = {
            "period": period,
            "data": data,
            "summary": {
                "total": round(total, 2),
                "average_monthly": round(avg_monthly, 2),
                "highest_month": highest["month"],
                "lowest_month": lowest["month"],
            },
        }

        cache.set(cache_key, response_data, 900)  # Cache 15 min
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ============================================================================
# PRIORITY 3: LIST DATA (Paginated - load on demand)
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAdminUser])
def recent_signups(request):
    """
    GET /api/admin/users/recent?page=1&limit=20&range=daily
    Paginated recent user signups
    """
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 20))
    range_param = request.GET.get('range', 'daily')
    
    try:
        # Calculate date range
        now = timezone.now()
        if range_param == 'daily':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif range_param == 'weekly':
            start_date = now - timedelta(days=7)
        elif range_param == 'monthly':
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            start_date = now - timedelta(days=1)
        
        # Query users
        queryset = CustomUser.objects.filter(
            date_joined__gte=start_date,
            is_deleted=False
        ).order_by('-date_joined')
        
        total_count = queryset.count()
        total_pages = (total_count + limit - 1) // limit
        
        # Pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        users = queryset[start_idx:end_idx]
        
        data = []
        for user in users:
            data.append({
                "user_id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "date_joined": user.date_joined.isoformat(),
                "profile_picture": user.profile_picture or "",
                "initial_savings": float(user.savings),
                "wealth_stage": calculate_wealth_stage(user)['stage']
            })
        
        return Response({
            "range": range_param,
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": total_pages,
            "data": data
        })
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


def _parse_bool_param(value):
    """None means "not provided, don't filter on this" - distinct from an
    explicit false, which must still filter. Accepts both query-string
    values (always strings) and JSON request-body values (native bools),
    since _build_admin_user_queryset now serves both GET query params and
    POST JSON bodies."""
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('true', '1', 'yes')


# Boolean CustomUser fields exposed as filters here, matching the same
# ones Django's own CustomUserAdmin.list_filter exposes (admin.py) so this
# endpoint can back a "filter like in Django" list UI.
USER_LIST_BOOLEAN_FILTERS = (
    'is_ambassador',
    'is_staff',
    'is_banned',
    'is_active',
    'is_influencer',
)


def _annotate_activity(queryset, as_of):
    """
    Shared by _build_admin_user_queryset's `activity` filter and
    user_activity_segments's counts, so the two definitions of
    active/dormant/inactive can't drift apart. See
    user_activity_segments's docstring for what each annotation means.
    """
    recent_threshold = as_of - timedelta(days=30)
    recent_tx = Transaction.objects.filter(
        user=OuterRef('pk'), status='confirmed',
        date__gte=recent_threshold, date__lte=as_of,
    )
    any_tx = Transaction.objects.filter(
        user=OuterRef('pk'), status='confirmed', date__lte=as_of,
    )
    return queryset.annotate(
        has_recent_tx=Exists(recent_tx),
        has_any_tx=Exists(any_tx),
    )


def _build_admin_user_queryset(params, exclude_unmailable=False):
    """
    Shared search/filter logic behind all_users_list,
    admin_user_emails_for_segment, admin_user_export_csv, and
    create_email_campaign, so none of them can drift out of sync on what
    "matches this segment" means. `params` is anything dict-like with
    .get() - request.GET (query string, values always strings) for the
    GET endpoints, or request.data (JSON body, values may be native
    bools) for the POST campaign-create endpoint. Returns (queryset,
    filters_applied), ordered by -date_joined; callers paginate/slice/cap
    as needed.

    exclude_unmailable=True drops is_subscribed=False and
    email_undeliverable=True users - pass this from every endpoint that
    actually SENDS mail (not all_users_list, which is a general browse/
    search list an admin still needs to find an opted-out or bounced user
    on, e.g. to follow up some other way).
    """
    search = (params.get('search') or '').strip()
    queryset = CustomUser.objects.filter(is_deleted=False)
    if exclude_unmailable:
        queryset = queryset.filter(is_subscribed=True, email_undeliverable=False)

    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(email__icontains=search) |
            Q(phone_number__icontains=search)
        )

    filters_applied = {"search": search}

    for field in USER_LIST_BOOLEAN_FILTERS:
        parsed = _parse_bool_param(params.get(field))
        if parsed is not None:
            queryset = queryset.filter(**{field: parsed})
            filters_applied[field] = parsed

    kyc_status = (params.get('kyc_status') or '').strip()
    if kyc_status:
        queryset = queryset.filter(kyc_status=kyc_status)
        filters_applied["kyc_status"] = kyc_status

    non_zero_balance = _parse_bool_param(params.get('non_zero_balance'))
    if non_zero_balance:
        queryset = queryset.filter(
            Q(savings__gt=0) | Q(investment__gt=0) | Q(wallet__gt=0)
        )
        filters_applied["non_zero_balance"] = True

    zero_balance = _parse_bool_param(params.get('zero_balance'))
    if zero_balance:
        queryset = queryset.filter(
            Q(savings__lte=0) & Q(investment__lte=0) & Q(wallet__lte=0)
        )
        filters_applied["zero_balance"] = True

    # New-signup segments (1/3/6 months) - matches the "New Users" chips
    # on the mobile Email tab's segment picker.
    new_users_months = params.get('new_users_months')
    if new_users_months not in (None, ''):
        try:
            months = int(new_users_months)
        except (TypeError, ValueError):
            months = None
        if months in (1, 3, 6):
            cutoff = timezone.now() - relativedelta(months=months)
            queryset = queryset.filter(date_joined__gte=cutoff)
            filters_applied["new_users_months"] = months

    # Signed up this calendar month but hasn't made a single confirmed
    # savings/investment deposit yet - same "not yet saved" definition as
    # signup_metrics/signup_segment_users (credited_to is the destination
    # bucket a deposit landed in, not the funding channel - using `source`
    # here would wrongly exclude nearly every real deposit).
    not_yet_saved_this_month = _parse_bool_param(params.get('not_yet_saved_this_month'))
    if not_yet_saved_this_month:
        month_start = timezone.now().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        month_end = month_start + relativedelta(months=1)
        queryset = queryset.filter(
            date_joined__gte=month_start, date_joined__lt=month_end
        )
        activated_ids = Transaction.objects.filter(
            user__in=queryset,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed',
        ).values_list('user', flat=True).distinct()
        queryset = queryset.exclude(id__in=list(activated_ids))
        filters_applied["not_yet_saved_this_month"] = True

    # Employee is a separate model (payroll/allowance tracking, not a
    # CustomUser field) matched by email - deliberately NOT is_staff, which
    # was decoupled from actual employment status on purpose (see
    # AdminNotifyRecipient's docstring on the old EmployeeAdmin is_staff
    # sync being removed).
    is_employee = _parse_bool_param(params.get('is_employee'))
    if is_employee:
        employee_emails = list(Employee.objects.filter(is_active=True).values_list('email', flat=True))
        if employee_emails:
            email_q = Q()
            for email in employee_emails:
                email_q |= Q(email__iexact=email)
            queryset = queryset.filter(email_q)
        else:
            queryset = queryset.none()
        filters_applied["is_employee"] = True

    # Transaction-activity segment - same definitions as
    # user_activity_segments (via the shared _annotate_activity helper):
    # active = confirmed transaction in the last 30 days; dormant = quiet
    # right now but has a balance or prior transaction history; inactive
    # = never transacted and has a zero balance. ever_transacted is a 4th,
    # independent cut across that same split - has_any_tx=True regardless
    # of recency or current balance - for "everyone who's ever put money
    # in," which active+dormant only approximates (it also catches a
    # handful of dormant users with a non-zero balance but no transaction
    # on record - an admin credit/adjustment, not an actual transaction).
    # Backs the mobile app's User Activity detail drill-down
    # (AdminUsersScreen.js's "Active (Txns)"/"Dormant"/"Never Transacted"/
    # "Ever Transacted" filter chips) - CSV export, recipient count, and
    # campaign send all get this for free since they already go through
    # this shared queryset builder.
    activity = (params.get('activity') or '').strip().lower()
    if activity in ('active', 'dormant', 'inactive', 'ever_transacted'):
        queryset = _annotate_activity(queryset, timezone.now())
        has_balance_q = Q(savings__gt=0) | Q(investment__gt=0) | Q(wallet__gt=0)
        if activity == 'active':
            queryset = queryset.filter(has_recent_tx=True)
        elif activity == 'dormant':
            queryset = queryset.filter(
                Q(has_recent_tx=False) & (has_balance_q | Q(has_any_tx=True))
            )
        elif activity == 'ever_transacted':
            queryset = queryset.filter(has_any_tx=True)
        else:  # inactive
            queryset = queryset.filter(
                has_recent_tx=False, has_any_tx=False,
            ).filter(Q(savings__lte=0) & Q(investment__lte=0) & Q(wallet__lte=0))
        filters_applied["activity"] = activity

    # No referrer at all - the "Engagement Team" segment on the Growth
    # card (see admin_top_performers' engagement_team category). Reused
    # here so the same segment can be exported/emailed like every other
    # one, not just counted.
    no_referral = _parse_bool_param(params.get('no_referral'))
    if no_referral:
        queryset = queryset.filter(referral__isnull=True)
        filters_applied["no_referral"] = True

    # Has THIS user ever referred anyone else - opposite direction from
    # `no_referral` above (that asks "was this user referred BY someone";
    # this asks "has this user referred someone else"). Same `referral`
    # FK, same Exists pattern admin_top_performers' referrer leaderboard
    # uses to count a person's referrals - just a boolean cut rather than
    # a count, and with no date window (any time, ever), independent of
    # whether the referrer themselves has ever saved/transacted.
    has_referred = _parse_bool_param(params.get('has_referred'))
    if has_referred is not None:
        referred_exists = CustomUser.objects.filter(
            is_deleted=False, referral=OuterRef('pk'),
        )
        queryset = queryset.annotate(has_referred_anyone=Exists(referred_exists))
        queryset = queryset.filter(has_referred_anyone=has_referred)
        filters_applied["has_referred"] = has_referred

    # Never referred anyone, but already engaged (saved/transacted) -
    # the natural "hasn't discovered the referral program yet, but is
    # clearly bought into the product" segment for an invite-a-friend
    # campaign. Reuses _annotate_activity's has_any_tx so "transacted
    # before" can't drift from what activity=ever_transacted already
    # means elsewhere.
    never_referred_active = _parse_bool_param(params.get('never_referred_active'))
    if never_referred_active:
        referred_exists = CustomUser.objects.filter(
            is_deleted=False, referral=OuterRef('pk'),
        )
        queryset = _annotate_activity(queryset, timezone.now())
        queryset = queryset.annotate(has_referred_anyone=Exists(referred_exists))
        queryset = queryset.filter(has_referred_anyone=False, has_any_tx=True)
        filters_applied["never_referred_active"] = True

    # Referred at least one person within the last 1/3/6 months - a
    # recency-scoped refinement of has_referred, e.g. to reward/re-engage
    # recently-active referrers specifically. Same window choices as
    # new_users_months above and admin_top_performers' leaderboard ranges.
    referred_within_months = params.get('referred_within_months')
    if referred_within_months not in (None, ''):
        try:
            months = int(referred_within_months)
        except (TypeError, ValueError):
            months = None
        if months in (1, 3, 6):
            cutoff = timezone.now() - relativedelta(months=months)
            recent_referred_exists = CustomUser.objects.filter(
                is_deleted=False, referral=OuterRef('pk'), date_joined__gte=cutoff,
            )
            queryset = queryset.annotate(
                has_recent_referral=Exists(recent_referred_exists)
            )
            queryset = queryset.filter(has_recent_referral=True)
            filters_applied["referred_within_months"] = months

    return queryset.order_by('-date_joined'), filters_applied


@api_view(['GET'])
@permission_classes([IsAdminUser])
def all_users_list(request):
    """
    GET /api/admin/users/list?page=1&limit=50&search=john
        &is_ambassador=true&is_staff=false&is_banned=false&is_active=true
        &is_influencer=true&kyc_status=approved
    Paginated, searchable, filterable user list. Filters mirror Django's
    own CustomUserAdmin.list_filter (is_staff/is_active/is_banned/
    is_ambassador/is_influencer/kyc_status) so the mobile admin Users
    screen can offer the same filtering Django admin does.
    """
    try:
        page = max(1, int(request.GET.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        limit = int(request.GET.get('limit', 50))
    except (TypeError, ValueError):
        limit = 50
    limit = min(max(limit, 1), 200)  # keep a single page request cheap

    try:
        queryset, filters_applied = _build_admin_user_queryset(request.GET)

        total_count = queryset.count()
        total_pages = (total_count + limit - 1) // limit if total_count else 0

        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        users = queryset[start_idx:end_idx]

        serializer = AdminUserListSerializer(
            users, many=True, context={"request": request}
        )

        return Response({
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": total_pages,
            "filters_applied": filters_applied,
            "data": serializer.data
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# Cap on how many recipient emails a single campaign send can pull back in
# one go - protects against an accidental "no filters" blast being built
# from an unbounded in-memory list. 10,000 is comfortably above the current
# user base while still being a sane hard ceiling.
MAX_SEGMENT_EMAIL_RECIPIENTS = 10000


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_user_emails_for_segment(request):
    """
    GET /api/admin/users/emails/?is_ambassador=true&count_only=true
    Same filters as all_users_list (via _build_admin_user_queryset), but
    returns matching emails instead of a paginated user list - backs the
    mobile admin Email tab's "who am I about to send this to" recipient
    picker. With count_only=true, only a cheap count is computed (no email
    list built) - used to show a live "N recipients" preview before the
    admin actually commits to sending.
    """
    try:
        queryset, filters_applied = _build_admin_user_queryset(
            request.GET, exclude_unmailable=True,
        )
        # Only ever email users who can actually receive mail - opted-out
        # and known-bounced addresses are already dropped by
        # exclude_unmailable above; this just also drops blank emails.
        queryset = queryset.exclude(email__isnull=True).exclude(email__exact='')

        count_only = _parse_bool_param(request.GET.get('count_only')) or False

        total_count = queryset.count()

        if count_only:
            return Response({
                "count": total_count,
                "filters_applied": filters_applied,
            })

        truncated = total_count > MAX_SEGMENT_EMAIL_RECIPIENTS
        emails = list(
            queryset.values_list('email', flat=True)[:MAX_SEGMENT_EMAIL_RECIPIENTS]
        )

        return Response({
            "count": total_count,
            "returned_count": len(emails),
            "truncated": truncated,
            "emails": emails,
            "filters_applied": filters_applied,
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


def _csv_safe_filename(label):
    """
    Turn a free-text segment label ("KYC Approved", "Ambassadors" etc.)
    into a safe filename fragment - alnum/dash/underscore only, spaces
    collapsed to underscores, falls back to "users" if that leaves
    nothing usable.
    """
    cleaned = "".join(
        c if c.isalnum() or c in ("-", "_") else "_" for c in label.replace(" ", "_")
    ).strip("_")
    return cleaned or "users"


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_user_export_csv(request):
    """
    GET /api/admin/users/export/?is_ambassador=true&segment_label=Ambassadors
    Same filters as all_users_list/admin_user_emails_for_segment (via
    _build_admin_user_queryset) - whatever category/segment is currently
    selected on the mobile admin Users screen - but returns the matching
    users as a downloadable CSV (phone number, email, and basic contact
    info) instead of a paginated JSON list, for use in an external email
    campaign tool or a phone-call bot. Capped at
    MAX_SEGMENT_EMAIL_RECIPIENTS (10,000), same reasoning and same limit
    as admin_user_emails_for_segment - protects against an accidental
    "no filters" export being built from an unbounded queryset.
    segment_label is purely cosmetic (used for the downloaded filename)
    and doesn't affect which users match.
    """
    import csv
    from django.http import HttpResponse

    try:
        queryset, filters_applied = _build_admin_user_queryset(request.GET)
        users = queryset[:MAX_SEGMENT_EMAIL_RECIPIENTS]

        segment_label = _csv_safe_filename(request.GET.get('segment_label') or 'users')
        today_str = timezone.now().strftime('%Y-%m-%d')

        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = (
            f'attachment; filename="{segment_label}_{today_str}.csv"'
        )

        writer = csv.writer(response)
        writer.writerow([
            "First Name",
            "Last Name",
            "Email",
            "Phone Number",
            "Gender",
            "State",
            "Country",
            "KYC Status",
            "Date Joined",
        ])
        for user in users:
            writer.writerow([
                user.first_name or "",
                user.last_name or "",
                user.email or "",
                user.phone_number or "",
                user.gender or "",
                user.state or "",
                user.country or "",
                user.kyc_status or "",
                user.date_joined.strftime('%Y-%m-%d') if user.date_joined else "",
            ])

        return response

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_user_detail(request, user_id):
    """
    GET /api/admin/users/<user_id>/
    Full profile for a single user - no dedicated per-user admin detail
    endpoint existed before this (the webapp's admin Users page has no
    detail view at all, just a table).
    """
    try:
        user = CustomUser.objects.get(pk=user_id, is_deleted=False)
    except CustomUser.DoesNotExist:
        return Response({"error": "User not found."}, status=404)
    except (ValueError, TypeError):
        return Response({"error": "Invalid user id."}, status=400)

    serializer = AdminUserListSerializer(user, context={"request": request})
    return Response(serializer.data)


# Fields an admin can toggle for a user, same set Django's own /admin/
# exposes as bulk actions (make/revoke ambassador, ban/unban, staff
# toggle) - kept as an explicit whitelist rather than allowing arbitrary
# field mass-assignment.
USER_STATUS_TOGGLEABLE_FIELDS = {'is_ambassador', 'is_influencer', 'is_banned', 'is_staff', 'is_active'}


@api_view(['POST'])
@permission_classes([IsAdminUser])
def update_user_status(request, user_id):
    """
    POST /api/admin/users/<user_id>/update-status/
    Body: {"field": "is_ambassador", "value": true}
    Toggles one whitelisted boolean status field on a user - the same
    actions Django's own /admin/ panel exposes as bulk actions on
    CustomUserAdmin. is_ambassador goes through
    grant_user_ambassador_status/revoke_user_ambassador_status (utils.py)
    so the same push/email notification fires as when this is done via
    Django admin; is_banned also flips is_active off (matching
    CustomUserAdmin.ban_user's exact behavior); the rest are a plain
    attribute set.
    """
    field = request.data.get('field')
    value = request.data.get('value')

    if field not in USER_STATUS_TOGGLEABLE_FIELDS:
        return Response(
            {"error": f"Unsupported field '{field}'. Must be one of {sorted(USER_STATUS_TOGGLEABLE_FIELDS)}."},
            status=400,
        )
    if not isinstance(value, bool):
        return Response({"error": "'value' must be true or false."}, status=400)

    try:
        user = CustomUser.objects.get(pk=user_id, is_deleted=False)
    except CustomUser.DoesNotExist:
        return Response({"error": "User not found."}, status=404)
    except (ValueError, TypeError):
        return Response({"error": "Invalid user id."}, status=400)

    try:
        if field == 'is_ambassador':
            if value:
                grant_user_ambassador_status(user)
            else:
                revoke_user_ambassador_status(user)
        elif field == 'is_banned':
            user.is_banned = value
            update_fields = ['is_banned']
            if value:
                user.is_active = False
                update_fields.append('is_active')
            user.save(update_fields=update_fields)
        else:
            setattr(user, field, value)
            user.save(update_fields=[field])

        return Response({
            "id": user.id,
            "field": field,
            "value": getattr(user, field),
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_growth_rate(current, previous):
    """Calculate percentage growth rate"""
    if previous == 0 or previous is None:
        return 0
    
    growth = ((current - previous) / previous) * 100
    return round(growth, 2)


def calculate_wealth_stage(user):
    """Calculate user's wealth stage based on total savings and investments"""
    total = user.savings_and_investments
    
    if total == 0:
        stage = 1
    else:
        # Simple log-based calculation (adjust to your needs)
        import math
        stage = min(int(math.log10(total + 1)) + 1, 9)
    
    stage_texts = {
        1: "Getting Started",
        2: "Building Foundation",
        3: "Growing Wealth",
        4: "Accelerating",
        5: "Building Wealth",
        6: "Wealth Builder",
        7: "Prospering",
        8: "Wealthy",
        9: "Ultra Wealthy"
    }
    
    return {
        "stage": stage,
        "text": stage_texts.get(stage, "Unknown")
    }


# ============================================================================
# GROWTH METRICS ENDPOINTS
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAdminUser])
def monthly_active_savers(request):
    """
    GET /api/admin/metrics/monthly-active-savers?month=current
    Returns how many people saved/invested this month and total amount
    """
    month_param = request.GET.get('month', 'current')
    
    cache_key = f"metrics:mas:{month_param}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        if month_param == 'current':
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            # Parse custom month format YYYY-MM
            date_obj = datetime.strptime(month_param, '%Y-%m')
            month_start = timezone.make_aware(date_obj.replace(day=1))
        
        month_end = month_start + relativedelta(months=1)
        
        # Get savers (people who made credit transactions to SAVINGS) -
        # credited_to is the destination bucket; source is the funding
        # channel (bank transfer/card/wallet) and would wrongly exclude
        # nearly every real deposit.
        savers_data = Transaction.objects.filter(
            date__gte=month_start,
            date__lt=month_end,
            credited_to='SAVINGS',
            transaction_type='credit',
            status='confirmed'
        ).aggregate(
            unique_savers=Count('user', distinct=True),
            total_amount=Sum('amount')
        )

        # Get investors (people who made credit transactions to INVESTMENT)
        investors_data = Transaction.objects.filter(
            date__gte=month_start,
            date__lt=month_end,
            credited_to='INVESTMENT',
            transaction_type='credit',
            status='confirmed'
        ).aggregate(
            unique_investors=Count('user', distinct=True),
            total_amount=Sum('amount')
        )

        # Get users who did both
        savers_ids = set(Transaction.objects.filter(
            date__gte=month_start,
            date__lt=month_end,
            credited_to='SAVINGS',
            transaction_type='credit',
            status='confirmed'
        ).values_list('user', flat=True))

        investors_ids = set(Transaction.objects.filter(
            date__gte=month_start,
            date__lt=month_end,
            credited_to='INVESTMENT',
            transaction_type='credit',
            status='confirmed'
        ).values_list('user', flat=True))
        
        both_ids = savers_ids.intersection(investors_ids)
        total_active = len(savers_ids.union(investors_ids))
        
        response_data = {
            "period": month_start.strftime('%B %Y'),
            "total_active_savers": total_active,
            "savers": {
                "count": savers_data['unique_savers'] or 0,
                "total_amount": float(savers_data['total_amount'] or 0)
            },
            "investors": {
                "count": investors_data['unique_investors'] or 0,
                "total_amount": float(investors_data['total_amount'] or 0)
            },
            "both_savers_and_investors": len(both_ids),
            "total_amount": float((savers_data['total_amount'] or 0) + (investors_data['total_amount'] or 0))
        }
        
        cache.set(cache_key, response_data, 600)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def activated_users_percentage(request):
    """
    GET /api/admin/metrics/activated-users?month=current
    Returns % of new signups who saved/invested at least once
    Formula: (New users who signed up and saved / new signups) x 100%
    """
    month_param = request.GET.get('month', 'current')
    
    cache_key = f"metrics:activated:{month_param}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        if month_param == 'current':
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            date_obj = datetime.strptime(month_param, '%Y-%m')
            month_start = timezone.make_aware(date_obj.replace(day=1))
        
        month_end = month_start + relativedelta(months=1)
        
        # Get all new signups this month
        new_users = CustomUser.objects.filter(
            date_joined__gte=month_start,
            date_joined__lt=month_end,
            is_deleted=False
        )
        total_new_signups = new_users.count()
        
        # Get new users who made at least one confirmed transaction -
        # credited_to is the destination bucket (source is the funding
        # channel and would wrongly exclude nearly every real deposit).
        # distinct() matters here: a user with 2 confirmed deposits must
        # only count once, not be double-counted.
        activated_user_ids = list(Transaction.objects.filter(
            user__in=new_users,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed'
        ).values_list('user', flat=True).distinct())

        activated_count = len(activated_user_ids)

        # Calculate total amount saved by activated users
        total_saved = Transaction.objects.filter(
            user__in=activated_user_ids,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed'
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Calculate percentage
        activation_rate = (activated_count / total_new_signups * 100) if total_new_signups > 0 else 0
        
        response_data = {
            "period": month_start.strftime('%B %Y'),
            "total_new_signups": total_new_signups,
            "activated_users": activated_count,
            "activation_rate": round(activation_rate, 2),
            "total_amount_saved_by_activated": float(total_saved),
            "average_per_activated_user": float(total_saved / activated_count) if activated_count > 0 else 0
        }
        
        cache.set(cache_key, response_data, 600)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def retention_rate(request):
    """
    GET /api/admin/metrics/retention-rate
    Returns 30-day retention: users who saved again after 30 days
    Formula: (Activated users after 30 days / Users who joined 30 days ago) x 100%
    """
    cache_key = "metrics:retention:30day"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)
        sixty_days_ago = now - timedelta(days=60)
        
        # Get users who joined 30-60 days ago (cohort to measure)
        cohort_users = CustomUser.objects.filter(
            date_joined__gte=sixty_days_ago,
            date_joined__lt=thirty_days_ago,
            is_deleted=False
        )
        cohort_count = cohort_users.count()
        
        # Get users from cohort who made transactions in the last 30 days -
        # credited_to (destination bucket), not source (funding channel);
        # distinct() so a user with 2 confirmed deposits counts once.
        retained_user_ids = Transaction.objects.filter(
            user__in=cohort_users,
            date__gte=thirty_days_ago,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed'
        ).values_list('user', flat=True).distinct()

        retained_count = retained_user_ids.count()
        
        # Calculate retention rate
        retention_rate = (retained_count / cohort_count * 100) if cohort_count > 0 else 0
        
        response_data = {
            "cohort_period": f"{sixty_days_ago.strftime('%B %d')} - {thirty_days_ago.strftime('%B %d, %Y')}",
            "cohort_size": cohort_count,
            "retained_users": retained_count,
            "retention_rate": round(retention_rate, 2)
        }
        
        cache.set(cache_key, response_data, 600)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def active_investors_vs_savers(request):
    """
    GET /api/admin/metrics/investors-vs-savers
    Returns users who have investments / savings > 1
    """
    cache_key = "metrics:investors-vs-savers"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Users with more investments than savings
        investment_heavy = CustomUser.objects.filter(
            is_deleted=False,
            savings__gt=0
        ).annotate(
            ratio=F('investment') / F('savings')
        ).filter(ratio__gt=1).count()
        
        # Users with more savings than investments
        savings_heavy = CustomUser.objects.filter(
            is_deleted=False,
            investment__gt=0
        ).annotate(
            ratio=F('investment') / F('savings')
        ).filter(ratio__lte=1).count()
        
        # Users with only investments (no savings)
        investment_only = CustomUser.objects.filter(
            is_deleted=False,
            investment__gt=0,
            savings=0
        ).count()
        
        # Users with only savings (no investments)
        savings_only = CustomUser.objects.filter(
            is_deleted=False,
            savings__gt=0,
            investment=0
        ).count()
        
        total_active = investment_heavy + savings_heavy + investment_only + savings_only
        
        response_data = {
            "investment_heavy_users": investment_heavy,
            "savings_heavy_users": savings_heavy,
            "investment_only_users": investment_only,
            "savings_only_users": savings_only,
            "total_active_users": total_active,
            "investor_percentage": round((investment_heavy + investment_only) / total_active * 100, 2) if total_active > 0 else 0
        }
        
        cache.set(cache_key, response_data, 900)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def transaction_success_rate(request):
    """
    GET /api/admin/metrics/transaction-success-rate?period=30days
    Returns success vs failed transaction percentage
    Formula: (Failed transactions / Total transactions) x 100%
    """
    period = request.GET.get('period', '30days')
    
    cache_key = f"metrics:transaction-success:{period}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        if period == '30days':
            start_date = timezone.now() - timedelta(days=30)
        elif period == '7days':
            start_date = timezone.now() - timedelta(days=7)
        elif period == 'current_month':
            start_date = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            start_date = timezone.now() - timedelta(days=30)
        
        # Get transaction stats
        transaction_stats = Transaction.objects.filter(
            date__gte=start_date
        ).aggregate(
            total=Count('id'),
            confirmed=Count('id', filter=Q(status='confirmed')),
            failed=Count('id', filter=Q(status='failed')),
            pending=Count('id', filter=Q(status='pending'))
        )
        
        total = transaction_stats['total'] or 0
        confirmed = transaction_stats['confirmed'] or 0
        failed = transaction_stats['failed'] or 0
        pending = transaction_stats['pending'] or 0
        
        # Calculate rates
        success_rate = (confirmed / total * 100) if total > 0 else 0
        failure_rate = (failed / total * 100) if total > 0 else 0
        pending_rate = (pending / total * 100) if total > 0 else 0
        
        response_data = {
            "period": period,
            "total_transactions": total,
            "confirmed_transactions": confirmed,
            "failed_transactions": failed,
            "pending_transactions": pending,
            "success_rate": round(success_rate, 2),
            "failure_rate": round(failure_rate, 2),
            "pending_rate": round(pending_rate, 2)
        }
        
        cache.set(cache_key, response_data, 600)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ============================================================================
# GROWTH MULTIPLIERS ENDPOINTS
# ============================================================================

# Growth leaderboard - one endpoint backing all three "Top ..." cards on
# the mobile admin dashboard (referrals/ambassadors/influencers are all
# the same underlying computation: referred-signup counts, just scoped to
# a different subset of referrers). Replaces two previously broken
# endpoints here (top_referrals queried a `referred_by` field that never
# existed on CustomUser - the real field is `referral`; top_influencers
# queried an `influencer_code` field that never existed either - "hired
# referrer" users, now renamed `is_influencer`, are what this app actually
# calls influencers). Neither old endpoint was ever called by the mobile
# app or the web admin dashboard (both of those use the real, working
# /api/top-referrals/ instead), so nothing depended on the old shape.
GROWTH_LEADER_CATEGORIES = ("referrals", "ambassadors", "influencers", "engagement_team")
GROWTH_LEADER_RANGES = ("month", "last_month", "3months", "6months", "1year", "all")


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_top_performers(request):
    """
    GET /api/admin/multipliers/top-performers?category=referrals|ambassadors|influencers|engagement_team
        &range=month|3months|6months|1year|all&limit=20
    Leaderboard of referrers ranked by how many people they referred (and
    how many of those referrals were confirmed) within the selected
    range - same computation TopReferralsAPIView already does for a
    single user's own gamified ranking (see authentication/views.py),
    just admin-facing across everyone and period-configurable instead of
    locked to "this month".
    - category=referrals: every referrer.
    - category=ambassadors: referrers with is_ambassador=True only.
    - category=influencers: referrers with is_influencer=True only.
    - category=engagement_team: NOT a leaderboard (there's no referrer to
      rank - that's the point) - a plain count of signups with no
      referral/ambassador/influencer attribution at all (referral IS
      NULL) in the range, plus how many of those went on to start
      saving. This is a label of convenience for "nobody referred them,
      so we're crediting this to the company's own outreach" - it's
      really just every unattributed signup, which could in principle
      also include e.g. organic app-store discovery with no tracked
      source; there's no field that distinguishes those from genuine
      engagement-team-driven signups (how_did_you_hear is self-reported
      and free-text-ish, not a reliable attribution signal). Returns
      {"category", "range", "signups", "confirmed"} - no "leaderboard"
      key, since there's nothing to rank.
    """
    category = request.GET.get('category', 'referrals').strip().lower()
    if category not in GROWTH_LEADER_CATEGORIES:
        return Response(
            {"error": f"Invalid category '{category}'. Must be one of {GROWTH_LEADER_CATEGORIES}."},
            status=400,
        )

    range_key = request.GET.get('range', 'month').strip().lower()
    if range_key not in GROWTH_LEADER_RANGES:
        return Response(
            {"error": f"Invalid range '{range_key}'. Must be one of {GROWTH_LEADER_RANGES}."},
            status=400,
        )

    try:
        limit = int(request.GET.get('limit', 20))
    except (TypeError, ValueError):
        limit = 20
    limit = min(max(limit, 1), 100)

    cache_key = f"multipliers:top-performers:{category}:{range_key}:{limit}"
    cached_data = cache.get(cache_key)
    if cached_data:
        return Response(cached_data)

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    this_month_start = today_start.replace(day=1)

    # last_month is the one bounded window here (a fixed calendar month) -
    # same treatment as signup_summary's last_month above.
    if range_key == "last_month":
        start = this_month_start - relativedelta(months=1)
        end = this_month_start
    else:
        range_starts = {
            "month": this_month_start,
            "3months": today_start - relativedelta(months=3),
            "6months": today_start - relativedelta(months=6),
            "1year": today_start - relativedelta(years=1),
            "all": None,
        }
        start = range_starts[range_key]
        end = None

    try:
        if category == "engagement_team":
            qs = CustomUser.objects.filter(is_deleted=False, referral__isnull=True)
            if start is not None:
                qs = qs.filter(date_joined__gte=start)
            if end is not None:
                qs = qs.filter(date_joined__lt=end)

            signups = qs.count()
            # Same "started saving" definition as signup_summary/
            # not_yet_saved_this_month - a confirmed credit into savings
            # or investment, not just any transaction.
            activated_ids = Transaction.objects.filter(
                user__in=qs, credited_to__in=['SAVINGS', 'INVESTMENT'],
                transaction_type='credit', status='confirmed',
            ).values_list('user', flat=True).distinct()

            response_data = {
                "category": category,
                "range": range_key,
                "signups": signups,
                "confirmed": activated_ids.count(),
            }
            cache.set(cache_key, response_data, 900)
            return Response(response_data)

        referred_qs = CustomUser.objects.filter(is_deleted=False, referral__isnull=False)
        if start is not None:
            referred_qs = referred_qs.filter(date_joined__gte=start)
        if end is not None:
            referred_qs = referred_qs.filter(date_joined__lt=end)

        if category == "ambassadors":
            referred_qs = referred_qs.filter(referral__is_ambassador=True)
        elif category == "influencers":
            referred_qs = referred_qs.filter(referral__is_influencer=True)

        confirmed_filter = Q(referral_reward_granted=True)
        if start is not None:
            confirmed_filter &= Q(referral_reward_confirmed_at__gte=start)
        if end is not None:
            confirmed_filter &= Q(referral_reward_confirmed_at__lt=end)

        stats = (
            referred_qs
            .values('referral')
            .annotate(
                signups=Count('id'),
                confirmed=Count('id', filter=confirmed_filter),
            )
            .order_by('-confirmed', '-signups')[:limit]
        )

        referrer_ids = [s['referral'] for s in stats]
        referrers = CustomUser.objects.in_bulk(referrer_ids)

        leaderboard = []
        for stat in stats:
            referrer = referrers.get(stat['referral'])
            if not referrer:
                continue
            leaderboard.append({
                "user_id": referrer.id,
                "first_name": referrer.first_name,
                "last_name": referrer.last_name,
                "email": referrer.email,
                "profile_picture": referrer.profile_picture or "",
                "is_ambassador": referrer.is_ambassador,
                "is_influencer": referrer.is_influencer,
                "signups": stat['signups'],
                "confirmed": stat['confirmed'],
            })

        response_data = {
            "category": category,
            "range": range_key,
            "leaderboard": leaderboard,
        }

        cache.set(cache_key, response_data, 900)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


import uuid
from decimal import InvalidOperation
from datetime import datetime as dt
from django.db import transaction as db_transaction, IntegrityError
from .models import Group, GroupOwnership, GroupIncomeEvent, GroupIncomeDistribution
from .utils import create_transaction, split_amount_by_percentage
from .serializers import GroupIncomeEventSerializer


@api_view(["POST"])
@permission_classes([IsAdminUser])
def distribute_groupbuy_income(request, group_id):
    """
    POST /api/admin/groupbuy/<group_id>/distribute-income/

    Staff-only. Records that a GroupBuy's property earned income for a given
    period, then distributes it to every member's wallet in proportion to
    their GroupOwnership.ownership_percentage.
    """
    try:
        group_uuid = uuid.UUID(str(group_id))
    except ValueError:
        return Response(
            {"message": "Invalid group ID. It must be a valid UUID."}, status=400
        )

    try:
        group = Group.objects.get(id=group_uuid)
    except Group.DoesNotExist:
        return Response({"message": "Group not found."}, status=404)

    if group.status != "completed":
        return Response(
            {
                "message": "Income can only be distributed for a GroupBuy whose "
                "status is 'completed'. Mark the group completed in Django admin first."
            },
            status=400,
        )

    try:
        amount = Decimal(str(request.data.get("amount")))
    except (TypeError, InvalidOperation):
        return Response({"message": "Invalid or missing amount."}, status=400)

    if amount <= 0:
        return Response({"message": "Amount must be greater than zero."}, status=400)

    period_start_raw = request.data.get("period_start")
    period_end_raw = request.data.get("period_end")
    if not period_start_raw or not period_end_raw:
        return Response(
            {"message": "period_start and period_end are required (YYYY-MM-DD)."},
            status=400,
        )

    try:
        period_start = dt.strptime(period_start_raw, "%Y-%m-%d").date()
        period_end = dt.strptime(period_end_raw, "%Y-%m-%d").date()
    except ValueError:
        return Response(
            {"message": "period_start/period_end must be in YYYY-MM-DD format."},
            status=400,
        )

    if period_end < period_start:
        return Response({"message": "period_end cannot be before period_start."}, status=400)

    description = request.data.get("description", "")

    try:
        with db_transaction.atomic():
            event = GroupIncomeEvent.objects.create(
                group=group,
                recorded_by=request.user,
                amount=amount,
                period_start=period_start,
                period_end=period_end,
                description=description,
            )

            # Note: can't combine select_for_update() with a GROUP BY/annotate
            # query (Postgres rejects "FOR UPDATE" with GROUP BY), so lock the
            # raw rows first and aggregate per-user in Python instead.
            ownership_rows = list(
                GroupOwnership.objects.select_for_update().filter(group=group)
            )
            pct_by_user = {}
            for row in ownership_rows:
                pct_by_user[row.user_id] = (
                    pct_by_user.get(row.user_id, Decimal("0")) + row.ownership_percentage
                )
            ownership_pairs = [
                (user_id, pct) for user_id, pct in pct_by_user.items() if pct > 0
            ]

            if not ownership_pairs:
                raise ValueError(
                    "This group has no members with a positive ownership percentage."
                )

            shares = split_amount_by_percentage(amount, ownership_pairs)
            pct_lookup = dict(ownership_pairs)
            user_lookup = {
                u.id: u for u in CustomUser.objects.filter(id__in=shares.keys())
            }
            total_distributed = Decimal("0.00")

            for user_id, share in shares.items():
                if share <= 0:
                    continue
                member = user_lookup[user_id]
                tx = create_transaction(
                    user=member,
                    amount=share,
                    transaction_type="credit",
                    source="WALLET",
                    credited_to="WALLET",
                    status="confirmed",
                    description=(
                        f"GroupBuy income: {group.property.name} "
                        f"({period_start} - {period_end})"
                    ),
                )
                GroupIncomeDistribution.objects.create(
                    income_event=event,
                    user=member,
                    ownership_percentage=pct_lookup[user_id],
                    amount=share,
                    transaction=tx,
                    status="paid",
                )
                total_distributed += share

            event.status = "completed"
            event.total_distributed = total_distributed
            event.completed_at = timezone.now()
            event.save()
    except IntegrityError:
        return Response(
            {"message": "Income has already been recorded for this group and period."},
            status=409,
        )
    except ValueError as e:
        return Response({"message": str(e)}, status=400)

    from .tasks import distribute_groupbuy_income_notifications

    distribute_groupbuy_income_notifications.delay(str(event.id))

    return Response(GroupIncomeEventSerializer(event).data, status=201)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def groupbuy_metrics(request):
    """
    GET /api/admin/multipliers/groupbuys
    Returns active vs failed groupbuys
    """
    cache_key = "multipliers:groupbuys"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        from .models import Group, GroupIncomeEvent

        groupbuy_stats = Group.objects.aggregate(
            active=Count("id", filter=Q(status="active")),
            successful=Count("id", filter=Q(status="completed")),
            failed=Count("id", filter=Q(status="failed")),
            total=Count("id"),
            total_raised=Coalesce(Sum("total_raised"), Value(0, output_field=DecimalField())),
            total_goal=Coalesce(Sum("goal_amount"), Value(0, output_field=DecimalField())),
        )

        total = groupbuy_stats["total"] or 0
        # "Successful" here means fully funded (status=completed), not yet
        # decided/still raising (active) - failed groups missed their deadline.
        decided = groupbuy_stats["successful"] + groupbuy_stats["failed"]
        success_rate = (groupbuy_stats["successful"] / decided * 100) if decided > 0 else 0

        total_income_distributed = GroupIncomeEvent.objects.filter(
            status="completed"
        ).aggregate(total=Coalesce(Sum("total_distributed"), Value(0, output_field=DecimalField())))["total"]

        response_data = {
            "active_groupbuys": groupbuy_stats["active"],
            "successful_groupbuys": groupbuy_stats["successful"],
            "failed_groupbuys": groupbuy_stats["failed"],
            "total_groupbuys": total,
            "success_rate": round(success_rate, 2),
            "total_raised": float(groupbuy_stats["total_raised"]),
            "total_goal_amount": float(groupbuy_stats["total_goal"]),
            "total_income_distributed": float(total_income_distributed),
        }

        cache.set(cache_key, response_data, 900)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ============================================================================
# FINANCIAL STRENGTH & MOMENTUM ENDPOINTS
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAdminUser])
def funds_under_management(request):
    """
    GET /api/admin/financial/fum
    Returns total funds under management (all user balances)
    """
    cache_key = "financial:fum"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Calculate total FUM
        fum_data = CustomUser.objects.filter(
            is_deleted=False
        ).aggregate(
            total_savings=Sum('savings'),
            total_investments=Sum('investment'),
            total_fum=Sum(F('savings') + F('investment'))
        )
        
        # Get user distribution
        users_with_balance = CustomUser.objects.filter(
            is_deleted=False
        ).annotate(
            total_balance=F('savings') + F('investment')
        ).filter(total_balance__gt=0).count()
        
        total_users = CustomUser.objects.filter(is_deleted=False).count()
        
        # Calculate average per user
        avg_per_user = (fum_data['total_fum'] or 0) / total_users if total_users > 0 else 0
        
        response_data = {
            "total_fum": float(fum_data['total_fum'] or 0),
            "total_savings": float(fum_data['total_savings'] or 0),
            "total_investments": float(fum_data['total_investments'] or 0),
            "total_users": total_users,
            "users_with_balance": users_with_balance,
            "average_per_user": round(float(avg_per_user), 2)
        }
        
        cache.set(cache_key, response_data, 300)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def net_fum_change(request):
    """
    GET /api/admin/financial/net-fum-change?period=week
    Returns net change in FUM (money added - money withdrawn)
    Formula: Total Money added - Money withdrawn
    """
    period = request.GET.get('period', 'week')
    
    cache_key = f"financial:net-fum:{period}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Calculate date range
        now = timezone.now()
        if period == 'week':
            start_date = now - timedelta(days=7)
            period_label = "This Week"
        elif period == 'month':
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            period_label = "This Month"
        elif period == 'day':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            period_label = "Today"
        else:
            start_date = now - timedelta(days=7)
            period_label = "This Week"
        
        # Calculate money added (credit transactions) - credited_to is the
        # destination bucket; source is the funding channel (bank
        # transfer/card/wallet) and would wrongly exclude nearly every
        # real deposit.
        money_added = Transaction.objects.filter(
            date__gte=start_date,
            transaction_type='credit',
            status='confirmed',
            credited_to__in=['SAVINGS', 'INVESTMENT']
        ).aggregate(total=Sum('amount'))['total'] or 0

        # Calculate money withdrawn (debit transactions) - source is
        # correct here: it's the bucket funds were withdrawn FROM.
        money_withdrawn = Transaction.objects.filter(
            date__gte=start_date,
            transaction_type='debit',
            status='confirmed',
            source__in=['SAVINGS', 'INVESTMENT']
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Calculate net change
        net_change = float(money_added) - float(money_withdrawn)
        
        # Calculate change percentage
        if money_withdrawn > 0:
            change_percentage = (net_change / float(money_withdrawn)) * 100
        else:
            change_percentage = 100 if net_change > 0 else 0
        
        response_data = {
            "period": period_label,
            "money_added": float(money_added),
            "money_withdrawn": float(money_withdrawn),
            "net_change": net_change,
            "change_percentage": round(change_percentage, 2),
            "is_positive": net_change >= 0
        }
        
        cache.set(cache_key, response_data, 600)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def churn_rate(request):
    """
    GET /api/admin/financial/churn-rate?period=30days
    Returns churn rate: users who stopped using MyFund
    Formula: (Users who left or inactive / Total users) x 100
    """
    period = request.GET.get('period', '30days')
    
    cache_key = f"financial:churn:{period}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Define inactivity threshold
        if period == '30days':
            inactive_threshold = timezone.now() - timedelta(days=30)
        elif period == '60days':
            inactive_threshold = timezone.now() - timedelta(days=60)
        elif period == '90days':
            inactive_threshold = timezone.now() - timedelta(days=90)
        else:
            inactive_threshold = timezone.now() - timedelta(days=30)
        
        # Total users
        total_users = CustomUser.objects.filter(is_deleted=False).count()
        
        # Inactive users (no transactions in the period)
        active_user_ids = Transaction.objects.filter(
            date__gte=inactive_threshold,
            status='confirmed'
        ).values_list('user', flat=True).distinct()
        
        inactive_users = total_users - len(set(active_user_ids))
        
        # Users who explicitly deleted account
        deleted_users = CustomUser.objects.filter(is_deleted=True).count()
        
        # Calculate churn rate
        churn_rate = (inactive_users / total_users * 100) if total_users > 0 else 0
        
        response_data = {
            "period": period,
            "total_users": total_users,
            "active_users": len(set(active_user_ids)),
            "inactive_users": inactive_users,
            "deleted_users": deleted_users,
            "churn_rate": round(churn_rate, 2),
            "retention_rate": round(100 - churn_rate, 2)
        }

        cache.set(cache_key, response_data, 900)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ============================================================================
# ADMIN METRICS DASHBOARD (mobile app - 7-category overview)
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAdminUser])
def signup_metrics(request):
    """
    GET /api/admin/metrics/signups?month=current
    Returns new-signup totals for the month vs the prior month, a
    week-by-week breakdown within the month, and how many of the month's
    new signups have made at least one confirmed SAVINGS/INVESTMENT credit
    transaction (i.e. "started saving").
    """
    month_param = request.GET.get('month', 'current')

    cache_key = f"metrics:signups:{month_param}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        if month_param == 'current':
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            date_obj = datetime.strptime(month_param, '%Y-%m')
            month_start = timezone.make_aware(date_obj.replace(day=1))

        month_end = month_start + relativedelta(months=1)
        prev_month_start = month_start - relativedelta(months=1)

        this_month_total = CustomUser.objects.filter(
            date_joined__gte=month_start, date_joined__lt=month_end, is_deleted=False
        ).count()
        last_month_total = CustomUser.objects.filter(
            date_joined__gte=prev_month_start, date_joined__lt=month_start, is_deleted=False
        ).count()

        if last_month_total > 0:
            growth_rate = ((this_month_total - last_month_total) / last_month_total) * 100
        else:
            growth_rate = 100.0 if this_month_total > 0 else 0.0
        growth_rate_str = f"{'+' if growth_rate >= 0 else ''}{round(growth_rate, 1)}%"

        # Week-by-week breakdown within the month. Week 4 absorbs any
        # trailing days in months longer than 28 days, rather than trying
        # to create a partial 5th week.
        days_in_month = (month_end - month_start).days
        weekly_counts = [0, 0, 0, 0]
        new_users_qs = CustomUser.objects.filter(
            date_joined__gte=month_start, date_joined__lt=month_end, is_deleted=False
        )
        for user in new_users_qs.only('date_joined'):
            day_of_month = user.date_joined.day
            week_index = min(3, (day_of_month - 1) // 7)
            weekly_counts[week_index] += 1

        weekly_breakdown = []
        for i in range(4):
            week_start_day = i * 7 + 1
            week_end_day = days_in_month if i == 3 else min(days_in_month, (i + 1) * 7)
            weekly_breakdown.append({
                "week": i + 1,
                "label": f"{month_start.strftime('%b')} {week_start_day}-{week_end_day}",
                "count": weekly_counts[i],
            })

        # credited_to is the destination bucket a deposit landed in;
        # source is the funding channel (bank transfer/card/wallet) and
        # would wrongly exclude nearly every real deposit - this was the
        # actual bug behind "new savers this month" undercounting.
        activated_count = Transaction.objects.filter(
            user__in=new_users_qs,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed',
        ).values('user').distinct().count()

        activation_rate = (activated_count / this_month_total * 100) if this_month_total > 0 else 0

        response_data = {
            "period": month_start.strftime('%B %Y'),
            "this_month_total": this_month_total,
            "last_month_total": last_month_total,
            "growth_rate": growth_rate_str,
            "weekly_breakdown": weekly_breakdown,
            "activated_count": activated_count,
            "activation_rate": round(activation_rate, 2),
            "not_yet_saved_count": this_month_total - activated_count,
        }

        cache.set(cache_key, response_data, 300)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


SIGNUP_SUMMARY_RANGES = ("today", "month", "last_month", "3months", "6months", "1year", "all")


@api_view(['GET'])
@permission_classes([IsAdminUser])
def signup_summary(request):
    """
    GET /api/admin/metrics/signups/summary?range=today|month|last_month|3months|6months|1year|all
    Total new signups and how many of them have "started saving" (a
    confirmed SAVINGS/INVESTMENT credit) for the selected window, plus a
    growth_rate vs the immediately preceding window of the same length -
    same range-picker convention as admin_transactions_summary, just for
    the Signups card's own range control (This Month/Last Month/3
    Months/6 Months/1 Year/All Time) - the existing signup_metrics above
    only ever compares one calendar month against the prior one.
    """
    range_key = request.GET.get('range', 'month').strip().lower()
    if range_key not in SIGNUP_SUMMARY_RANGES:
        return Response(
            {"error": f"Invalid range '{range_key}'. Must be one of {SIGNUP_SUMMARY_RANGES}."},
            status=400,
        )

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    this_month_start = today_start.replace(day=1)

    try:
        # last_month is the one bounded window here (a fixed [start, end)
        # calendar month) - every other range is open-ended through now,
        # so it needs its own end rather than reusing the generic
        # range_starts dict below.
        if range_key == "last_month":
            start = this_month_start - relativedelta(months=1)
            end = this_month_start
        else:
            range_starts = {
                "today": today_start,
                "month": this_month_start,
                "3months": today_start - relativedelta(months=3),
                "6months": today_start - relativedelta(months=6),
                "1year": today_start - relativedelta(years=1),
                "all": None,
            }
            start = range_starts[range_key]
            end = None

        base_qs = CustomUser.objects.filter(is_deleted=False)
        current_qs = base_qs
        if start is not None:
            current_qs = current_qs.filter(date_joined__gte=start)
        if end is not None:
            current_qs = current_qs.filter(date_joined__lt=end)
        total_signups = current_qs.count()

        # credited_to (destination bucket), not source (funding channel) -
        # same fix signup_metrics's activated_count above already applies.
        started_saving_count = Transaction.objects.filter(
            user__in=current_qs,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed',
        ).values('user').distinct().count()

        growth_rate = None
        if start is not None:
            period_length = (end or now) - start
            prev_start = start - period_length
            prev_total = base_qs.filter(
                date_joined__gte=prev_start, date_joined__lt=start,
            ).count()
            if prev_total > 0:
                growth_rate = ((total_signups - prev_total) / prev_total) * 100
            else:
                growth_rate = 100.0 if total_signups > 0 else 0.0

        return Response({
            "range": range_key,
            "total_signups": total_signups,
            "started_saving_count": started_saving_count,
            "not_yet_saved_count": max(total_signups - started_saving_count, 0),
            "growth_rate": (
                f"{'+' if growth_rate >= 0 else ''}{round(growth_rate, 1)}%"
                if growth_rate is not None
                else None
            ),
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


SIGNUP_USER_LIST_CAP = 500


@api_view(['GET'])
@permission_classes([IsAdminUser])
def signup_segment_users(request):
    """
    GET /api/admin/metrics/signups/users?segment=new|activated|not_yet_saved&month=current
    Drill-down list behind signup_metrics's aggregate counts - "new" is
    every signup in the month, "activated" is the same credited_to-based
    check signup_metrics uses (kept in lockstep so the list and the count
    can never disagree), "not_yet_saved" is the complement.
    """
    segment = request.GET.get('segment', 'new')
    month_param = request.GET.get('month', 'current')

    if segment not in ('new', 'activated', 'not_yet_saved'):
        return Response({"error": f"Unknown segment '{segment}'."}, status=400)

    try:
        if month_param == 'current':
            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            date_obj = datetime.strptime(month_param, '%Y-%m')
            month_start = timezone.make_aware(date_obj.replace(day=1))

        month_end = month_start + relativedelta(months=1)

        new_users_qs = CustomUser.objects.filter(
            date_joined__gte=month_start, date_joined__lt=month_end, is_deleted=False
        )

        activated_ids = Transaction.objects.filter(
            user__in=new_users_qs,
            credited_to__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed',
        ).values_list('user', flat=True).distinct()

        if segment == 'activated':
            users_qs = new_users_qs.filter(id__in=list(activated_ids))
        elif segment == 'not_yet_saved':
            users_qs = new_users_qs.exclude(id__in=list(activated_ids))
        else:
            users_qs = new_users_qs

        total_count = users_qs.count()
        activated_id_set = set(activated_ids)
        users = users_qs.order_by('-date_joined')[:SIGNUP_USER_LIST_CAP]

        data = [
            {
                "id": u.id,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "email": u.email,
                "phone_number": u.phone_number,
                "date_joined": u.date_joined,
                "kyc_status": u.kyc_status,
                "has_saved": u.id in activated_id_set,
            }
            for u in users
        ]

        return Response({
            "segment": segment,
            "period": month_start.strftime('%B %Y'),
            "total_count": total_count,
            "truncated": total_count > SIGNUP_USER_LIST_CAP,
            "data": data,
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def cashflow_summary(request):
    """
    GET /api/admin/financial/cashflow-summary
    Returns total saved, invested, and withdrawn this month vs last month,
    plus a snapshot of scheduled withdrawal requests. Withdrawals are
    defined as confirmed debit transactions out of SAVINGS/INVESTMENT,
    mirroring net_fum_change's "money_withdrawn" definition.
    """
    cache_key = "financial:cashflow-summary"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        now = timezone.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        prev_month_start = month_start - relativedelta(months=1)

        def rate_str(current, previous):
            if previous > 0:
                rate = ((current - previous) / previous) * 100
            else:
                rate = 100.0 if current > 0 else 0.0
            return f"{'+' if rate >= 0 else ''}{round(rate, 1)}%"

        def sum_for_range(start, end, transaction_type, source=None, source__in=None, credited_to=None):
            qs = Transaction.objects.filter(
                date__gte=start, date__lt=end,
                transaction_type=transaction_type, status='confirmed',
            )
            if source:
                qs = qs.filter(source=source)
            if source__in:
                qs = qs.filter(source__in=source__in)
            if credited_to:
                qs = qs.filter(credited_to=credited_to)
            return float(qs.aggregate(total=Sum('amount'))['total'] or 0)

        # Deposits: credited_to is the destination bucket (source is the
        # funding channel - bank transfer/card/wallet - and would wrongly
        # exclude nearly every real deposit). Withdrawals below correctly
        # use source, since that's the bucket funds were withdrawn FROM.
        def build_metric(credited_to):
            this_month = sum_for_range(month_start, now, 'credit', credited_to=credited_to)
            last_month = sum_for_range(prev_month_start, month_start, 'credit', credited_to=credited_to)
            return {
                "this_month": this_month,
                "last_month": last_month,
                "growth_rate": rate_str(this_month, last_month),
            }

        total_saved = build_metric('SAVINGS')
        total_invested = build_metric('INVESTMENT')

        this_month_withdrawals = sum_for_range(
            month_start, now, 'debit', source__in=['SAVINGS', 'INVESTMENT']
        )
        last_month_withdrawals = sum_for_range(
            prev_month_start, month_start, 'debit', source__in=['SAVINGS', 'INVESTMENT']
        )
        total_withdrawals = {
            "this_month": this_month_withdrawals,
            "last_month": last_month_withdrawals,
            "growth_rate": rate_str(this_month_withdrawals, last_month_withdrawals),
        }

        scheduled_agg = WithdrawalsRequestToAdmin.objects.filter(
            withdrawal_type='scheduled'
        ).aggregate(
            count=Count('id'),
            total_amount=Sum('total_amount'),
            pending_count=Count('id', filter=Q(status='pending')),
            processing_count=Count('id', filter=Q(status='processing')),
        )

        response_data = {
            "period": month_start.strftime('%B %Y'),
            "total_saved": total_saved,
            "total_invested": total_invested,
            "total_withdrawals": total_withdrawals,
            "scheduled_withdrawals": {
                "count": scheduled_agg['count'] or 0,
                "total_amount": float(scheduled_agg['total_amount'] or 0),
                "pending_count": scheduled_agg['pending_count'] or 0,
                "processing_count": scheduled_agg['processing_count'] or 0,
            },
        }

        cache.set(cache_key, response_data, 300)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


CASHFLOW_RANGE_SUMMARY_RANGES = ("today", "month", "last_month", "3months", "6months", "1year", "all")


@api_view(['GET'])
@permission_classes([IsAdminUser])
def cashflow_range_summary(request):
    """
    GET /api/admin/financial/cashflow-summary/range?range=today|month|last_month|3months|6months|1year|all
    Range-picker version of cashflow_summary above (This Month/Last
    Month/3 Months/6 Months/1 Year/All Time), for the dashboard's global
    range control (see AdminDashboard.js - the same picker also drives
    Signups/Growth/Transactions). cashflow_summary itself stays
    month-only/untouched, since AdminCashflowDetailScreen.js's own
    weekly/trend breakdown still needs that fixed this-month-vs-last-month
    shape.
    """
    range_key = request.GET.get('range', 'month').strip().lower()
    if range_key not in CASHFLOW_RANGE_SUMMARY_RANGES:
        return Response(
            {"error": f"Invalid range '{range_key}'. Must be one of {CASHFLOW_RANGE_SUMMARY_RANGES}."},
            status=400,
        )

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    this_month_start = today_start.replace(day=1)

    try:
        if range_key == "last_month":
            start = this_month_start - relativedelta(months=1)
            end = this_month_start
        else:
            range_starts = {
                "today": today_start,
                "month": this_month_start,
                "3months": today_start - relativedelta(months=3),
                "6months": today_start - relativedelta(months=6),
                "1year": today_start - relativedelta(years=1),
                "all": None,
            }
            start = range_starts[range_key]
            end = None

        def sum_for(win_start, win_end, transaction_type, source__in=None, credited_to=None):
            qs = Transaction.objects.filter(transaction_type=transaction_type, status='confirmed')
            if win_start is not None:
                qs = qs.filter(date__gte=win_start)
            if win_end is not None:
                qs = qs.filter(date__lt=win_end)
            if source__in:
                qs = qs.filter(source__in=source__in)
            if credited_to:
                qs = qs.filter(credited_to=credited_to)
            return float(qs.aggregate(total=Sum('amount'))['total'] or 0)

        def rate_str(current, previous):
            if previous > 0:
                rate = ((current - previous) / previous) * 100
            else:
                rate = 100.0 if current > 0 else 0.0
            return f"{'+' if rate >= 0 else ''}{round(rate, 1)}%"

        prev_start = prev_end = None
        if start is not None:
            period_length = (end or now) - start
            prev_start = start - period_length
            prev_end = start

        def build_metric(transaction_type, **filters):
            current = sum_for(start, end, transaction_type, **filters)
            if start is None:
                return {"amount": current, "growth_rate": None}
            previous = sum_for(prev_start, prev_end, transaction_type, **filters)
            return {"amount": current, "growth_rate": rate_str(current, previous)}

        total_saved = build_metric('credit', credited_to='SAVINGS')
        total_invested = build_metric('credit', credited_to='INVESTMENT')
        total_withdrawals = build_metric('debit', source__in=['SAVINGS', 'INVESTMENT'])

        return Response({
            "range": range_key,
            "total_saved": total_saved,
            "total_invested": total_invested,
            "total_withdrawals": total_withdrawals,
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def target_savings_breakdown(request):
    """
    GET /api/admin/metrics/target-savings
    Returns target savings counts by outcome: in_progress (still active,
    not cancelled), and completed/failed/cancelled read from
    TargetSavingsCompletion - the authoritative record for finished
    targets, distinct from the live TargetSavings row.
    """
    cache_key = "metrics:target-savings-breakdown"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        in_progress = TargetSavings.objects.filter(is_active=True, is_cancelled=False).count()

        completion_counts = TargetSavingsCompletion.objects.values('status').annotate(count=Count('id'))
        status_map = {row['status']: row['count'] for row in completion_counts}

        completed = status_map.get('SUCCESS', 0)
        failed = status_map.get('FAILED', 0)
        cancelled = status_map.get('CANCELLED', 0)

        response_data = {
            "in_progress": in_progress,
            "completed": completed,
            "failed": failed,
            "cancelled": cancelled,
            "total": in_progress + completed + failed + cancelled,
        }

        cache.set(cache_key, response_data, 900)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def user_activity_segments(request):
    """
    GET /api/admin/metrics/user-activity
    Segments users into active/dormant/inactive:
      - active: made a confirmed transaction in the last 30 days
      - dormant: not active, but has a non-zero balance or has made a
        confirmed transaction at some point (i.e. not a clean zero)
      - inactive: never made a confirmed transaction and has zero balance
    Also returns the same breakdown as of the last day of the previous
    month for a month-over-month comparison. That comparison recomputes
    transaction recency at that past point in time, but balance fields
    (savings/investment/wallet) only reflect their CURRENT values - there's
    no historical balance snapshot table, so the "last month" balance-based
    half of the dormant/inactive split is an approximation, not a true
    historical reconstruction.
    Deliberately NOT using CustomUser.updated_at as an activity proxy (see
    user_metrics_chart) - that field changes on almost any save and doesn't
    reflect real transaction activity.

    Counts only - the mobile app's User Activity drill-down (tap Active/
    Dormant/Inactive) gets the actual per-user list via all_users_list /
    admin_user_export_csv / admin_user_emails_for_segment, all filterable
    by the same segmentation through _build_admin_user_queryset's
    `activity` param (shares _annotate_activity with this view so the two
    can't drift apart).

    Also returns "engaged" - a coarser, second cut across the same user
    base answering "is this a real, live account at all" rather than
    "how recently did they transact": non-zero balance OR ever
    transacted OR active (logged in, or the app re-registered its push
    token - see CustomUser.last_active_at) in the last 6 months. The
    complement is a genuinely dead account - never funded, never
    transacted, never seen the app in 6+ months. Reported as a
    percentage of total_users, with a percentage-point (not relative %)
    month-over-month delta - "+2.1pts" reads unambiguously, "+2.1%"
    could be misread as the count growing 2.1%. Same last-month caveat
    as dormant/inactive above for the balance/last_active_at halves
    (current values only, no historical snapshot) - only the
    ever-transacted half is a true historical reconstruction.
    """
    cache_key = "metrics:user-activity-segments"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        def segment_counts(as_of):
            users = _annotate_activity(
                CustomUser.objects.filter(is_deleted=False), as_of,
            )

            total = users.count()
            active = users.filter(has_recent_tx=True).count()
            has_balance_q = Q(savings__gt=0) | Q(investment__gt=0) | Q(wallet__gt=0)
            dormant = users.filter(
                Q(has_recent_tx=False) & (has_balance_q | Q(has_any_tx=True))
            ).count()
            inactive = total - active - dormant

            return active, dormant, inactive, total

        def engaged_counts(as_of):
            users = _annotate_activity(
                CustomUser.objects.filter(is_deleted=False), as_of,
            )
            has_balance_q = Q(savings__gt=0) | Q(investment__gt=0) | Q(wallet__gt=0)
            six_months_ago = as_of - relativedelta(months=6)
            recently_active_q = Q(last_active_at__gte=six_months_ago)

            total = users.count()
            engaged = users.filter(
                Q(has_any_tx=True) | has_balance_q | recently_active_q
            ).count()
            return engaged, total

        now = timezone.now()
        this_active, this_dormant, this_inactive, total_users = segment_counts(now)
        this_engaged, _ = engaged_counts(now)

        last_month_point = now.replace(day=1) - timedelta(days=1)
        last_active, last_dormant, last_inactive, _ = segment_counts(last_month_point)
        last_engaged, _ = engaged_counts(last_month_point)

        def rate_str(current, previous):
            if previous > 0:
                rate = ((current - previous) / previous) * 100
            else:
                rate = 100.0 if current > 0 else 0.0
            return f"{'+' if rate >= 0 else ''}{round(rate, 1)}%"

        this_engaged_pct = round((this_engaged / total_users) * 100, 1) if total_users else 0.0
        last_engaged_pct = round((last_engaged / total_users) * 100, 1) if total_users else 0.0
        pct_point_delta = round(this_engaged_pct - last_engaged_pct, 1)
        engaged_trend = f"{'+' if pct_point_delta >= 0 else ''}{pct_point_delta}pts"

        response_data = {
            "as_of": now.date().isoformat(),
            "active": {
                "this_month": this_active, "last_month": last_active,
                "growth_rate": rate_str(this_active, last_active),
            },
            "dormant": {
                "this_month": this_dormant, "last_month": last_dormant,
                "growth_rate": rate_str(this_dormant, last_dormant),
            },
            "inactive": {
                "this_month": this_inactive, "last_month": last_inactive,
                "growth_rate": rate_str(this_inactive, last_inactive),
            },
            "engaged": {
                "this_month": this_engaged, "last_month": last_engaged,
                "percentage": this_engaged_pct,
                "percentage_last_month": last_engaged_pct,
                "trend": engaged_trend,
            },
            "total_users": total_users,
        }

        cache.set(cache_key, response_data, 1800)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def transaction_type_breakdown(request):
    """
    GET /api/admin/metrics/transaction-types?period=current_month
        (also accepts the dashboard's global range keys - today/month/
        last_month/3months/6months/1year/all - since this is the
        Transactions category card's data source and the dashboard now
        has one range picker driving Signups/Growth/Cashflow/Transactions
        together; the original 30days/7days/current_month values still
        work too, kept for backward compatibility.)
    Returns confirmed transaction counts/amounts split by credit vs debit
    for the given period, plus how many carried a service charge.
    """
    period = request.GET.get('period', 'current_month')

    cache_key = f"metrics:transaction-types:{period}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        this_month_start = today_start.replace(day=1)
        end_date = None

        if period == '30days':
            start_date = now - timedelta(days=30)
        elif period == '7days':
            start_date = now - timedelta(days=7)
        elif period == 'today':
            start_date = today_start
        elif period == 'last_month':
            start_date = this_month_start - relativedelta(months=1)
            end_date = this_month_start
        elif period == '3months':
            start_date = today_start - relativedelta(months=3)
        elif period == '6months':
            start_date = today_start - relativedelta(months=6)
        elif period == '1year':
            start_date = today_start - relativedelta(years=1)
        elif period == 'all':
            start_date = None
        else:
            period = 'current_month'
            start_date = this_month_start

        base_qs = Transaction.objects.filter(status='confirmed')
        if start_date is not None:
            base_qs = base_qs.filter(date__gte=start_date)
        if end_date is not None:
            base_qs = base_qs.filter(date__lt=end_date)

        credit_agg = base_qs.filter(transaction_type='credit').aggregate(
            count=Count('id'), total_amount=Sum('amount')
        )
        debit_agg = base_qs.filter(transaction_type='debit').aggregate(
            count=Count('id'), total_amount=Sum('amount')
        )
        charges_agg = base_qs.filter(service_charge__gt=0).aggregate(
            count=Count('id'), total_service_charge=Sum('service_charge')
        )

        response_data = {
            "period": period,
            "credit": {
                "count": credit_agg['count'] or 0,
                "total_amount": float(credit_agg['total_amount'] or 0),
            },
            "debit": {
                "count": debit_agg['count'] or 0,
                "total_amount": float(debit_agg['total_amount'] or 0),
            },
            "with_charges": {
                "count": charges_agg['count'] or 0,
                "total_service_charge": float(charges_agg['total_service_charge'] or 0),
            },
        }

        cache.set(cache_key, response_data, 300)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def property_inventory(request):
    """
    GET /api/admin/metrics/properties
    Returns total properties bought (direct purchases only -
    CustomUser.properties is incremented on every successful
    BuyPropertyView purchase) and total units still available across
    listings. GroupBuy-acquired ownership is reported separately by
    /api/admin/multipliers/groupbuys and never touches
    CustomUser.properties, so these two figures don't overlap.
    """
    cache_key = "metrics:property-inventory"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        total_properties_bought = CustomUser.objects.filter(is_deleted=False).aggregate(
            total=Sum('properties')
        )['total'] or 0

        property_agg = Property.objects.aggregate(
            total_units_available=Sum('units_available'),
            total_listings=Count('id'),
        )
        listings_with_availability = Property.objects.filter(units_available__gt=0).count()

        response_data = {
            "total_properties_bought": total_properties_bought,
            "total_units_available": property_agg['total_units_available'] or 0,
            "listings_with_availability": listings_with_availability,
            "total_listings": property_agg['total_listings'] or 0,
        }

        cache.set(cache_key, response_data, 900)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# Exact-match filters exposed here, matching Django's own TransactionAdmin
# list_filter fields, for the mobile admin Transactions tab's filter chips.
TRANSACTION_LIST_EXACT_FILTERS = ('transaction_type', 'status', 'source', 'credited_to')


@api_view(['GET'])
@permission_classes([IsAdminUser])
def all_transactions_list(request):
    """
    GET /api/admin/transactions/list?page=1&limit=50&search=john
        &transaction_type=credit&status=confirmed&source=WALLET
        &credited_to=SAVINGS&date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
    Paginated, searchable, filterable transaction list - same shape and
    conventions as all_users_list, for the mobile admin Transactions tab.
    """
    try:
        page = max(1, int(request.GET.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        limit = int(request.GET.get('limit', 50))
    except (TypeError, ValueError):
        limit = 50
    limit = min(max(limit, 1), 200)

    search = request.GET.get('search', '').strip()

    try:
        queryset = Transaction.objects.select_related('user').all()

        if search:
            queryset = queryset.filter(
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(user__email__icontains=search) |
                Q(transaction_id__icontains=search) |
                Q(description__icontains=search)
            )

        filters_applied = {"search": search}

        for field in TRANSACTION_LIST_EXACT_FILTERS:
            value = request.GET.get(field, '').strip()
            if value:
                queryset = queryset.filter(**{field: value})
                filters_applied[field] = value

        date_from = request.GET.get('date_from', '').strip()
        if date_from:
            queryset = queryset.filter(date__date__gte=date_from)
            filters_applied['date_from'] = date_from

        date_to = request.GET.get('date_to', '').strip()
        if date_to:
            queryset = queryset.filter(date__date__lte=date_to)
            filters_applied['date_to'] = date_to

        queryset = queryset.order_by('-date')

        total_count = queryset.count()
        total_pages = (total_count + limit - 1) // limit if total_count else 0

        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        transactions = queryset[start_idx:end_idx]

        serializer = AdminTransactionListSerializer(transactions, many=True)

        return Response({
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": total_pages,
            "filters_applied": filters_applied,
            "data": serializer.data,
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# Range keys the mobile admin Transactions tab's summary selector offers -
# maps directly to how far back `date__gte` filters, `None` meaning
# unbounded ("all time").
TRANSACTION_SUMMARY_RANGES = (
    "today",
    "month",
    "3months",
    "6months",
    "1year",
    "all",
)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_transactions_summary(request):
    """
    GET /api/admin/transactions/summary?range=today|month|3months|6months|1year|all
        &transaction_type=credit&status=confirmed&credited_to=SAVINGS
    Total credits, total debits, and net for the selected period, scoped by
    whichever of the Transactions tab's filter chips (type/status/
    credited-to - same TRANSACTION_LIST_EXACT_FILTERS param names
    all_transactions_list uses) are currently active, so the strip actually
    matches what's filtered below it instead of always being the
    all-time-confirmed total. Defaults to confirmed-only when no status
    filter is given - same convention dashboard_summary above uses for
    every other money aggregate in this file (pending/failed rows haven't
    actually moved money yet); picking "Pending" explicitly overrides that.
    """
    range_key = request.GET.get('range', 'today').strip().lower()
    if range_key not in TRANSACTION_SUMMARY_RANGES:
        return Response(
            {"error": f"Invalid range '{range_key}'. Must be one of {TRANSACTION_SUMMARY_RANGES}."},
            status=400,
        )

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    range_starts = {
        "today": today_start,
        "month": today_start.replace(day=1),
        "3months": today_start - relativedelta(months=3),
        "6months": today_start - relativedelta(months=6),
        "1year": today_start - relativedelta(years=1),
        "all": None,
    }

    try:
        queryset = Transaction.objects.all()
        start = range_starts[range_key]
        if start is not None:
            queryset = queryset.filter(date__gte=start)

        status_filter = request.GET.get('status', '').strip()
        queryset = queryset.filter(status=status_filter if status_filter else 'confirmed')

        for field in ('transaction_type', 'credited_to'):
            value = request.GET.get(field, '').strip()
            if value:
                queryset = queryset.filter(**{field: value})

        agg = queryset.aggregate(
            total_credits=Coalesce(
                Sum('amount', filter=Q(transaction_type='credit')),
                Value(0), output_field=DecimalField(),
            ),
            total_debits=Coalesce(
                Sum('amount', filter=Q(transaction_type='debit')),
                Value(0), output_field=DecimalField(),
            ),
            credit_count=Count('id', filter=Q(transaction_type='credit')),
            debit_count=Count('id', filter=Q(transaction_type='debit')),
        )

        total_credits = float(agg['total_credits'])
        total_debits = float(agg['total_debits'])

        return Response({
            "range": range_key,
            "total_credits": total_credits,
            "total_debits": total_debits,
            "net": total_credits - total_debits,
            "credit_count": agg['credit_count'],
            "debit_count": agg['debit_count'],
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


# Brevo's real daily sending cap is 300 (see
# authentication/services/brevo_service.py: DAILY_EMAIL_LIMIT). The
# automatic base batch only uses 280 of that, leaving a 20-email buffer
# for other transactional mail sent the same day (OTPs, notifications,
# etc. share the same Brevo daily cap) - CAMPAIGN_EXTRA_DAILY_LIMIT is
# that buffer, sendable the same day only via an explicit admin action
# (send_extra_email_campaign_batch), never automatically.
CAMPAIGN_BASE_BATCH_LIMIT = 280
CAMPAIGN_EXTRA_DAILY_LIMIT = 20


def _safe_brevo_usage():
    """
    get_brevo_usage_today(), or None if the Brevo API call itself fails
    (network blip, Brevo outage, etc.) - callers that cap a batch by this
    treat None as "couldn't check, don't block the send", since refusing
    to send campaign email because a *reporting* API call failed would be
    a worse outcome than occasionally not catching an overshoot.
    """
    from .services.brevo_service import get_brevo_usage_today

    try:
        return get_brevo_usage_today()
    except Exception as e:
        logger.warning(f"Brevo usage lookup failed, sending without a quota cap: {e}")
        return None


def _dedupe_preserve_order(emails):
    seen = set()
    result = []
    for email in emails:
        e = email.strip().lower()
        if e and e not in seen:
            seen.add(e)
            result.append(e)
    return result


@api_view(['POST'])
@permission_classes([IsAdminUser])
def create_email_campaign(request):
    """
    POST /api/admin/email-campaigns/create/
    Body: {"subject": ..., "body": "<html>...", "is_ambassador": true, ...,
           "extra_emails": ["a@example.com", ...]}
    Resolves the matching segment via the same filters all_users_list/
    admin_user_emails_for_segment use, freezes the matching emails into a
    snapshot (so later daily batches stay stable even if segment
    membership changes) - extra_emails (hand-typed addresses not
    necessarily in the segment) are placed at the front of that snapshot,
    guaranteeing they land in day one's batch regardless of segment size.
    Dispatches the first batch (<=280) to send_email_campaign_batch_task
    (tasks.py) to actually send in the background rather than inline in
    this request - a batch that size reliably exceeds the platform's
    request timeout if sent synchronously (see that task's docstring for
    the incident this fixed). This view returns immediately with the
    campaign still at sent_count 0; poll/refresh the campaign list to see
    real progress. Larger lists stay "in_progress" until
    send_next_email_campaign_batch (next day) or
    send_extra_email_campaign_batch (same day, optional top-up) is
    called.
    """
    try:
        subject = (request.data.get('subject') or '').strip()
        body = (request.data.get('body') or '').strip()
        if not subject or not body:
            return Response({"error": "Subject and body are required."}, status=400)

        # Optional display-name override ("Ibukunoluwa" -> sent as
        # "Ibukunoluwa from MyFund <...>", see send_email_campaign_batch_task)
        # - stripped of newlines/angle brackets (defensive; the SDK sends
        # this as a separate JSON field, not a raw header, but there's no
        # reason to accept characters that have no business in a name) and
        # capped well under the model's max_length.
        import re
        sender_name = (request.data.get('sender_name') or '').strip()
        sender_name = re.sub(r'[\r\n<>]', '', sender_name)[:100]

        # "Personal style" toggle on the compose screen - drops the
        # branded header entirely and shrinks the footer to just an
        # unsubscribe link (see email_plain.html / EmailCampaign.
        # template_mode). Defaults to branded (current behaviour) so
        # every existing/other caller is unaffected.
        template_mode = (request.data.get('template_mode') or 'branded').strip().lower()
        if template_mode not in ('branded', 'plain'):
            template_mode = 'branded'

        extra_emails_raw = request.data.get('extra_emails') or []
        if not isinstance(extra_emails_raw, list):
            return Response({"error": "extra_emails must be a list."}, status=400)
        extra_emails = _dedupe_preserve_order(extra_emails_raw)

        queryset, filters_applied = _build_admin_user_queryset(
            request.data, exclude_unmailable=True,
        )
        queryset = queryset.exclude(email__isnull=True).exclude(email__exact='')

        segment_emails = list(
            queryset.values_list('email', flat=True)[:MAX_SEGMENT_EMAIL_RECIPIENTS]
        )

        emails = _dedupe_preserve_order(extra_emails + segment_emails)[
            :MAX_SEGMENT_EMAIL_RECIPIENTS
        ]

        if not emails:
            return Response(
                {"error": "No users match this segment and no extra emails were given."},
                status=400,
            )

        campaign = EmailCampaign.objects.create(
            subject=subject,
            body_html=body,
            created_by=request.user,
            filters_applied=filters_applied,
            recipient_emails=emails,
            total_recipients=len(emails),
            sender_name=sender_name,
            template_mode=template_mode,
        )

        desired_batch = emails[:CAMPAIGN_BASE_BATCH_LIMIT]
        usage = _safe_brevo_usage()
        allowed = (
            len(desired_batch)
            if usage is None
            else min(len(desired_batch), usage["remaining_today"])
        )
        first_batch = desired_batch[:allowed]

        # Only mark last_batch_sent_at/is_sending if a batch actually went
        # out today - if quota is already exhausted (allowed == 0), leave
        # the campaign untouched at sent_count 0 so can_send_next_batch
        # stays True and an admin can just tap "Send next batch" once the
        # quota frees up, rather than it wrongly looking like today's
        # attempt already happened.
        if first_batch:
            campaign.last_batch_sent_at = timezone.now()
            campaign.is_sending = True
            campaign.save()

            from .tasks import send_email_campaign_batch_task
            send_email_campaign_batch_task.delay(
                campaign.id, first_batch, is_first_batch=True, is_extra_batch=False,
            )

        data = EmailCampaignSerializer(campaign).data
        data["brevo_usage"] = usage
        if allowed < len(desired_batch):
            data["quota_capped"] = True
            data["quota_capped_reason"] = (
                f"Only {usage['remaining_today']} of Brevo's daily "
                f"{usage['daily_limit']} was left today, so this batch was "
                f"capped to {allowed} instead of {len(desired_batch)}."
                if usage
                else "Batch was capped due to a Brevo quota check issue."
            )
        return Response(data, status=201)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def list_email_campaigns(request):
    """
    GET /api/admin/email-campaigns/
    Most recent 50 campaigns - this is an internal tool used by two
    people, not a paginated-at-scale list.
    """
    try:
        campaigns = EmailCampaign.objects.all()[:50]
        return Response(EmailCampaignSerializer(campaigns, many=True).data)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_email_campaigns_overview(request):
    """
    GET /api/admin/email-campaigns/overview/
    Aggregate delivery/engagement metrics across every campaign that's
    actually sent something (sent_count>0, most recent 50 - matches
    list_email_campaigns' own cap), for the summary board at the top of
    the mobile Email admin screen. Sums each campaign's own Brevo
    aggregated_smtp_report (same per-campaign tag lookup as
    get_email_campaign_report) rather than querying Brevo without a tag
    filter, since an untagged range would also pull in unrelated
    transactional email (OTPs, notifications) that shares the same Brevo
    account. Fetched concurrently (ThreadPoolExecutor, same pattern as
    BankAccountViewSet.predict in views.py) since this is otherwise up to
    50 sequential Brevo API round-trips.

    Rate thresholds in `recommendations` below are general email-industry
    benchmarks (Brevo/Mailchimp-published ranges), not MyFund-specific
    targets - a rough sanity check, not a precise goal.
    """
    import sib_api_v3_sdk
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from .services.brevo_service import get_brevo_client

    campaigns = list(
        EmailCampaign.objects.filter(sent_count__gt=0).order_by("-created_at")[:50]
    )
    if not campaigns:
        return Response({"campaign_count": 0, "reported_campaign_count": 0})

    api = sib_api_v3_sdk.TransactionalEmailsApi(get_brevo_client())
    today = timezone.now().date().isoformat()

    def fetch_one(campaign):
        try:
            return api.get_aggregated_smtp_report(
                start_date=campaign.created_at.date().isoformat(),
                end_date=today,
                tag=f"campaign-{campaign.id}",
            )
        except Exception as e:
            logger.warning(
                "Skipping campaign %s in overview - Brevo report failed: %s",
                campaign.id, e,
            )
            return None

    totals = {
        "requests": 0, "delivered": 0, "opens": 0, "unique_opens": 0,
        "clicks": 0, "unique_clicks": 0, "hard_bounces": 0, "soft_bounces": 0,
        "blocked": 0, "invalid": 0, "spam_reports": 0, "unsubscribed": 0,
    }
    reported_campaign_count = 0
    with ThreadPoolExecutor(max_workers=min(len(campaigns), 20)) as pool:
        for agg in pool.map(fetch_one, campaigns):
            if agg is None:
                continue
            reported_campaign_count += 1
            for key in totals:
                totals[key] += getattr(agg, key, 0) or 0

    def pct(numerator, denominator):
        return round((numerator / denominator) * 100, 1) if denominator else None

    delivery_rate = pct(totals["delivered"], totals["requests"])
    open_rate = pct(totals["unique_opens"], totals["delivered"])
    click_rate = pct(totals["unique_clicks"], totals["delivered"])
    click_to_open_rate = pct(totals["unique_clicks"], totals["unique_opens"])
    bounce_rate = pct(
        totals["hard_bounces"] + totals["soft_bounces"], totals["requests"]
    )
    spam_rate = pct(totals["spam_reports"], totals["delivered"])
    unsubscribe_rate = pct(totals["unsubscribed"], totals["delivered"])

    recommendations = []
    if bounce_rate is not None and bounce_rate > 2:
        recommendations.append(
            f"Bounce rate is {bounce_rate}%, above the ~2% healthy ceiling - "
            "clean stale addresses from your list before the next send."
        )
    if spam_rate is not None and spam_rate > 0.1:
        recommendations.append(
            f"Spam complaint rate is {spam_rate}%, above the 0.1% threshold "
            "Gmail/Yahoo use for bulk-sender standing - watch this closely, "
            "sustained complaints above ~0.3% risk inbox placement for all "
            "your mail, not just campaigns."
        )
    if unsubscribe_rate is not None and unsubscribe_rate > 0.5:
        recommendations.append(
            f"Unsubscribe rate is {unsubscribe_rate}%, above the ~0.5% "
            "healthy range - consider segmenting more narrowly or sending "
            "less frequently to less-engaged users."
        )
    if open_rate is not None and open_rate < 15:
        recommendations.append(
            f"Open rate is {open_rate}%, below the ~15-25% range typical "
            "for this kind of email - sharper subject lines or a different "
            "send time may help."
        )
    if click_to_open_rate is not None and click_to_open_rate < 10:
        recommendations.append(
            f"Click-to-open rate is {click_to_open_rate}% (of people who "
            "opened, how many clicked) - below the ~10-15% range, suggesting "
            "the content/CTA isn't landing even when the email gets opened."
        )
    if not recommendations:
        recommendations.append(
            "All metrics are within healthy industry ranges - keep up "
            "current sending practices."
        )

    return Response({
        "campaign_count": len(campaigns),
        "reported_campaign_count": reported_campaign_count,
        **totals,
        "delivery_rate": delivery_rate,
        "open_rate": open_rate,
        "click_rate": click_rate,
        "click_to_open_rate": click_to_open_rate,
        "bounce_rate": bounce_rate,
        "spam_rate": spam_rate,
        "unsubscribe_rate": unsubscribe_rate,
        "recommendations": recommendations,
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_email_campaign_detail(request, campaign_id):
    """
    GET /api/admin/email-campaigns/<campaign_id>/
    The one place body_html is returned for a campaign - deliberately left
    out of EmailCampaignSerializer/list_email_campaigns (that list can be
    50 campaigns deep and doesn't need the raw HTML payload for every row).
    Only fetched on demand, when an admin taps "Edit & Resend" on a
    specific campaign card.
    """
    try:
        campaign = EmailCampaign.objects.get(pk=campaign_id)
    except EmailCampaign.DoesNotExist:
        return Response({"error": "Campaign not found."}, status=404)

    return Response({
        "id": campaign.id,
        "subject": campaign.subject,
        "body_html": campaign.body_html,
        "filters_applied": campaign.filters_applied,
        "sender_name": campaign.sender_name,
        "template_mode": campaign.template_mode,
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_email_campaign_report(request, campaign_id):
    """
    GET /api/admin/email-campaigns/<campaign_id>/report/
    Pulls this campaign's delivered/opened/clicked/bounced/blocked/
    invalid counts straight from Brevo's own event log
    (get_aggregated_smtp_report, filtered by the "campaign-<id>" tag
    every send is stamped with - see send_email_campaign_batch_task) - no
    webhook receiver needed. "sent"/"failed" on the campaign record
    itself only ever meant "did Brevo's API accept the request"; this is
    what actually happened afterward.

    Side effect: separately pulls just the hardBounces events (same tag)
    and flags each of those addresses email_undeliverable=True on
    CustomUser, so future campaign segments
    (_build_admin_user_queryset's exclude_unmailable) stop selecting
    them. Soft bounces are left alone - those can be transient (mailbox
    full, etc.), not necessarily a dead address.
    """
    import json
    import sib_api_v3_sdk
    from .services.brevo_service import get_brevo_client

    try:
        campaign = EmailCampaign.objects.get(pk=campaign_id)
    except EmailCampaign.DoesNotExist:
        return Response({"error": "Campaign not found."}, status=404)

    try:
        api = sib_api_v3_sdk.TransactionalEmailsApi(get_brevo_client())
        tag = f"campaign-{campaign_id}"
        start_date = campaign.created_at.date().isoformat()
        end_date = timezone.now().date().isoformat()

        aggregated = api.get_aggregated_smtp_report(
            start_date=start_date, end_date=end_date, tag=tag,
        )

        # Hard bounces only, to find + flag the actual dead addresses -
        # capped at 500, comfortably above what even a multi-week
        # campaign (280/day batches) would produce.
        bounce_report = api.get_email_event_report(
            start_date=start_date, end_date=end_date,
            tags=json.dumps([tag]), event='hardBounces', limit=500,
        )
        bounced_emails = sorted({
            e.email for e in (bounce_report.events or []) if e.email
        })
        newly_flagged = 0
        if bounced_emails:
            newly_flagged = CustomUser.objects.filter(
                email__in=bounced_emails, email_undeliverable=False,
            ).update(email_undeliverable=True)

        return Response({
            "campaign_id": campaign.id,
            "requests": aggregated.requests,
            "delivered": aggregated.delivered,
            "opens": aggregated.opens,
            "unique_opens": aggregated.unique_opens,
            "clicks": aggregated.clicks,
            "unique_clicks": aggregated.unique_clicks,
            "hard_bounces": aggregated.hard_bounces,
            "soft_bounces": aggregated.soft_bounces,
            "blocked": aggregated.blocked,
            "invalid": aggregated.invalid,
            "spam_reports": aggregated.spam_reports,
            "unsubscribed": aggregated.unsubscribed,
            "bounced_emails": bounced_emails,
            "newly_flagged_undeliverable": newly_flagged,
        })

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def send_next_email_campaign_batch(request, campaign_id):
    """
    POST /api/admin/email-campaigns/<campaign_id>/send-next-batch/
    Sends the day's base batch (<=280). Admin-triggered - there is no
    automatic background job advancing a campaign. Enforces at most one
    base batch per calendar day; see send_extra_email_campaign_batch for
    the optional same-day top-up.
    """
    try:
        try:
            campaign = EmailCampaign.objects.get(pk=campaign_id)
        except EmailCampaign.DoesNotExist:
            return Response({"error": "Campaign not found."}, status=404)

        if campaign.status != 'in_progress':
            return Response(
                {"error": f"Campaign is already {campaign.status}."}, status=400
            )

        if (
            campaign.last_batch_sent_at is not None
            and campaign.last_batch_sent_at.date() >= timezone.now().date()
        ):
            return Response(
                {"error": "A batch was already sent today for this campaign. Try again tomorrow."},
                status=400,
            )

        if campaign.is_sending:
            return Response(
                {"error": "A batch is still sending in the background for this campaign - wait for it to finish."},
                status=400,
            )

        already_attempted = campaign.sent_count + campaign.failed_count
        desired_batch = campaign.recipient_emails[
            already_attempted:already_attempted + CAMPAIGN_BASE_BATCH_LIMIT
        ]

        if not desired_batch:
            campaign.status = 'completed'
            campaign.save()
            return Response(EmailCampaignSerializer(campaign).data)

        # Cap to whatever's actually left on Brevo's live daily count today
        # - CAMPAIGN_BASE_BATCH_LIMIT (280) assumes nothing else is
        # competing for the quota, which isn't always true (other
        # transactional mail sent the same day, or Brevo's own queue still
        # trickling out part of a previous day's batch - see
        # get_brevo_usage_today's docstring for the incident this fixed).
        usage = _safe_brevo_usage()
        allowed = (
            len(desired_batch)
            if usage is None
            else min(len(desired_batch), usage["remaining_today"])
        )

        if allowed <= 0:
            return Response(
                {
                    "error": (
                        f"Brevo's daily limit is already used up today "
                        f"({usage['used_today']}/{usage['daily_limit']}). "
                        "Try again after it resets."
                    ),
                    "brevo_usage": usage,
                },
                status=400,
            )

        next_batch = desired_batch[:allowed]

        campaign.last_batch_sent_at = timezone.now()
        campaign.extra_sent_today = 0  # new day - the extra allowance refreshes
        campaign.is_sending = True
        campaign.save()

        from .tasks import send_email_campaign_batch_task
        send_email_campaign_batch_task.delay(
            campaign.id, next_batch, is_first_batch=False, is_extra_batch=False,
        )

        data = EmailCampaignSerializer(campaign).data
        data["brevo_usage"] = usage
        if allowed < len(desired_batch):
            data["quota_capped"] = True
            data["quota_capped_reason"] = (
                f"Only {usage['remaining_today']} of Brevo's daily "
                f"{usage['daily_limit']} was left today, so this batch was "
                f"capped to {allowed} instead of {len(desired_batch)}. "
                "The rest will be picked up by a future batch."
            )
        return Response(data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def send_extra_email_campaign_batch(request, campaign_id):
    """
    POST /api/admin/email-campaigns/<campaign_id>/send-extra-batch/
    Optional same-day top-up: only usable after today's base batch has
    already gone out, sends up to CAMPAIGN_EXTRA_DAILY_LIMIT (20) more on
    top of it. This is how an admin can choose to use Brevo's full
    300/day cap on a day they know nothing else is competing for it,
    instead of always being capped at the conservative 280 default.
    """
    try:
        try:
            campaign = EmailCampaign.objects.get(pk=campaign_id)
        except EmailCampaign.DoesNotExist:
            return Response({"error": "Campaign not found."}, status=404)

        if campaign.status != 'in_progress':
            return Response(
                {"error": f"Campaign is already {campaign.status}."}, status=400
            )

        today = timezone.now().date()
        if campaign.last_batch_sent_at is None or campaign.last_batch_sent_at.date() != today:
            return Response(
                {"error": "Send today's base batch first before sending extra."},
                status=400,
            )

        if campaign.is_sending:
            return Response(
                {"error": "A batch is still sending in the background for this campaign - wait for it to finish."},
                status=400,
            )

        remaining_allowance = CAMPAIGN_EXTRA_DAILY_LIMIT - campaign.extra_sent_today
        if remaining_allowance <= 0:
            return Response(
                {"error": "Today's extra allowance (20) has already been used."},
                status=400,
            )

        already_attempted = campaign.sent_count + campaign.failed_count
        desired_batch = campaign.recipient_emails[
            already_attempted:already_attempted + remaining_allowance
        ]

        if not desired_batch:
            campaign.status = 'completed'
            campaign.save()
            return Response(EmailCampaignSerializer(campaign).data)

        usage = _safe_brevo_usage()
        allowed = (
            len(desired_batch)
            if usage is None
            else min(len(desired_batch), usage["remaining_today"])
        )

        if allowed <= 0:
            return Response(
                {
                    "error": (
                        f"Brevo's daily limit is already used up today "
                        f"({usage['used_today']}/{usage['daily_limit']}). "
                        "Try again after it resets."
                    ),
                    "brevo_usage": usage,
                },
                status=400,
            )

        next_batch = desired_batch[:allowed]

        campaign.is_sending = True
        campaign.save()

        from .tasks import send_email_campaign_batch_task
        send_email_campaign_batch_task.delay(
            campaign.id, next_batch, is_first_batch=False, is_extra_batch=True,
        )

        data = EmailCampaignSerializer(campaign).data
        data["brevo_usage"] = usage
        if allowed < len(desired_batch):
            data["quota_capped"] = True
            data["quota_capped_reason"] = (
                f"Only {usage['remaining_today']} of Brevo's daily "
                f"{usage['daily_limit']} was left today, so this extra "
                f"batch was capped to {allowed} instead of {len(desired_batch)}."
            )
        return Response(data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def cancel_email_campaign(request, campaign_id):
    """
    POST /api/admin/email-campaigns/<campaign_id>/cancel/
    Stops future daily batches - whatever's already been sent stays sent.
    """
    try:
        try:
            campaign = EmailCampaign.objects.get(pk=campaign_id)
        except EmailCampaign.DoesNotExist:
            return Response({"error": "Campaign not found."}, status=404)

        if campaign.status != 'in_progress':
            return Response(
                {"error": f"Campaign is already {campaign.status}."}, status=400
            )

        campaign.status = 'cancelled'
        campaign.save(update_fields=['status'])
        return Response(EmailCampaignSerializer(campaign).data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def resume_email_campaign(request, campaign_id):
    """
    POST /api/admin/email-campaigns/<campaign_id>/resume/
    Undoes cancel_email_campaign - flips a cancelled campaign back to
    in_progress so send_next_email_campaign_batch/send_extra_email_campaign_batch
    work on it again. Both of those already resume from
    sent_count + failed_count (see send_next_email_campaign_batch), so
    nothing else needs to change - this just clears the status gate that
    was rejecting them. Whatever's left in recipient_emails picks up
    exactly where cancellation left off; nothing already sent is resent.
    """
    try:
        try:
            campaign = EmailCampaign.objects.get(pk=campaign_id)
        except EmailCampaign.DoesNotExist:
            return Response({"error": "Campaign not found."}, status=404)

        if campaign.status != 'cancelled':
            return Response(
                {"error": f"Only a cancelled campaign can be resumed (this one is {campaign.status})."},
                status=400,
            )

        if campaign.sent_count + campaign.failed_count >= campaign.total_recipients:
            campaign.status = 'completed'
            campaign.save(update_fields=['status'])
            return Response(EmailCampaignSerializer(campaign).data)

        campaign.status = 'in_progress'
        campaign.save(update_fields=['status'])
        return Response(EmailCampaignSerializer(campaign).data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def end_email_campaign(request, campaign_id):
    """
    POST /api/admin/email-campaigns/<campaign_id>/end/
    For a cancelled (paused) campaign that will never be resumed - e.g. the
    launch it was announcing already happened, so there's no point sending
    the remaining batches. Marks it permanently completed as-is (whatever's
    in sent_count/failed_count stays final) rather than leaving it stuck
    showing a "Resume" action forever. Unlike resume_email_campaign, this
    never re-enters in_progress - completed is terminal.
    """
    try:
        try:
            campaign = EmailCampaign.objects.get(pk=campaign_id)
        except EmailCampaign.DoesNotExist:
            return Response({"error": "Campaign not found."}, status=404)

        if campaign.status != 'cancelled':
            return Response(
                {"error": f"Only a cancelled campaign can be ended (this one is {campaign.status})."},
                status=400,
            )

        campaign.status = 'completed'
        campaign.save(update_fields=['status'])
        return Response(EmailCampaignSerializer(campaign).data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


MAX_CAMPAIGN_IMAGE_BYTES = 5 * 1024 * 1024  # matches profile_picture_update's cap


@api_view(['POST'])
@permission_classes([IsAdminUser])
def upload_campaign_image(request):
    """
    POST /api/admin/email-campaigns/upload-image/
    Body: {"image_base64": "...", "filename": "photo.jpg"}
    Uploads to ImageKit (same pipeline as profile picture uploads - see
    upload_to_imagekit in views.py) and returns a public HTTPS URL, for
    embedding as an <img> in a composed campaign email. Doesn't persist
    anywhere - the URL is only ever used inline in that one email's HTML.
    """
    from .views import upload_to_imagekit

    image_base64 = request.data.get('image_base64')
    filename = request.data.get('filename', 'campaign_image.jpg')

    if not image_base64:
        return Response({"error": "No image data provided."}, status=400)

    if "," in image_base64:
        image_base64 = image_base64.split(",")[1]

    # Rough size check before spending time on the upload - base64 is
    # ~4/3 the size of the raw bytes.
    if len(image_base64) * 3 / 4 > MAX_CAMPAIGN_IMAGE_BYTES:
        return Response({"error": "Image too large. Max size is 5MB."}, status=400)

    try:
        public_url = upload_to_imagekit(
            image_base64, request.user.id, filename, prefix="campaign"
        )
        return Response({"url": public_url})
    except Exception as e:
        return Response({"error": f"Upload failed: {str(e)}"}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def brevo_daily_usage(request):
    """
    GET /api/admin/brevo-daily-usage/
    Live count + subject breakdown of transactional emails actually sent
    TODAY across the *whole* Brevo account - not just this app's
    campaigns, everything sharing the same daily quota (OTPs,
    notifications, webapp sends, etc.). See
    services/brevo_service.py:get_brevo_usage_today for the actual query -
    this view and every campaign-batch-sending view share that one
    implementation so the badge here and the quota cap those views enforce
    can never disagree about what "used today" means. The "breakdown" list
    (subject -> count for today) is what the admin panel's usage-detail
    modal renders, so an admin can see *what* is eating the quota instead
    of just a bare number.
    """
    try:
        from .services.brevo_service import get_brevo_usage_today

        return Response(get_brevo_usage_today())
    except Exception as e:
        return Response({"error": str(e)}, status=500)


# ============================================================================
# OPERATING EXPENSES (Finance tab, founders-only)
# ============================================================================

from .models import OperatingExpense
from .serializers import OperatingExpenseSerializer
from .views import FINANCE_METRICS_ALLOWED_EMAILS


def _is_finance_allowed(user):
    return bool(user.is_staff) and (user.email or "").strip().lower() in FINANCE_METRICS_ALLOWED_EMAILS


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def operating_expenses_list(request):
    """
    GET /api/admin/operating-expenses/list?date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
    Founders-only, same boundary as AdminFinanceMetricsView - this ledger
    directly feeds calculate_finance_metrics's operating_expenses line.
    Unfiltered, returns the most recent 200 entries.
    """
    if not _is_finance_allowed(request.user):
        return Response({"detail": "Permission denied"}, status=403)

    queryset = OperatingExpense.objects.all()

    date_from = request.GET.get('date_from', '').strip()
    if date_from:
        queryset = queryset.filter(date_incurred__gte=date_from)

    date_to = request.GET.get('date_to', '').strip()
    if date_to:
        queryset = queryset.filter(date_incurred__lte=date_to)

    if not date_from and not date_to:
        queryset = queryset[:200]

    serializer = OperatingExpenseSerializer(queryset, many=True)
    return Response({"data": serializer.data})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def operating_expenses_create(request):
    """
    POST /api/admin/operating-expenses/create
    Body: {"description": "...", "category": "software", "amount": 15000,
           "date_incurred": "2026-09-01", "notes": "..."}
    """
    if not _is_finance_allowed(request.user):
        return Response({"detail": "Permission denied"}, status=403)

    serializer = OperatingExpenseSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=400)

    serializer.save(added_by=request.user)
    return Response(serializer.data, status=201)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def operating_expenses_delete(request, expense_id):
    """DELETE /api/admin/operating-expenses/<expense_id>/delete"""
    if not _is_finance_allowed(request.user):
        return Response({"detail": "Permission denied"}, status=403)

    try:
        expense = OperatingExpense.objects.get(pk=expense_id)
    except OperatingExpense.DoesNotExist:
        return Response({"error": "Expense not found."}, status=404)

    expense.delete()
    return Response({"success": True})


@api_view(['POST'])
@permission_classes([IsAdminUser])
def submit_cx_weekly_report(request):
    """
    POST /api/admin/cx/weekly-reports/create/
    Body: {"report": "...", "recommendation": "...", "week_start": "YYYY-MM-DD"}
    Any is_staff admin can submit - the mobile app only surfaces this
    form on the CX-restricted dashboard, but there's no reason to block a
    founder/other admin from using the same channel. Notifies founders
    (get_admin_notify_users(category="system") via
    send_admin_push_notification - see AdminNotifyRecipient) with a
    summary so nothing submitted here goes unseen.

    week_start is the Monday of whichever week this report is actually
    for - the mobile app lets CX pick any week in the current or
    previous month (not just "this week"), so a catch-up report or
    several reports for different weeks can all be submitted in one
    sitting. No uniqueness constraint on (submitted_by, week_start) -
    resubmitting/adding another report for a week already covered is
    allowed. Defaults to the Monday of the current week if omitted.
    """
    from datetime import date

    report_text = (request.data.get('report') or '').strip()
    recommendation_text = (request.data.get('recommendation') or '').strip()
    week_start_str = (request.data.get('week_start') or '').strip()

    if not report_text:
        return Response({"error": "Report text is required."}, status=400)

    if week_start_str:
        try:
            week_start = date.fromisoformat(week_start_str)
        except ValueError:
            return Response({"error": "week_start must be YYYY-MM-DD."}, status=400)
    else:
        today = date.today()
        week_start = today - timedelta(days=today.weekday())

    try:
        cx_report = CxWeeklyReport.objects.create(
            submitted_by=request.user,
            report=report_text,
            recommendation=recommendation_text,
            week_start=week_start,
        )

        submitter_name = (
            f"{request.user.first_name} {request.user.last_name}".strip()
            or request.user.email
        )

        def _truncate(text, limit):
            return text if len(text) <= limit else f"{text[:limit - 3]}..."

        # Both summaries share the notification body, so each gets a
        # smaller budget than the old report-only version did (140) -
        # keeps the combined message a reasonable push-notification
        # length instead of just growing it unbounded.
        message = _truncate(report_text, 100)
        if recommendation_text:
            message += f"\n\nRecommendation: {_truncate(recommendation_text, 80)}"

        try:
            send_admin_push_notification(
                title=f"📋 Weekly report from {submitter_name} (week of {week_start.strftime('%b %d')})",
                message=message,
                data={"type": "cx_weekly_report", "report_id": cx_report.id},
                notif_type="ADMIN",
                category="system",
            )
        except Exception as e:
            logger.warning(f"CX weekly report push failed: {e}")

        return Response(CxWeeklyReportSerializer(cx_report).data, status=201)

    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def list_cx_weekly_reports(request):
    """
    GET /api/admin/cx/weekly-reports/
    Founders only (_is_finance_allowed) - the full feed across all of CX,
    not just the calling user's own submissions (see my_cx_weekly_reports
    below for that).
    """
    if not _is_finance_allowed(request.user):
        return Response({"detail": "Permission denied"}, status=403)

    reports = CxWeeklyReport.objects.select_related('submitted_by').all()[:200]
    return Response(CxWeeklyReportSerializer(reports, many=True).data)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def my_cx_weekly_reports(request):
    """
    GET /api/admin/cx/weekly-reports/mine/
    Self-service read-back, always filtered to request.user regardless of
    who's asking - safe to expose to CX-only accounts (unlike
    list_cx_weekly_reports, which is founders-only and returns
    everyone's). Lets CX check what they've already submitted before
    picking a week to report on, now that week_start means they aren't
    limited to "this week only".
    """
    reports = CxWeeklyReport.objects.filter(submitted_by=request.user)[:200]
    return Response(CxWeeklyReportSerializer(reports, many=True).data)