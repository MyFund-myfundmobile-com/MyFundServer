# admin_views.py - Optimized Admin Dashboard Endpoints with Growth Metrics

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
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
)
from .serializers import UserSerializer, AdminUserListSerializer
from .utils import grant_user_ambassador_status, revoke_user_ambassador_status
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
                source__in=['SAVINGS', 'INVESTMENT'],
                transaction_type='credit',
                status='confirmed'
            ),
            distinct=True
        ),
        mas_amount=Coalesce(
            Sum('amount', filter=Q(
                source__in=['SAVINGS', 'INVESTMENT'],
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
        source__in=['SAVINGS', 'INVESTMENT'],
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
                source__in=['SAVINGS', 'INVESTMENT'],
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
                source__in=["SAVINGS", "INVESTMENT"],
                transaction_type="credit",
                status="confirmed",
            ),
        ),
        mas_amount=Coalesce(
            Sum(
                "amount",
                filter=Q(
                    source__in=["SAVINGS", "INVESTMENT"],
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
            source__in=['SAVINGS', 'INVESTMENT']
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

        # Determine which source we're aggregating
        source_filter = "SAVINGS" if fin_type == "savings" else "INVESTMENT"

        # Only CONFIRMED credit transactions represent money coming in
        queryset = (
            Transaction.objects.filter(
                date__gte=start_date,
                source=source_filter,
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
    explicit false, which must still filter."""
    if value is None or value == '':
        return None
    return value.strip().lower() in ('true', '1', 'yes')


# Boolean CustomUser fields exposed as filters here, matching the same
# ones Django's own CustomUserAdmin.list_filter exposes (admin.py) so this
# endpoint can back a "filter like in Django" list UI.
USER_LIST_BOOLEAN_FILTERS = (
    'is_ambassador',
    'is_staff',
    'is_banned',
    'is_active',
    'is_hired_referrer',
)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def all_users_list(request):
    """
    GET /api/admin/users/list?page=1&limit=50&search=john
        &is_ambassador=true&is_staff=false&is_banned=false&is_active=true
        &is_hired_referrer=true&kyc_status=approved
    Paginated, searchable, filterable user list. Filters mirror Django's
    own CustomUserAdmin.list_filter (is_staff/is_active/is_banned/
    is_ambassador/is_hired_referrer/kyc_status) so the mobile admin Users
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

    search = request.GET.get('search', '').strip()

    try:
        queryset = CustomUser.objects.filter(is_deleted=False)

        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search) |
                Q(phone_number__icontains=search)
            )

        filters_applied = {"search": search}

        for field in USER_LIST_BOOLEAN_FILTERS:
            parsed = _parse_bool_param(request.GET.get(field))
            if parsed is not None:
                queryset = queryset.filter(**{field: parsed})
                filters_applied[field] = parsed

        kyc_status = request.GET.get('kyc_status', '').strip()
        if kyc_status:
            queryset = queryset.filter(kyc_status=kyc_status)
            filters_applied["kyc_status"] = kyc_status

        queryset = queryset.order_by('-date_joined')

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
USER_STATUS_TOGGLEABLE_FIELDS = {'is_ambassador', 'is_banned', 'is_staff', 'is_active'}


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
        
        # Get savers (people who made credit transactions to SAVINGS)
        savers_data = Transaction.objects.filter(
            date__gte=month_start,
            date__lt=month_end,
            source='SAVINGS',
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
            source='INVESTMENT',
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
            source='SAVINGS',
            transaction_type='credit',
            status='confirmed'
        ).values_list('user', flat=True))
        
        investors_ids = set(Transaction.objects.filter(
            date__gte=month_start,
            date__lt=month_end,
            source='INVESTMENT',
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
        
        # Get new users who made at least one confirmed transaction
        activated_user_ids = Transaction.objects.filter(
            user__in=new_users,
            source__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed'
        ).values_list('user', )
        
        activated_count = len(activated_user_ids)
        
        # Calculate total amount saved by activated users
        total_saved = Transaction.objects.filter(
            user__in=activated_user_ids,
            source__in=['SAVINGS', 'INVESTMENT'],
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
        
        # Get users from cohort who made transactions in the last 30 days
        retained_user_ids = Transaction.objects.filter(
            user__in=cohort_users,
            date__gte=thirty_days_ago,
            source__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed'
        ).values_list('user',)
        
        retained_count = len(retained_user_ids)
        
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

@api_view(['GET'])
@permission_classes([IsAdminUser])
def top_referrals(request):
    """
    GET /api/admin/multipliers/top-referrals?limit=20
    Returns top referrers with badges (Active, Ambassador, Advocate)
    Formula: (Signups with referrals / Total signups)
    """
    limit = int(request.GET.get('limit', 20))
    
    cache_key = f"multipliers:referrals:{limit}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Assuming CustomUser has a 'referred_by' field
        # Get users who have referred others
        referral_stats = CustomUser.objects.filter(
            is_deleted=False
        ).exclude(
            referred_by__isnull=True
        ).values('referred_by').annotate(
            referral_count=Count('id')
        ).order_by('-referral_count')[:limit]
        
        # Get total signups with and without referrals
        total_signups = CustomUser.objects.filter(is_deleted=False).count()
        signups_with_referrals = CustomUser.objects.filter(
            is_deleted=False
        ).exclude(referred_by__isnull=True).count()
        signups_without_referrals = total_signups - signups_with_referrals
        
        referral_rate = (signups_with_referrals / total_signups * 100) if total_signups > 0 else 0
        
        # Build leaderboard with badges
        leaderboard = []
        for stat in referral_stats:
            user = CustomUser.objects.get(id=stat['referred_by'])
            count = stat['referral_count']
            
            # Assign badge based on referral count
            if count >= 50:
                badge = "Advocate"
            elif count >= 20:
                badge = "Ambassador"
            else:
                badge = "Active"
            
            leaderboard.append({
                "user_id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "referral_count": count,
                "badge": badge,
                "profile_picture": user.profile_picture or ""
            })
        
        response_data = {
            "total_signups": total_signups,
            "signups_with_referrals": signups_with_referrals,
            "signups_without_referrals": signups_without_referrals,
            "referral_rate": round(referral_rate, 2),
            "leaderboard": leaderboard
        }
        
        cache.set(cache_key, response_data, 900)
        return Response(response_data)
        
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def top_influencers(request):
    """
    GET /api/admin/multipliers/top-influencers?limit=20
    Returns top influencers with badges (Bronze, Silver, Gold)
    Formula: (Signups via influencers / Total signups)
    """
    limit = int(request.GET.get('limit', 20))
    
    cache_key = f"multipliers:influencers:{limit}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Assuming CustomUser has an 'influencer_code' field
        # Get influencer stats
        influencer_stats = CustomUser.objects.filter(
            is_deleted=False
        ).exclude(
            influencer_code__isnull=True
        ).values('influencer_code').annotate(
            signup_count=Count('id')
        ).order_by('-signup_count')[:limit]
        
        # Get total signups
        total_signups = CustomUser.objects.filter(is_deleted=False).count()
        signups_via_influencers = CustomUser.objects.filter(
            is_deleted=False
        ).exclude(influencer_code__isnull=True).count()
        signups_without_influencers = total_signups - signups_via_influencers
        
        influencer_rate = (signups_via_influencers / total_signups * 100) if total_signups > 0 else 0
        
        # Build leaderboard with badges
        leaderboard = []
        for stat in influencer_stats:
            count = stat['signup_count']
            
            # Assign badge based on signup count
            if count >= 100:
                badge = "Gold"
            elif count >= 50:
                badge = "Silver"
            else:
                badge = "Bronze"
            
            leaderboard.append({
                "influencer_code": stat['influencer_code'],
                "signup_count": count,
                "badge": badge
            })
        
        response_data = {
            "total_signups": total_signups,
            "signups_via_influencers": signups_via_influencers,
            "signups_without_influencers": signups_without_influencers,
            "influencer_rate": round(influencer_rate, 2),
            "leaderboard": leaderboard
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
        
        # Calculate money added (credit transactions)
        money_added = Transaction.objects.filter(
            date__gte=start_date,
            transaction_type='credit',
            status='confirmed',
            source__in=['SAVINGS', 'INVESTMENT']
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Calculate money withdrawn (debit transactions)
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

        activated_count = Transaction.objects.filter(
            user__in=new_users_qs,
            source__in=['SAVINGS', 'INVESTMENT'],
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

        def sum_for_range(start, end, transaction_type, source=None, source__in=None):
            qs = Transaction.objects.filter(
                date__gte=start, date__lt=end,
                transaction_type=transaction_type, status='confirmed',
            )
            if source:
                qs = qs.filter(source=source)
            if source__in:
                qs = qs.filter(source__in=source__in)
            return float(qs.aggregate(total=Sum('amount'))['total'] or 0)

        def build_metric(source):
            this_month = sum_for_range(month_start, now, 'credit', source=source)
            last_month = sum_for_range(prev_month_start, month_start, 'credit', source=source)
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
    """
    cache_key = "metrics:user-activity-segments"
    cached_data = cache.get(cache_key)

    if cached_data:
        return Response(cached_data)

    try:
        def segment_counts(as_of):
            recent_threshold = as_of - timedelta(days=30)

            recent_tx = Transaction.objects.filter(
                user=OuterRef('pk'), status='confirmed',
                date__gte=recent_threshold, date__lte=as_of,
            )
            any_tx = Transaction.objects.filter(
                user=OuterRef('pk'), status='confirmed', date__lte=as_of,
            )

            users = CustomUser.objects.filter(is_deleted=False).annotate(
                has_recent_tx=Exists(recent_tx),
                has_any_tx=Exists(any_tx),
            )

            total = users.count()
            active = users.filter(has_recent_tx=True).count()
            has_balance_q = Q(savings__gt=0) | Q(investment__gt=0) | Q(wallet__gt=0)
            dormant = users.filter(
                Q(has_recent_tx=False) & (has_balance_q | Q(has_any_tx=True))
            ).count()
            inactive = total - active - dormant

            return active, dormant, inactive, total

        now = timezone.now()
        this_active, this_dormant, this_inactive, total_users = segment_counts(now)

        last_month_point = now.replace(day=1) - timedelta(days=1)
        last_active, last_dormant, last_inactive, _ = segment_counts(last_month_point)

        def rate_str(current, previous):
            if previous > 0:
                rate = ((current - previous) / previous) * 100
            else:
                rate = 100.0 if current > 0 else 0.0
            return f"{'+' if rate >= 0 else ''}{round(rate, 1)}%"

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
        if period == '30days':
            start_date = now - timedelta(days=30)
        elif period == '7days':
            start_date = now - timedelta(days=7)
        else:
            period = 'current_month'
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        base_qs = Transaction.objects.filter(status='confirmed', date__gte=start_date)

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