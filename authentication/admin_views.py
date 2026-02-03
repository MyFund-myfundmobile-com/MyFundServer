# admin_views.py - Optimized Admin Dashboard Endpoints with Growth Metrics

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from django.db.models import Sum, Count, Q, F, Case, When, IntegerField, FloatField,ExpressionWrapper
from django.utils import timezone
from datetime import timedelta, datetime
from dateutil.relativedelta import relativedelta
from django.core.cache import cache
from decimal import Decimal
from .models import CustomUser, Transaction, MonthlySavings, TopSaverHistory
from .serializers import UserSerializer
from django.db.models.functions import ExtractMonth, ExtractYear
 



# ============================================================================
# PRIORITY 1: CRITICAL DASHBOARD DATA (Load first - 2-3 seconds)
# ============================================================================


@api_view(['GET'])
@permission_classes([IsAdminUser])
def dashboard_summary(request):
    """
    Single endpoint that replaces multiple dashboard calls
    GET /api/admin/dashboard/summary
    """
    cache_key = f"dashboard:summary:{timezone.now().strftime('%Y-%m-%d:%H:%M')}"
    cached_data = cache.get(cache_key)
    if cached_data:
        return Response(cached_data)

    try:
        # ------------------------------------------------------------
        # ORIGINAL ADMIN OVERVIEW (UNCHANGED)
        # ------------------------------------------------------------
        admin_user = request.user
        wealth_stage = calculate_wealth_stage(admin_user)

        now = timezone.now()
        current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        month_totals = CustomUser.objects.aggregate(
            total_savings=Sum('savings'),
            total_investments=Sum('investment')
        )

        prev_month_start = current_month_start - relativedelta(months=1)
        prev_month_totals = MonthlySavings.objects.filter(
            month=prev_month_start.month,
            year=prev_month_start.year
        ).aggregate(
            prev_savings=Sum('savings'),
            prev_investments=Sum('investment')
        )

        savings_growth = calculate_growth_rate(
            month_totals.get('total_savings', 0),
            prev_month_totals.get('prev_savings', 0)
        )

        investments_growth = calculate_growth_rate(
            month_totals.get('total_investments', 0),
            prev_month_totals.get('prev_investments', 0)
        )

        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        week_start = today_start - timedelta(days=7)
        last_week_start = week_start - timedelta(days=7)
        month_start = current_month_start
        last_month_start = month_start - relativedelta(months=1)

        user_stats = CustomUser.objects.aggregate(
            total_users=Count('id', filter=Q(is_deleted=False)),
            new_users_today=Count('id', filter=Q(date_joined__gte=today_start, is_deleted=False)),
            new_users_yesterday=Count(
                'id',
                filter=Q(date_joined__gte=yesterday_start, date_joined__lt=today_start, is_deleted=False)
            ),
            new_users_this_week=Count('id', filter=Q(date_joined__gte=week_start, is_deleted=False)),
            new_users_last_week=Count(
                'id',
                filter=Q(date_joined__gte=last_week_start, date_joined__lt=week_start, is_deleted=False)
            ),
            new_users_this_month=Count('id', filter=Q(date_joined__gte=month_start, is_deleted=False)),
            new_users_last_month=Count(
                'id',
                filter=Q(date_joined__gte=last_month_start, date_joined__lt=month_start, is_deleted=False)
            )
        )

        # ------------------------------------------------------------
        # ADVANCED METRICS (SAFELY APPENDED)
        # ------------------------------------------------------------
        thirty_days_ago = now - timedelta(days=30)
        sixty_days_ago = now - timedelta(days=60)

        # 1. Monthly Active Savers
        mas_tx = Transaction.objects.filter(
            date__gte=month_start,
            source__in=['SAVINGS', 'INVESTMENT'],
            transaction_type='credit',
            status='confirmed'
        )

        mas_users = mas_tx.values('user').distinct().count()
        mas_amount = mas_tx.aggregate(total=Sum('amount'))['total'] or 0

        # 2. Activated users
        new_users = CustomUser.objects.filter(
            date_joined__gte=month_start,
            is_deleted=False
        )

        activated_users = Transaction.objects.filter(
            user__in=new_users,
            transaction_type='credit',
            status='confirmed',
            source__in=['SAVINGS', 'INVESTMENT']
        ).values('user').distinct().count()

        activation_rate = (
            activated_users / new_users.count() * 100
            if new_users.exists() else 0
        )

        # 3. Retention
        cohort_users = CustomUser.objects.filter(
            date_joined__gte=sixty_days_ago,
            date_joined__lt=thirty_days_ago,
            is_deleted=False
        )

        retained_users = Transaction.objects.filter(
            user__in=cohort_users,
            date__gte=thirty_days_ago,
            transaction_type='credit',
            status='confirmed'
        ).values('user').distinct().count()

        retention_rate = (
            retained_users / cohort_users.count() * 100
            if cohort_users.exists() else 0
        )

        # 4. Investors vs Savers (SAFE)
        base_users = CustomUser.objects.filter(
            is_deleted=False,
            savings__gt=0
        ).annotate(
            ratio=ExpressionWrapper(
                F('investment') * 1.0 / F('savings'),
                output_field=FloatField()
            )
        )

        investor_heavy = base_users.filter(ratio__gt=1).count()
        savings_heavy = base_users.filter(ratio__lte=1).count()

        # 5. Transaction health
        tx_stats = Transaction.objects.filter(
            date__gte=thirty_days_ago
        ).aggregate(
            total=Count('id'),
            failed=Count('id', filter=Q(status='failed'))
        )

        failure_rate = (
            tx_stats['failed'] / tx_stats['total'] * 100
            if tx_stats['total'] else 0
        )

        # 6. Multipliers
        total_users = CustomUser.objects.filter(is_deleted=False).count()
        referral_signups = CustomUser.objects.filter(referral_id__isnull=False).count()
        influencer_signups = CustomUser.objects.filter(is_ambassador=True).count()

        # 7. Financial strength
        fum = CustomUser.objects.filter(is_deleted=False).aggregate(
            total=Sum(F('savings') + F('investment'))
        )['total'] or 0

        inactive_users = CustomUser.objects.exclude(
            id__in=Transaction.objects.filter(date__gte=thirty_days_ago).values('user')
        ).count()

        churn_rate = (inactive_users / total_users * 100) if total_users else 0

        # ------------------------------------------------------------
        # FINAL RESPONSE (MERGED, NON-BREAKING)
        # ------------------------------------------------------------
        response_data = {
            "user_info": {
                "first_name": admin_user.first_name,
                "profile_picture": admin_user.profile_picture or "",
                "wealth_stage": wealth_stage
            },
            "current_month": {
                "total_savings": float(month_totals.get('total_savings') or 0),
                "total_investments": float(month_totals.get('total_investments') or 0),
                "savings_growth_rate": savings_growth,
                "investments_growth_rate": investments_growth
            },
            "user_statistics": user_stats,

            # 👇 safely appended
            "advanced_metrics": {
                "monthly_active_savers": {
                    "users": mas_users,
                    "total_amount": float(mas_amount)
                },
                "activation_rate": round(activation_rate, 2),
                "retention_30d": round(retention_rate, 2),
                "investors_vs_savers": {
                    "investor_heavy": investor_heavy,
                    "savings_heavy": savings_heavy
                },
                "transaction_failure_rate": round(failure_rate, 2),
                "growth_multipliers": {
                    "referrals_pct": round(referral_signups / total_users * 100, 2) if total_users else 0,
                    "influencers_pct": round(influencer_signups / total_users * 100, 2) if total_users else 0
                },
                "financial_health": {
                    "fum": float(fum),
                    "churn_rate": round(churn_rate, 2)
                }
            }
        }

        cache.set(cache_key, response_data, 300)
        return Response(response_data)

    except Exception as e:
        return Response({"error": str(e)}, status=500)



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


@api_view(['GET'])
@permission_classes([IsAdminUser])
def all_users_list(request):
    """
    GET /api/admin/users/list?page=1&limit=50&search=john&wealth_stage=5
    Paginated list with filters
    """
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 50))
    search = request.GET.get('search', '')
    wealth_stage = request.GET.get('wealth_stage', '')
    
    try:
        queryset = CustomUser.objects.filter(is_deleted=False)
        
        # Apply search filter
        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search)
            )
        
        # Apply wealth stage filter (simplified)
        if wealth_stage:
            # Implement wealth stage filtering based on your logic
            pass
        
        queryset = queryset.order_by('-date_joined')
        
        total_count = queryset.count()
        total_pages = (total_count + limit - 1) // limit
        
        # Pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        users = queryset[start_idx:end_idx]
        
        # Serialize users
        serializer = UserSerializer(users, many=True)
        
        return Response({
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": total_pages,
            "filters_applied": {
                "search": search,
                "wealth_stage": wealth_stage
            },
            "data": serializer.data
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
        # Assuming there's a GroupBuy model with status field
        # You'll need to import and adjust based on your actual model
        # from .models import GroupBuy
        
        # Placeholder response - replace with actual GroupBuy queries
        response_data = {
            "active_groupbuys": 0,
            "successful_groupbuys": 0,
            "failed_groupbuys": 0,
            "total_groupbuys": 0,
            "success_rate": 0,
            "note": "GroupBuy model integration needed"
        }
        
        # Example implementation (uncomment and adjust):
        # groupbuy_stats = GroupBuy.objects.aggregate(
        #     active=Count('id', filter=Q(status='active')),
        #     successful=Count('id', filter=Q(status='successful')),
        #     failed=Count('id', filter=Q(status='failed')),
        #     total=Count('id')
        # )
        # 
        # total = groupbuy_stats['total'] or 0
        # success_rate = (groupbuy_stats['successful'] / total * 100) if total > 0 else 0
        # 
        # response_data = {
        #     "active_groupbuys": groupbuy_stats['active'],
        #     "successful_groupbuys": groupbuy_stats['successful'],
        #     "failed_groupbuys": groupbuy_stats['failed'],
        #     "total_groupbuys": total,
        #     "success_rate": round(success_rate, 2)
        # }
        
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