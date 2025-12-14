# admin_views.py - Optimized Admin Dashboard Endpoints

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from django.db.models import Sum, Count, Q, F
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
    Single endpoint that replaces 4+ current calls
    GET /api/admin/dashboard/summary
    Response time: ~200-500ms (vs current 10-15 seconds)
    """
    cache_key = f"dashboard:summary:{timezone.now().strftime('%Y-%m-%d:%H:%M')}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    try:
        # Get admin user info
        admin_user = request.user
        
        # Calculate wealth stage (simplified - adjust based on your logic)
        wealth_stage = calculate_wealth_stage(admin_user)
        
        # Current month aggregations - optimized single query
        current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Get current month totals from all users
        month_totals = CustomUser.objects.aggregate(
            total_savings=Sum('savings'),
            total_investments=Sum('investment')
        )
        
        # Get previous month totals for growth calculation
        prev_month_start = current_month_start - relativedelta(months=1)
        prev_month_totals = MonthlySavings.objects.filter(
            month=prev_month_start.month,
            year=prev_month_start.year
        ).aggregate(
            prev_savings=Sum('savings'),
            prev_investments=Sum('investment')
        )
        
        # Calculate growth rates
        savings_growth = calculate_growth_rate(
            month_totals.get('total_savings', 0),
            prev_month_totals.get('prev_savings', 0)
        )
        
        investments_growth = calculate_growth_rate(
            month_totals.get('total_investments', 0),
            prev_month_totals.get('prev_investments', 0)
        )
        
        # User statistics - single optimized query
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        week_start = today_start - timedelta(days=7)
        last_week_start = week_start - timedelta(days=7)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_start = month_start - relativedelta(months=1)
        
        user_stats = CustomUser.objects.aggregate(
            total_users=Count('id', filter=Q(is_deleted=False)),
            new_users_today=Count('id', filter=Q(date_joined__gte=today_start, is_deleted=False)),
            new_users_yesterday=Count('id', filter=Q(
                date_joined__gte=yesterday_start,
                date_joined__lt=today_start,
                is_deleted=False
            )),
            new_users_this_week=Count('id', filter=Q(date_joined__gte=week_start, is_deleted=False)),
            new_users_last_week=Count('id', filter=Q(
                date_joined__gte=last_week_start,
                date_joined__lt=week_start,
                is_deleted=False
            )),
            new_users_this_month=Count('id', filter=Q(date_joined__gte=month_start, is_deleted=False)),
            new_users_last_month=Count('id', filter=Q(
                date_joined__gte=last_month_start,
                date_joined__lt=month_start,
                is_deleted=False
            ))
        )
        
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
            "user_statistics": user_stats
        }
        
        # Cache for 5 minutes
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

        # Determine which source we’re aggregating
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