# admin_urls.py - URL Configuration for Admin Dashboard

from django.urls import path
from . import admin_views

urlpatterns = [
    # ========================================================================
    # PRIORITY 1: Critical Dashboard Data
    # ========================================================================
    path(
        "dashboard/summary/",
        admin_views.dashboard_summary,
        name="admin_dashboard_summary",
    ),
    # GROWTH METRICS
    # ========================================================================
    path(
        "metrics/monthly-active-savers",
        admin_views.monthly_active_savers,
        name="admin_monthly_active_savers",
    ),
    path(
        "metrics/activated-users",
        admin_views.activated_users_percentage,
        name="admin_activated_users",
    ),
    path(
        "metrics/retention-rate",
        admin_views.retention_rate,
        name="admin_retention_rate",
    ),
    path(
        "metrics/investors-vs-savers",
        admin_views.active_investors_vs_savers,
        name="admin_investors_vs_savers",
    ),
    path(
        "metrics/transaction-success-rate",
        admin_views.transaction_success_rate,
        name="admin_transaction_success_rate",
    ),
    # ========================================================================
    # GROWTH MULTIPLIERS
    # ========================================================================
    path(
        "multipliers/top-referrals",
        admin_views.top_referrals,
        name="admin_top_referrals",
    ),
    path(
        "multipliers/top-influencers",
        admin_views.top_influencers,
        name="admin_top_influencers",
    ),
    path(
        "multipliers/groupbuys",
        admin_views.groupbuy_metrics,
        name="admin_groupbuy_metrics",
    ),
    path(
        "groupbuy/<str:group_id>/distribute-income/",
        admin_views.distribute_groupbuy_income,
        name="distribute_groupbuy_income",
    ),
    # ========================================================================
    # FINANCIAL STRENGTH & MOMENTUM
    # ========================================================================
    path(
        "financial/fum",
        admin_views.funds_under_management,
        name="admin_funds_under_management",
    ),
    path(
        "financial/net-fum-change",
        admin_views.net_fum_change,
        name="admin_net_fum_change",
    ),
    path("financial/churn-rate", admin_views.churn_rate, name="admin_churn_rate"),
    # ========================================================================
    # PRIORITY 2: Chart Data
    # ========================================================================
    path(
        "charts/user-growth",
        admin_views.user_growth_chart,
        name="admin_user_growth_chart",
    ),
    path(
        "charts/top-savers", admin_views.top_savers_chart, name="admin_top_savers_chart"
    ),
    path(
        "charts/new-savers", admin_views.new_savers_chart, name="admin_new_savers_chart"
    ),
    path(
        "charts/user-metrics",
        admin_views.user_metrics_chart,
        name="admin_user_metrics_chart",
    ),
    path(
        "charts/financial-history",
        admin_views.financial_history_chart,
        name="admin_financial_history_chart",
    ),
    path(
        "charts/withdrawals-trend",
        admin_views.withdrawals_trend_chart,
        name="admin_withdrawals_trend_chart",
    ),
    # ========================================================================
    # PRIORITY 3: List Data (Paginated)
    # ========================================================================
    path("users/recent", admin_views.recent_signups, name="admin_recent_signups"),
    path("users/list", admin_views.all_users_list, name="admin_all_users_list"),
    # ========================================================================
    # ADMIN METRICS DASHBOARD (mobile app - 7-category overview)
    # ========================================================================
    path(
        "metrics/signups",
        admin_views.signup_metrics,
        name="admin_signup_metrics",
    ),
    path(
        "financial/cashflow-summary",
        admin_views.cashflow_summary,
        name="admin_cashflow_summary",
    ),
    path(
        "metrics/target-savings",
        admin_views.target_savings_breakdown,
        name="admin_target_savings_breakdown",
    ),
    path(
        "metrics/user-activity",
        admin_views.user_activity_segments,
        name="admin_user_activity_segments",
    ),
    path(
        "metrics/transaction-types",
        admin_views.transaction_type_breakdown,
        name="admin_transaction_type_breakdown",
    ),
    path(
        "metrics/properties",
        admin_views.property_inventory,
        name="admin_property_inventory",
    ),
]
