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
        "multipliers/top-performers",
        admin_views.admin_top_performers,
        name="admin_top_performers",
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
    path(
        "users/emails/",
        admin_views.admin_user_emails_for_segment,
        name="admin_user_emails_for_segment",
    ),
    path(
        "users/export/",
        admin_views.admin_user_export_csv,
        name="admin_user_export_csv",
    ),
    path(
        "users/<int:user_id>/",
        admin_views.admin_user_detail,
        name="admin_user_detail",
    ),
    path(
        "users/<int:user_id>/update-status/",
        admin_views.update_user_status,
        name="admin_update_user_status",
    ),
    path(
        "transactions/list",
        admin_views.all_transactions_list,
        name="admin_all_transactions_list",
    ),
    path(
        "transactions/summary",
        admin_views.admin_transactions_summary,
        name="admin_transactions_summary",
    ),
    # ========================================================================
    # OPERATING EXPENSES (Finance tab, founders-only)
    # ========================================================================
    path(
        "operating-expenses/list",
        admin_views.operating_expenses_list,
        name="admin_operating_expenses_list",
    ),
    path(
        "operating-expenses/create",
        admin_views.operating_expenses_create,
        name="admin_operating_expenses_create",
    ),
    path(
        "operating-expenses/<int:expense_id>/delete",
        admin_views.operating_expenses_delete,
        name="admin_operating_expenses_delete",
    ),
    # ========================================================================
    # ADMIN METRICS DASHBOARD (mobile app - 7-category overview)
    # ========================================================================
    path(
        "metrics/signups",
        admin_views.signup_metrics,
        name="admin_signup_metrics",
    ),
    path(
        "metrics/signups/users",
        admin_views.signup_segment_users,
        name="admin_signup_segment_users",
    ),
    path(
        "metrics/signups/summary",
        admin_views.signup_summary,
        name="admin_signup_summary",
    ),
    path(
        "financial/cashflow-summary",
        admin_views.cashflow_summary,
        name="admin_cashflow_summary",
    ),
    path(
        "financial/cashflow-summary/range",
        admin_views.cashflow_range_summary,
        name="admin_cashflow_range_summary",
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
    # ========================================================================
    # EMAIL CAMPAIGNS (mobile app - segment sends batched at Brevo's
    # daily cap, admin-triggered day to day)
    # ========================================================================
    path(
        "email-campaigns/create/",
        admin_views.create_email_campaign,
        name="admin_create_email_campaign",
    ),
    path(
        "email-campaigns/upload-image/",
        admin_views.upload_campaign_image,
        name="admin_upload_campaign_image",
    ),
    path(
        "brevo-daily-usage/",
        admin_views.brevo_daily_usage,
        name="admin_brevo_daily_usage",
    ),
    path(
        "email-campaigns/",
        admin_views.list_email_campaigns,
        name="admin_list_email_campaigns",
    ),
    path(
        "email-campaigns/overview/",
        admin_views.get_email_campaigns_overview,
        name="admin_get_email_campaigns_overview",
    ),
    path(
        "email-campaigns/<int:campaign_id>/",
        admin_views.get_email_campaign_detail,
        name="admin_get_email_campaign_detail",
    ),
    path(
        "email-campaigns/<int:campaign_id>/report/",
        admin_views.get_email_campaign_report,
        name="admin_get_email_campaign_report",
    ),
    path(
        "email-templates/<int:template_id>/report/",
        admin_views.get_email_template_report,
        name="admin_get_email_template_report",
    ),
    path(
        "email-campaigns/<int:campaign_id>/send-next-batch/",
        admin_views.send_next_email_campaign_batch,
        name="admin_send_next_email_campaign_batch",
    ),
    path(
        "email-campaigns/<int:campaign_id>/send-extra-batch/",
        admin_views.send_extra_email_campaign_batch,
        name="admin_send_extra_email_campaign_batch",
    ),
    path(
        "email-campaigns/<int:campaign_id>/cancel/",
        admin_views.cancel_email_campaign,
        name="admin_cancel_email_campaign",
    ),
    path(
        "email-campaigns/<int:campaign_id>/resume/",
        admin_views.resume_email_campaign,
        name="admin_resume_email_campaign",
    ),
    path(
        "email-campaigns/<int:campaign_id>/end/",
        admin_views.end_email_campaign,
        name="admin_end_email_campaign",
    ),
    # ========================================================================
    # CX WEEKLY REPORTS (mobile app - CX-restricted dashboard submission
    # form; founders-only read list)
    # ========================================================================
    path(
        "cx/weekly-reports/create/",
        admin_views.submit_cx_weekly_report,
        name="admin_submit_cx_weekly_report",
    ),
    path(
        "cx/weekly-reports/mine/",
        admin_views.my_cx_weekly_reports,
        name="admin_my_cx_weekly_reports",
    ),
    path(
        "cx/weekly-reports/",
        admin_views.list_cx_weekly_reports,
        name="admin_list_cx_weekly_reports",
    ),
]
