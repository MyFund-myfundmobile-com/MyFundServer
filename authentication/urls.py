from django.urls import path, include
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import re_path
from django.contrib import admin
from rest_framework.routers import DefaultRouter
from .views import (
    CardListCreateView,
    CardDetailView,
    KYCUpdateView,
    get_user_by_email,
    KYCApprovalViewSet,
    BuyPropertyView,
    UserTransactionListView,
    UserCardListView,
    AccountBalancesAPIView,
    TopReferralsAPIView,
    delete_my_account,
    send_email,
    save_template,
    delete_template,
    get_template,
    update_template,
    get_all_users,
    unsubscribe_user,
    resubscribe_user,
    target_savings_total,
    CurrentMonthFinancialView,
    FinancialHistoryView,
    AllUsersMonthlyTotalsView,
    NotificationListCreateView,
    mark_notification_as_read,
    mark_all_notifications_as_read,
    send_admin_notification,
    get_my_push_notifications,
    send_admin_push_notification,
    save_expo_push_token,
    earnings_summary,
    get_or_create_dva_account,
    initiate_dva_quicksave,
    initiate_dva_quickinvest,
    requery_my_dva_payments,
    AmbassadorMonthlyReportCreateView, 
    AmbassadorMonthlyReportStatusView,
)
from django.views.decorators.csrf import csrf_exempt
from authentication.views import CustomGraphQLView
from authentication.schema import schema  # Adjust the import path
from graphql_jwt.decorators import jwt_cookie


router = DefaultRouter()
router.register(r"bank-accounts", views.BankAccountViewSet, basename="bank-account")


urlpatterns = [
    # Authentication APIs
    path("signup/", views.signup, name="signup"),
    path("confirm-otp/", views.confirm_otp, name="confirm-otp"),
    path("resend-otp/", views.resend_otp, name="resend-otp"),
    path("login/", views.CustomObtainAuthToken.as_view(), name="login"),
    path("admin/login/", views.CustomObtainAuthToken.as_view(), name="admin-login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path(
        "test-email/", views.test_email, name="test-email"
    ),  # Use this to test if your email sending functionality is working.
    path(
        "request-password-reset/",
        views.request_password_reset,
        name="request-password-reset",
    ),
    path("reset-password/", views.reset_password, name="reset-password"),
    # Profile-related APIs
    path("get-user-profile/", views.get_user_profile, name="get-user-profile"),
    path("update-user-profile/", views.update_user_profile, name="update-user-profile"),
    path(
        "profile-picture-update/",
        views.profile_picture_update,
        name="profile-picture-update",
    ),
    # Savings goal-related APIs
    path("update-savings-goal/", views.update_savings_goal, name="update-savings-goal"),
    # Admin-related APIs
    path("send-message/<int:recipient_id>/", views.send_message, name="send-message"),
    path("get-messages/<int:recipient_id>/", views.get_messages, name="get-messages"),
    path(
        "send-admin-reply/<int:message_id>/",
        views.send_admin_reply,
        name="send-admin-reply",
    ),
    path(
        "admin/authentication/message/<int:message_id>/reply/",
        views.reply_to_message,
        name="admin-reply-to-message",
    ),
    # Bank-related APIs
    path("api/", include(router.urls)),
    path("add-bank-account/", views.add_bank_account, name="add-bank-account"),
    path(
        "delete-bank-account/<str:account_number>/",
        views.delete_bank_account,
        name="delete-bank-account",
    ),
    path(
        "bank-accounts/get-bank-accounts/", views.get_user_banks, name="get_user_banks"
    ),
    # Card-related APIs
    path("add-card/", CardListCreateView.as_view(), name="card-list-create"),
    path("cards/<int:pk>/", CardDetailView.as_view(), name="card-detail"),
    path("get-cards/", UserCardListView.as_view(), name="user-card-list"),
    path("cards/<int:pk>/delete/", views.DeleteCardView.as_view(), name="delete-card"),
    # Accounts-related APIs
    path(
        "get-account-balances/",
        AccountBalancesAPIView.as_view(),
        name="get-account-balances",
    ),
    path(
        "user-transactions/",
        UserTransactionListView.as_view(),
        name="user-transactions",
    ),
    path(
        "graphql/",
        csrf_exempt(
            jwt_cookie(CustomGraphQLView.as_view(graphiql=True, schema=schema))
        ),
    ),
    # Savings-related APIs
    path("quicksave/", views.quicksave, name="quicksave"),
    path(
        "activate-autosave/", views.autosave, name="autosave"
    ),  # Make sure to use the correct view function
    path("deactivate-autosave/", views.deactivate_autosave, name="deactivate_autosave"),
    path(
        "get-autosave-settings/", views.get_autosave_status, name="get_autosave_status"
    ),
    # Investment-related APIs
    path("quickinvest/", views.quickinvest, name="quickinvest"),
    path("activate-autoinvest/", views.autoinvest, name="autoinvest"),
    path(
        "deactivate-autoinvest/",
        views.deactivate_autoinvest,
        name="deactivate_autoinvest",
    ),
    path(
        "get-autoinvest-settings/",
        views.get_autoinvest_status,
        name="get_autoinvest_status",
    ),
    # Withdrawals-related APIs
    path(
        "savings-to-investment/",
        views.savings_to_investment,
        name="savings-to-investment",
    ),
    path("wallet-to-savings/", views.wallet_to_savings, name="wallet_to_savings"),
    path(
        "wallet-to-investment/", views.wallet_to_investment, name="wallet_to_investment"
    ),
    path(
        "withdraw-to-bank/", views.withdraw_to_local_bank, name="withdraw_to_local_bank"
    ),
    path(
        "process-withdrawal-to-bank/",
        views.process_withdrawal_to_local_bank,
        name="process_withdrawal_to_local_bank",
    ),
    path(
        "cancel-scheduled-withdrawal/",
        views.cancel_scheduled_withdrawal,
        name="cancel_scheduled_withdrawal",
    ),
    path(
        "wallet-transfer/",
        views.wallet_transfer_view,  # ✅ updated view name
        name="wallet_transfer",  # same name, no issue
    ),
    path("delete-my-account/", delete_my_account, name="delete-my-account"),
    path("get-user-by-email/", get_user_by_email, name="get-user-by-email"),
    # Property-related APIs
    path("buy-property/", BuyPropertyView.as_view(), name="buy-property"),
    path(
        "get-all-property-details/",
        views.get_all_property_details,
        name="get-all-property-details",
    ),
    # Top savers
    path("top-savers/", views.get_top_savers, name="top_savers"),
    path(
        "top-savers/<int:month>/<int:year>/",
        views.get_past_top_savers,
        name="get_past_top_savers",
    ),
    # KYC Update API
    path("update-kyc/", KYCUpdateView.as_view(), name="kyc-update"),
    # Endpoint for KYC update
    path("get-kyc-status/", views.GetKYCStatusView.as_view(), name="get-kyc-status"),
    path(
        "kyc-approval/approve/<int:pk>/",
        KYCApprovalViewSet.as_view({"post": "approve_kyc"}),
        name="approve-kyc",
    ),
    path(
        "kyc-approval/reject/<int:pk>/",
        KYCApprovalViewSet.as_view({"post": "reject_kyc"}),
        name="reject-kyc",
    ),
    # Alert Messages API
    path(
        "create-alert-message/", views.create_alert_message, name="create_alert_message"
    ),
    path("get-alert-messages/", views.get_alert_messages, name="get_alert_messages"),
    # Bank Transfer API
    path(
        "initiate-save-transfer/",
        views.initiate_bank_transfer,
        name="initiate_bank_transfer",
    ),
    path(
        "initiate-invest-transfer/",
        views.initiate_invest_transfer,
        name="initiate_invest_transfer",
    ),
    path("message-admin/", views.message_admin, name="message-admin"),
    # DVAs
    path("dva/account/", get_or_create_dva_account, name="get_or_create_dva_account"),
    path("dva/quicksave/", initiate_dva_quicksave, name="initiate_dva_quicksave"),
    path("dva/quickinvest/", initiate_dva_quickinvest, name="initiate_dva_quickinvest"),
    path(
        "initiate-dva-quicksave/", initiate_dva_quicksave, name="initiate_dva_quicksave"
    ),
    path(
        "requery-my-dva-payments/",
        requery_my_dva_payments,
        name="requery_my_dva_payments",
    ),
    # PIN Management APIs
    path("update-myfundpin/", views.update_myfund_pin, name="update-myfundpin"),
    path("has-myfundpin/", views.has_myfund_pin, name="has-myfundpin"),
    path("validate-myfundpin/", views.validate_myfund_pin, name="validate_myfundpin"),
    path("submit_otp/", views.paystack_submit_otp, name="submit_otp"),
    path("paystack-webhook/", views.paystack_webhook, name="paystack-webhook"),
    path("send-pin-reset-otp/", views.send_pin_reset_otp, name="send_pin_reset_otp"),
    path(
        "verify-otp-reset-pin/",
        views.verify_otp_and_reset_pin,
        name="verify_otp_reset_pin",
    ),
    # Admin Related APIs
    path("get-all-users/", views.get_all_users, name="get_all_users"),
    path("send-email/", send_email, name="send_email"),
    path("save-template/", save_template, name="save_template"),
    path("get-templates/", views.get_templates, name="get_templates"),
    path("delete-template/<str:template_id>/", delete_template, name="delete_template"),
    path("edit-template/<int:template_id>/", get_template, name="get_template"),
    path("update-template/<int:template_id>/", update_template, name="update_template"),
    path("users/", get_all_users, name="get_all_users"),
    path("unsubscribe/", unsubscribe_user, name="unsubscribe_user"),
    path("resubscribe/", resubscribe_user, name="resubscribe_user"),
    path(
        "first_time_savers/",
        views.first_ever_transaction_in_month,
        name="first_time_savers",
    ),
    # Group Contribution Related APIs
    path(
        "groupbuy/",
        views.get_active_public_groupbuys,
        name="get_active_public_groupbuys",
    ),
    path("groupbuy/create/", views.create_groupbuy, name="create_groupbuy"),
    path(
        "groupbuy/<int:property_id>/",
        views.get_groupbuy_by_property,
        name="get_groupbuy_by_property",
    ),
    path("groupbuy/join/<str:group_id>/", views.join_groupbuy, name="join_groupbuy"),
    path(
        "groupbuy/invite/<str:group_id>/",
        views.invite_to_groupbuy,
        name="invite_to_groupbuy",
    ),
    path(
        "groupbuy/contribute/<str:group_id>/",
        views.contribute_to_groupbuy,
        name="contribute_to_groupbuy",
    ),
    path(
        "groupbuy/contributions/<str:group_id>/",
        views.get_groupbuy_contributions,
        name="get_groupbuy_contributions",
    ),
    path("groupbuy/leave/<str:group_id>/", views.leave_groupbuy, name="leave_group"),
    path("user/groupbuy/", views.get_user_groupbuys, name="get_user_groupbuys"),
    path(
        "user/groupbuy/contributions/",
        views.get_user_groupbuy_contributions,
        name="get_user_groupbuy_contributions",
    ),
    # Target Savings URLs
    path(
        "target-savings/",
        views.TargetSavingsListCreate.as_view(),
        name="target-savings-list",
    ),
    path(
        "target-savings/<int:pk>/",
        views.TargetSavingsRetrieveUpdateDestroy.as_view(),
        name="target-savings-detail",
    ),
    path(
        "target-savings/<int:pk>/cancel/",
        views.cancel_target_saving,
        name="cancel-target-saving",
    ),
    path(
        "target-savings/total/", views.target_savings_total, name="target-savings-total"
    ),
    path(
        "target-savings/<int:target_id>/force/",
        views.force_target_deduction,
        name="force-target-deduction",
    ),
    path(
        "target-savings/completed/",
        views.completed_target_savings,
        name="completed-target-savings",
    ),
    # MonthlyFinancial APIs
    path(
        "financials/current-month/",
        CurrentMonthFinancialView.as_view(),
        name="current-month-financial",
    ),
    path(
        "financials/history/", FinancialHistoryView.as_view(), name="financial-history"
    ),
    path("admin-totals/", AllUsersMonthlyTotalsView.as_view(), name="all-users-totals"),
    # Notification URLs
    path(
        "notifications/",
        NotificationListCreateView.as_view(),
        name="notifications-list",
    ),
    path(
        "notifications/<int:pk>/read/",
        mark_notification_as_read,
        name="mark-notification-read",
    ),
    path(
        "notifications/mark-all-read/",
        mark_all_notifications_as_read,
        name="mark-all-notifications-read",
    ),
    path(
        "admin/send-notification/",
        send_admin_notification,
        name="send-admin-notification",
    ),
    # ROI & Earnings URLs
    path("roi-summary/", views.get_roi_summary, name="roi-summary"),
    path("earnings/", earnings_summary, name="earnings-summary"),
    # PushNotification URLs
    path(
        "push-notifications/", get_my_push_notifications, name="get_push_notifications"
    ),
    path("admin/send-push/", send_admin_push_notification, name="send_admin_push"),
    path("push/save-token/", save_expo_push_token, name="save_push_token"),
    path("top-referrals/", TopReferralsAPIView.as_view(), name="top-referrals"),

    # Ambassadors
    path("ambassador-report/", AmbassadorMonthlyReportCreateView.as_view(), name="ambassador-report"),
    path("ambassador-report/status/", AmbassadorMonthlyReportStatusView.as_view(), name="ambassador-report-status"),

]
