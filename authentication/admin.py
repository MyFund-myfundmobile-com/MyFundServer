from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    CustomUser,
    Message,
    Property,
    BankAccount,
    InvestTransferRequest,
    BankTransferRequest,
    Card,
    AutoInvest,
    Transaction,
    AutoSave,
    WithdrawalsRequestToAdmin,
    TargetSavings,
    TopSaverHistory,
    DailyROIAccrual,
    ROITransaction,
)
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework.response import Response
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib import admin
from django.db.models import (
    Sum,
    F,
    Count,
    Case,
    When,
    IntegerField,
    Q,
    DecimalField,
    ExpressionWrapper,
)
from django.db import models
from django.db.models.functions import Coalesce
from django.utils import timezone
from .models import CustomUser, CustomUserMetrics, UserPassword, Transaction
import csv
from django.http import HttpResponse
from django.utils.html import format_html
from django.urls import reverse
from .utils import send_push_notification
from decimal import Decimal

GOOGLE_FORM_TEMPLATE = (
    "https://docs.google.com/forms/d/e/1FAIpQLSfHbVd5EtzSyJskgdvCRfGfYrdGaTw3RwCvnkk7pjl6LvS59A/"
    "viewform?usp=pp_url&entry.1884265043={name}&entry.390969690={email}"
)


@admin.action(description="Say Hello")
def say_hello(modeladmin, request, queryset):
    messages.success(request, "👋 Hello from admin action!")


class TransactionInline(admin.TabularInline):
    model = Transaction
    fk_name = "user"
    extra = 0
    fields = (
        "transaction_type",
        "amount",
        "service_charge",
        "total_amount",
        "date",
        "time",
        "description",
        "transaction_id",
    )
    readonly_fields = (
        "transaction_id",
        "date",
        "time",
    )


# class UserPasswordInline(admin.StackedInline):
#     model = UserPassword
#     can_delete = False
#     verbose_name_plural = "Password"


# admin.py - Add these BEFORE CustomUserAdmin class


class DailyROIAccrualInline(admin.TabularInline):
    model = DailyROIAccrual
    extra = 0
    readonly_fields = [
        "date",
        "savings_balance",
        "investment_balance",
        "savings_roi",
        "investment_roi",
        "total_roi",
    ]
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


class ROITransactionInline(admin.TabularInline):
    model = ROITransaction
    extra = 0
    readonly_fields = [
        "accrued_date",
        "amount",
        "roi_type",
        "is_paid_out",
        "payout_date",
    ]
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


from .utils import send_push_notification  # assuming utils is in authentication
from decimal import Decimal


class CustomUserAdmin(UserAdmin):
    list_display = (
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "get_total_referrals",
        "get_confirmed_referrals",
        "date_joined",
        "savings",
        "investment",
        "properties",
        "wallet",
        "total_savings_and_investments",
        "total_savings_and_investments_this_month",
        "user_percentage_to_top_saver",
        "how_did_you_hear",
        "is_hired_referrer",
        "is_ambassador",
        "kyc_updated",
        "is_staff",
        "is_active",
        "is_banned",  # 👈 show banned status
        "profile_picture",
        "pending_roi",  # 👈 add this
    )
    list_filter = (
        "is_staff",
        "is_active",
        "is_banned",  # 👈 show banned status
        "kyc_updated",
        "how_did_you_hear",
        "date_joined",
        "is_hired_referrer",
        "is_ambassador",
    )
    readonly_fields = ("get_total_referrals", "get_confirmed_referrals", "date_joined")

    actions = [
        "ban_user",
        "unban_user",
        "export_to_csv",  # Add export action
        "send_custom_email",
        "view_kyc_details",
        "approve_kyc",
        "reject_kyc",
        "make_hired_referrer",
        "make_ambassador",
        "revoke_ambassador",
        "delete_selected",
        "deactivate_user" "notify_outdated_users",
        "say_hello",
        "simulate_quarterly_payout",
        "test_daily_roi_calculation",  # ← Add this
        "test_quarterly_payout",  # ← Add this
        "view_roi_summary",  # ← Add this
        "test_top_saver_reward",
    ]

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Info",
            {"fields": ("first_name", "last_name", "phone_number", "profile_picture")},
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_staff",
                    "is_active",
                    "is_superuser",
                    "is_ambassador",
                    "is_hired_referrer",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Referral Stats",
            {
                "fields": (
                    "get_total_referrals",
                    "get_confirmed_referrals",
                )
            },
        ),
        (
            "Account Balances",
            {
                "fields": (
                    "savings",
                    "investment",
                    "properties",
                    "wallet",
                    "pending_roi",
                )
            },
        ),  # Add account balances fields
        ("Referral", {"fields": ("pending_referral_reward",)}),
        # Add a fieldset for KYC fields
        (
            "KYC Information",
            {
                "fields": (
                    "gender",
                    "relationship_status",
                    "employment_status",
                    "yearly_income",
                    "date_of_birth",
                    "address",
                    "mothers_maiden_name",
                    "identification_type",
                    "id_upload",
                    "next_of_kin_name",
                    "relationship_with_next_of_kin",
                    "next_of_kin_phone_number",
                ),
            },
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
    )
    search_fields = ("email", "first_name", "last_name")
    ordering = ("email", "date_joined")
    inlines = [
        TransactionInline,
        # UserPasswordInline,
        DailyROIAccrualInline,
        ROITransactionInline,
    ]

    def get_total_referrals(self, obj):
        return Transaction.objects.filter(referral_email=obj.email).count()

    get_total_referrals.short_description = "Total Referrals"

    def get_confirmed_referrals(self, obj):
        return Transaction.objects.filter(
            referral_email=obj.email, status="confirmed"
        ).count()

    get_confirmed_referrals.short_description = "Confirmed Referrals"

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.annotate(
            _total_referrals=Count("referral_transactions"),
            _confirmed_referrals=Count(
                "referral_transactions",
                filter=Q(referral_transactions__status="confirmed"),
            ),
        )

    def get_daily_savings_roi_rate(self):
        """Calculate daily savings ROI rate (13% per annum)"""
        return Decimal("0.13") / Decimal("365")

    def get_daily_investment_roi_rate(self):
        """Calculate daily investment ROI rate (20% per annum)"""
        return Decimal("0.20") / Decimal("365")

    def calculate_daily_roi(self, date=None):
        """Calculate ROI for a specific date based on current balances"""
        if date is None:
            date = timezone.now().date()

        daily_savings_rate = self.get_daily_savings_roi_rate()
        daily_investment_rate = self.get_daily_investment_roi_rate()

        savings_roi = self.savings * daily_savings_rate
        investment_roi = self.investment * daily_investment_rate
        total_roi = savings_roi + investment_roi

        return {
            "savings_roi": round(savings_roi, 2),
            "investment_roi": round(investment_roi, 2),
            "total_roi": round(total_roi, 2),
        }

    @admin.action(description="🚫 Ban selected users (cannot reactivate)")
    def ban_user(self, request, queryset):
        queryset.update(is_banned=True, is_active=False)
        self.message_user(request, f"{queryset.count()} user(s) banned successfully.")

    @admin.action(description="✅ Unban selected users")
    def unban_user(self, request, queryset):
        queryset.update(is_banned=False)
        self.message_user(request, f"{queryset.count()} user(s) unbanned successfully.")

    @admin.action(description="Simulate Quarterly ROI Payout")
    def simulate_quarterly_payout(self, request, queryset):
        from .tasks import process_quarterly_payouts_task

        result = process_quarterly_payouts_task()
        self.message_user(request, f"Simulation completed: {result}")

    def export_to_csv(self, request, queryset):
        # Create the response object and set the content type
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="custom_users.csv"'

        # Create the CSV writer
        writer = csv.writer(response)
        writer.writerow(
            [
                "ID",
                "Email",
                "First Name",
                "Last Name",
                "Phone Number",
                "Date Joined",
                "Profile Picture",
                "KYC Updated",
                "Is Staff",
                "Is Active",
                "Preferred Asset",
                "Savings Goal Amount",
                "Time Period",
                "Savings",
                "Investment",
                "Properties",
                "Wallet",
                "Total Savings and Investments",
                "Total Savings and Investments This Month",
                "User Percentage to Top Saver",
                "How Did You Hear",
                "Is Hired Referrer",
                "Is Ambassador",
            ]
        )

        # Write user data rows
        for user in queryset:
            writer.writerow(
                [
                    user.id,
                    user.email,
                    user.first_name,
                    user.last_name,
                    user.phone_number,
                    user.date_joined,
                    user.profile_picture,
                    user.kyc_updated,
                    user.is_staff,
                    user.is_active,
                    user.preferred_asset,
                    user.savings_goal_amount,
                    user.time_period,
                    user.savings,
                    user.investment,
                    user.properties,
                    user.wallet,
                    user.total_savings_and_investments_this_month,
                    user.how_did_you_hear,
                    user.is_hired_referrer,
                    user.is_ambassador,
                ]
            )

        return response

    export_to_csv.short_description = "Export selected users to CSV"

    @admin.action(description="🎯 Test Quarterly Payout")
    def test_quarterly_payout(self, request, queryset):
        from django.utils import timezone
        from datetime import date
        from django.db import transaction as db_transaction
        from .models import ROITransaction, Transaction
        from .utils import send_push_notification

        for user in queryset:
            try:
                # Get wallet balance before
                old_wallet = user.wallet

                # Create some test ROI transactions if none exist
                from .models import ROITransaction

                # Check if user has any unpaid ROI transactions
                unpaid_count = ROITransaction.objects.filter(
                    user=user, is_paid_out=False
                ).count()

                if unpaid_count == 0:
                    # Create test ROI transactions
                    ROITransaction.objects.create(
                        user=user,
                        amount=150.75,
                        roi_type="SAVINGS",
                        accrued_date=date(2024, 1, 15),
                        is_paid_out=False,
                    )
                    ROITransaction.objects.create(
                        user=user,
                        amount=89.25,
                        roi_type="INVESTMENT",
                        accrued_date=date(2024, 1, 20),
                        is_paid_out=False,
                    )
                    self.message_user(
                        request, f"📝 Created test ROI transactions for {user.email}"
                    )

                # Process payout SYNCHRONOUSLY
                today = timezone.now().date()

                # Get all unpaid ROI transactions for this user
                unpaid_roi = ROITransaction.objects.filter(user=user, is_paid_out=False)

                total_payout = sum(transaction.amount for transaction in unpaid_roi)

                if total_payout > 0:
                    with db_transaction.atomic():
                        # Credit wallet
                        user.wallet += total_payout
                        user.save(update_fields=["wallet"])

                        # Mark ROI transactions as paid
                        unpaid_roi.update(is_paid_out=True, payout_date=today)

                        # Calculate breakdown for description
                        savings_roi_total = sum(
                            t.amount for t in unpaid_roi if t.roi_type == "SAVINGS"
                        )
                        investment_roi_total = sum(
                            t.amount for t in unpaid_roi if t.roi_type == "INVESTMENT"
                        )

                        # Create transaction record (WITHOUT metadata)
                        Transaction.objects.create(
                            user=user,
                            transaction_type="CREDIT",
                            source="QUARTERLY_ROI_PAYOUT",
                            amount=total_payout,
                            description=f"Quarterly ROI payout - Savings: ₦{savings_roi_total:,.2f}, Investments: ₦{investment_roi_total:,.2f}",
                        )

                        # Send notification
                        send_push_notification(
                            user,
                            title="🎉 Test Quarterly ROI Payout!",
                            message=f"₦{total_payout:,.2f} has been credited to your wallet",
                            data={
                                "type": "TEST_QUARTERLY_PAYOUT",
                                "amount": float(total_payout),
                                "period": "Test",
                            },
                        )

                # Refresh user data
                user.refresh_from_db()
                new_wallet = user.wallet

                self.message_user(
                    request,
                    f"✅ Payout test for {user.email}: Wallet ₦{old_wallet:,.2f} → ₦{new_wallet:,.2f}",
                )

            except Exception as e:
                self.message_user(
                    request,
                    f"❌ Payout error for {user.email}: {str(e)}",
                    level=messages.ERROR,
                )

    @admin.action(description="🧪 Test Daily ROI Calculation")
    def test_daily_roi_calculation(self, request, queryset):
        from .utils import calculate_daily_roi, send_push_notification

        for user in queryset:
            try:
                # Calculate ROI for this user using the utils function
                total_roi, savings_roi, investment_roi = calculate_daily_roi(user)

                # Send notification
                send_push_notification(
                    user,
                    title="💰 Test Daily ROI",
                    message=f"Test: Savings: ₦{savings_roi:,.2f}, Investments: ₦{investment_roi:,.2f}",
                    data={
                        "type": "TEST_DAILY_ROI",
                        "savings_roi": float(savings_roi),
                        "investment_roi": float(investment_roi),
                        "total_roi": float(total_roi),
                    },
                )

                self.message_user(
                    request,
                    f"✅ Test ROI calculated for {user.email}: ₦{total_roi:,.2f} total",
                )

            except Exception as e:
                self.message_user(
                    request,
                    f"❌ Error for {user.email}: {str(e)}",
                    level=messages.ERROR,
                )

    @admin.action(description="🏆 Test Top Saver Notification (No Credit)")
    def test_top_saver_reward(self, request, queryset):
        from django.utils import timezone
        from .utils import send_push_notification, send_generic_email
        import datetime, logging

        logger = logging.getLogger(__name__)

        now = timezone.now()
        prev_month = now.month - 1 or 12
        year = now.year if now.month > 1 else now.year - 1
        prev_month_name = datetime.date(year, prev_month, 1).strftime("%B")

        for user in queryset:
            try:
                logger.info(f"[TEST_TOP_SAVER] Processing user: {user.email}")

                pre_filled_link = GOOGLE_FORM_TEMPLATE.format(
                    name=f"{user.first_name} {user.last_name}", email=user.email
                )

                has_been_top3_before = TopSaverHistory.objects.filter(
                    user=user, rank__lte=3
                ).exists()

                send_push_notification(
                    user,
                    title=f"🎉 Test Top Saver Notification!",
                    message=(
                        f"Congrats {user.first_name}! You made the Top 3 for {prev_month_name} (test). "
                        "Check your email for the simulated feedback form."
                    ),
                    data={"type": "TOP_SAVER_TEST"},
                )

                if not has_been_top3_before:
                    email_message = f"""
                    Hi {user.first_name or user.email},<br><br>
                    🎉 This is a <b>test</b> Top Saver Notification for <b>{prev_month_name}</b>.<br><br>
                    You’ve qualified for a <b>MyFund Branded T-Shirt</b> 👕 as a first-time Top Saver!<br><br>
                    Please fill this test form so we can record your details:<br><br>
                    <a href="{pre_filled_link}"><b>MyFund Top Saver Form (Test)</b></a><br><br>
                    — The MyFund Team
                    """
                else:
                    email_message = f"""
                    Hi {user.first_name or user.email},<br><br>
                    🎉 This is a <b>test</b> Top Saver Notification for <b>{prev_month_name}</b>.<br><br>
                    You’ve made the Top 3 again — great consistency!<br>
                    Please complete the feedback form:<br>
                    <a href="{pre_filled_link}">MyFund Feedback Form (Test)</a><br><br>
                    — The MyFund Team
                    """

                logger.info(f"[TEST_TOP_SAVER] Sending email to {user.email}")

                send_generic_email(
                    subject=f"[TEST] Top Saver Notification - {prev_month_name}",
                    message=email_message,
                    from_email="MyFund <info@myfundmobile.com>",
                    recipient_list=[user.email],
                )

                logger.info(f"[TEST_TOP_SAVER] Email sent to {user.email}")
                self.message_user(request, f"✅ Test notification sent to {user.email}")

            except Exception as e:
                logger.error(
                    f"[TEST_TOP_SAVER] Error for {user.email}: {str(e)}", exc_info=True
                )
                self.message_user(request, f"❌ Error for {user.email}: {str(e)}")

    @admin.action(description="Notify users with outdated app versions")
    def notify_outdated_users(self, request, queryset):
        from packaging import version
        from .utils import send_push_notification

        MIN_REQUIRED_VERSION = "3.1.7"
        count = 0

        for user in queryset:
            tokens = user.expo_push_tokens or []
            for token in tokens:
                app_version = token.get("app_version")
                if app_version and version.parse(app_version) < version.parse(
                    MIN_REQUIRED_VERSION
                ):
                    send_push_notification(
                        user,
                        "Update Required",
                        "A new version of MyFund is available. Please update to enjoy full features.",
                        notif_type="VERSION",
                    )
                    count += 1
                    break  # Notify once per user

        messages.success(request, f"✅ Sent update notice to {count} user(s).")

    def view_kyc_details(self, request, queryset):
        if queryset.count() == 1:
            user = queryset.first()
            url = reverse("admin:authentication_customuser_change", args=[user.id])
            return HttpResponseRedirect(url)
        else:
            self.message_user(
                request, "Please select only one user to view KYC details."
            )

    view_kyc_details.short_description = "View KYC Details"

    # === add code
    def deactivate_user(self, request, queryset):
        queryset.update(is_active=False)

    deactivate_user.short_description = "Deactivate user"

    def approve_kyc(self, request, queryset):
        updated_users = []
        rejected_users = []

        for user in queryset:
            if not user.kyc_updated:
                user.kyc_updated = True
                user.kyc_status = "Updated!"
                user.admin_approval_status = "Approved!"
                user.save()
                updated_users.append(user)

                # Send an approval email to the user
                subject = "KYC Update Approved!"
                message = f"Hi {user.first_name}, \n\nThank you for updating your KYC information. Your KYC update has been approved.\n\nKeep growing your funds!🥂\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )

                # Send push notification
                send_push_notification(
                    user=user,
                    title="KYC Verified ✅",
                    message="Hi {}, your KYC has been verified. You can now enjoy full access.".format(
                        user.first_name
                    ),
                    data={"kyc_status": "verified"},
                    notif_type="ACCOUNT",
                )

            else:
                rejected_users.append(user)

        if updated_users:
            if len(updated_users) == 1:
                message_bit = f"1 user ({updated_users[0]}) was"
            else:
                message_bit = f"{len(updated_users)} users were"
            self.message_user(request, f"{message_bit} approved for KYC update.")

        if rejected_users:
            if len(rejected_users) == 1:
                message_bit = f"1 user ({rejected_users[0]}) was"
            else:
                message_bit = f"{len(rejected_users)} users were"
            self.message_user(
                request, f"{message_bit} already approved for KYC update."
            )

    approve_kyc.short_description = "Approve KYC Details"

    def reject_kyc(self, request, queryset):
        for user in queryset:
            if user.kyc_updated:
                user.kyc_updated = False
                user.kyc_status = "failed"
                user.admin_approval_status = "rejected"  # Update admin approval status

                user.save()

                # Send a rejection email to the user
                subject = "KYC Update Failed!"
                message = f"Hi {user.first_name}, \n\nThank you for updating your KYC information. Unfortunately, we couldn't verify your information. Kindly check and try again.\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )

        self.message_user(request, f"Rejected KYC for {queryset.count()} user(s).")

        # Redirect to the changelist view after processing
        return HttpResponseRedirect(
            reverse("admin:authentication_customuser_changelist")
        )

    reject_kyc.short_description = "Reject KYC Details"

    def total_savings_and_investments(self, obj):
        return obj.savings + obj.investment

    total_savings_and_investments.short_description = "Total Savings and Investments"

    # Define a custom method to display 'Total Savings/Investment for the month'
    def savings_and_investment_for_month(self, obj):
        return obj.savings_and_investments

    savings_and_investment_for_month.short_description = (
        "Total Savings/Investment for the month"
    )

    def user_percentage_to_top_saver(self, obj):
        top_saver = (
            CustomUser.objects.filter(is_deleted=False)
            .order_by("-total_savings_and_investments_this_month")
            .first()
        )
        if top_saver and top_saver.total_savings_and_investments_this_month > 0:
            user_percentage = (
                obj.total_savings_and_investments_this_month
                / top_saver.total_savings_and_investments_this_month
            ) * 100
        else:
            user_percentage = 0
        return f"{user_percentage:.2f}%"

    user_percentage_to_top_saver.short_description = "Percentage to Top Saver"
    user_percentage_to_top_saver.admin_order_field = (
        "total_savings_and_investments_this_month"
    )

    change_list_template = (
        "admin/custom_user_change_list.html"  # Use the same template file
    )

    def changelist_view(self, request, extra_context=None):
        current_month_start = timezone.now().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        if request.method == "POST" and "_delete_selected" in request.POST:
            # Handle the delete action
            deleted_users = self.delete_selected(
                request, queryset=request.POST.getlist("_selected_action")
            )
            self.message_user(request, f"Deleted {len(deleted_users)} user(s).")

            # Redirect to the changelist view after processing the delete action
            return HttpResponseRedirect(
                reverse("admin:authentication_customuser_changelist")
            )

        # Calculate the total metrics separately
        total_users = CustomUser.objects.count()
        total_savings = (
            CustomUser.objects.aggregate(total_savings=Sum("savings"))["total_savings"]
            or 0
        )
        total_investments = (
            CustomUser.objects.aggregate(total_investments=Sum("investment"))[
                "total_investments"
            ]
            or 0
        )
        total_wallets = (
            CustomUser.objects.aggregate(total_wallets=Sum("wallet"))["total_wallets"]
            or 0
        )
        total_properties = (
            CustomUser.objects.aggregate(total_properties=Sum("properties"))[
                "total_properties"
            ]
            or 0
        )
        total_savings_and_investments = (
            CustomUser.objects.aggregate(
                total_savings_and_investments=Sum(F("savings") + F("investment"))
            )["total_savings_and_investments"]
            or 0
        )

        total_savings_and_investments_this_month = (
            CustomUser.objects.filter(
                user_transactions__date__year=current_month_start.year,  # ✅ Fixed
                user_transactions__date__month=current_month_start.month,
            ).aggregate(
                total_savings_and_investments_this_month=Sum(
                    "total_savings_and_investments_this_month"
                )
            )[
                "total_savings_and_investments_this_month"
            ]
            or 0
        )

        # Get the existing context
        response = super().changelist_view(request, extra_context=extra_context)

        # Update the context with the total metrics
        if hasattr(response, "context_data"):
            content_data = response.context_data
            content_data["total_users"] = total_users
            content_data["total_savings"] = total_savings
            content_data["total_investments"] = total_investments
            content_data["total_wallets"] = total_wallets
            content_data["total_properties"] = total_properties
            content_data["total_savings_and_investments"] = (
                total_savings_and_investments
            )
            content_data["total_savings_and_investments_this_month"] = (
                total_savings_and_investments_this_month
            )

        return response


admin.site.register(CustomUser, CustomUserAdmin)


from django.contrib import messages
import uuid


@admin.register(BankTransferRequest)
class BankTransferRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "amount", "is_approved", "created_at")
    list_filter = ("is_approved",)
    search_fields = ("user__email", "transaction_id", "amount")
    actions = ["approve_bank_transfer"]

    def approve_bank_transfer(self, request, queryset):
        for transfer_request in queryset:
            user = transfer_request.user
            transaction_id = transfer_request.transaction_id

            # ✅ Check for existing pending transaction using transaction_id
            transaction = Transaction.objects.filter(
                user=user, transaction_id=transaction_id, status="pending"
            ).first()

            if transaction:
                # ✅ Update transaction status
                transaction.status = "confirmed"
                transaction.date = timezone.now()
                transaction.description = "QuickSave (Transfer)"
                transaction.save()
            else:
                # ❌ Log error if transaction is not found
                print(
                    f"❌ ERROR: Pending transaction {transaction_id} not found for {user.email}"
                )
                self.message_user(
                    request,
                    f"Pending transaction {transaction_id} not found for {user.email}!",
                    level="error",
                )
                continue  # Skip processing this request

            # ✅ Approve the transfer request
            transfer_request.is_approved = True
            transfer_request.save()

            # ✅ Update user savings
            user.savings += int(transfer_request.amount)
            user.save()

            # Call the confirm_referral_rewards method here
            if user.referral:
                user.confirm_referral_rewards(is_referrer=False)

            # After processing an investment transfer transaction
            user.update_total_savings_and_investment_this_month()

            # ✅ Send Approval Email
            subject = "QuickSave Updated! ✅"
            message = f"Hi {user.first_name},\n\nYour bank transfer of ₦{transfer_request.amount} has been approved and added to your savings!\n\nKeep growing your funds! \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            send_mail(subject, message, "MyFund <info@myfundmobile.com>", [user.email])

            send_push_notification(
                user=user,
                title="QuickSave Approved ✅",
                message="Hi {}, your transfer of ₦{:,} has been added to your Savings account. Check to confirm.".format(
                    user.first_name, int(transfer_request.amount)
                ),
                data={
                    "amount": str(transfer_request.amount),
                    "transaction_id": transaction_id,
                    "type": "QuickSave",
                },
                notif_type="CREDIT",
            )

        self.message_user(
            request, "Selected bank transfers approved successfully!", level="success"
        )

    approve_bank_transfer.short_description = "Approve selected bank transfers"


@admin.register(InvestTransferRequest)
class InvestTransferRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "amount", "is_approved", "created_at")
    list_filter = ("is_approved",)
    actions = ["approve_invest_transfer", "reject_invest_transfer"]

    def approve_invest_transfer(self, request, queryset):
        for transfer_request in queryset:
            user = transfer_request.user
            transaction_id = transfer_request.transaction_id

            # ✅ Check for existing pending transaction using transaction_id
            transaction = Transaction.objects.filter(
                user=user, transaction_id=transaction_id, status="pending"
            ).first()

            if transaction:
                # ✅ Update transaction status
                transaction.status = "confirmed"
                transaction.date = timezone.now()
                transaction.description = "QuickInvest (Transfer)"
                transaction.save()
            else:
                # ❌ Log error if transaction is not found
                print(
                    f"❌ ERROR: Pending transaction {transaction_id} not found for {user.email}"
                )
                self.message_user(
                    request,
                    f"Pending transaction {transaction_id} not found for {user.email}!",
                    level="error",
                )
                continue  # Skip processing this request

            # ✅ Approve the transfer request
            transfer_request.is_approved = True
            transfer_request.save()

            # ✅ Update user's investment
            user.investment += int(transfer_request.amount)
            user.save()

            # Call the confirm_referral_rewards method here
            is_referrer = True
            user.confirm_referral_rewards(is_referrer=is_referrer)

            # After processing an investment transfer transaction
            user.update_total_savings_and_investment_this_month()

            # ✅ Send Approval Email
            subject = "QuickInvest Updated! ✔"
            message = f"Hi {user.first_name},\n\nYour investment transfer of ₦{transfer_request.amount} has been approved and added to your investments!\n\nKeep growing your funds! \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            send_mail(subject, message, "MyFund <info@myfundmobile.com>", [user.email])

            send_push_notification(
                user=user,
                title="QuickInvest Approved ✅",
                message="Hi {}, your transfer of ₦{:,} has been added to your Investment account. Check to confirm.".format(
                    user.first_name, int(transfer_request.amount)
                ),
                data={
                    "amount": str(transfer_request.amount),
                    "transaction_id": transaction_id,
                    "type": "QuickInvest",
                },
                notif_type="CREDIT",
            )

        self.message_user(
            request,
            "Selected investment transfers approved successfully!",
            level="success",
        )

    approve_invest_transfer.short_description = "Approve selected investment transfers"


from django.contrib import admin
from django.db import transaction as db_transaction
from django.core.mail import send_mail
from .models import WithdrawalsRequestToAdmin, Transaction


@admin.register(WithdrawalsRequestToAdmin)
class PendingWithdrawalsAdmin(admin.ModelAdmin):
    list_display = (
        "is_approved",
        "user",
        "source_account",
        "withdrawal_type",
        "total_amount_display",  # Original requested amount
        "charge_percentage_display",  # %
        "charge_amount_display",  # ₦ charge
        "net_amount_display",  # ₦ to send
        "target_bank",
        "target_account_number",
        "created_at",
        "scheduled_processing_date",
        "transaction_id",
    )

    list_filter = (
        "is_approved",
        "source_account",
        "withdrawal_type",
    )

    search_fields = (
        "user__email",
        "transaction_id",
        "target_bank",
        "source_account",
        "target_account_number",
    )

    actions = ["approve_withdrawal"]

    # =========================
    # DISPLAY HELPERS (READ-ONLY)
    # =========================

    def total_amount_display(self, obj):
        """Original amount requested by user"""
        return f"₦{obj.total_amount:,.2f}"

    total_amount_display.short_description = "Requested"

    def charge_percentage_display(self, obj):
        """Stored charge percentage"""
        if obj.withdrawal_type.lower() != "immediate":
            return "0%"
        return f"{obj.charge_percentage:.0f}%"

    charge_percentage_display.short_description = "%"

    def charge_amount_display(self, obj):
        """Stored charge amount"""
        return f"₦{obj.charge_amount:,.2f}"

    charge_amount_display.short_description = "Charge"

    def net_amount_display(self, obj):
        """Amount admin should send"""
        return f"₦{obj.amount:,.2f}"

    net_amount_display.short_description = "To Send"

    # =========================
    # ADMIN ACTION
    # =========================

    def approve_withdrawal(self, request, queryset):
        approved_count = 0

        for withdrawal in queryset:
            if withdrawal.is_approved:
                continue

            user = withdrawal.user
            transaction_id = withdrawal.transaction_id

            try:
                with db_transaction.atomic():
                    withdrawal.is_approved = True
                    withdrawal.save(update_fields=["is_approved"])

                    transaction = Transaction.objects.get(
                        user=user, transaction_id=transaction_id
                    )
                    transaction.status = "confirmed"
                    transaction.description = (
                        f"Withdrawal: Sent ₦{withdrawal.amount:,.2f} "
                        f"(Fee: ₦{withdrawal.charge_amount:,.2f})"
                    )
                    transaction.save()

                    approved_count += 1

                    # Push notification
                    send_push_notification(
                        user=user,
                        title="Withdrawal Approved! ✅",
                        message=(
                            f"Your withdrawal of ₦{withdrawal.amount:,.2f} "
                            f"to {withdrawal.target_bank} has been approved."
                        ),
                        data={
                            "amount": str(withdrawal.amount),
                            "transaction_id": transaction_id,
                            "source_account": withdrawal.source_account,
                            "status": "confirmed",
                        },
                        notif_type="DEBIT",
                    )

                    # Email
                    send_mail(
                        subject="Withdrawal Approved ✔",
                        message=(
                            f"Hi {user.first_name},\n\n"
                            f"Your withdrawal of ₦{withdrawal.amount:,.2f} from your "
                            f"{withdrawal.source_account.capitalize()} account "
                            f"has been approved.\n\n"
                            f"Transaction ID: {transaction_id}\n\n"
                            f"MyFund Team"
                        ),
                        from_email="MyFund <info@myfundmobile.com>",
                        recipient_list=[user.email],
                        fail_silently=False,
                    )

            except Exception as e:
                self.message_user(
                    request,
                    f"Error approving {transaction_id}: {str(e)}",
                    level="error",
                )

        if approved_count:
            self.message_user(
                request, f"{approved_count} withdrawal(s) approved successfully."
            )
        else:
            self.message_user(request, "No withdrawals were approved.")


class BankAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "bank_name",
        "account_number",
        "account_name",
        "is_default",
    )
    list_filter = ("is_default",)
    search_fields = (
        "user__email",
        "bank_name",
        "account_number",
        "account_name",
    )  # Add this line


admin.site.register(BankAccount, BankAccountAdmin)


class CardAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "bank_name",
        "card_number",
        "expiry_date",
        "cvv",
        "is_default",
    )
    list_filter = ("is_default",)
    search_fields = ("user__email", "bank_name", "card_number")  # Add search options


class AutoSaveAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "frequency",
        "amount",
        "active",
    )
    search_fields = ("user__email", "frequency")  # Add search options


class AutoInvestAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "frequency", "amount", "active")
    search_fields = ("user__email", "frequency")  # Add search options


from django.contrib import admin
from .models import Transaction


class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "transaction_type",
        "status",
        "amount",
        "date",
        "time",
        "description",
        "transaction_id",
        "is_referral_transaction",
    )
    list_filter = (
        "transaction_type",
        "status",
        ("date", admin.DateFieldListFilter),
    )
    # error comes
    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "description",
        "transaction_id",
        "status",
        "amount",
        # "referral__user__email",
        "referral_email",
    )

    def is_referral_transaction(self, obj):
        return bool(obj.referral_email)

    is_referral_transaction.boolean = True
    is_referral_transaction.short_description = "Is Referral?"

    def save_model(self, request, obj, form, change):
        print(
            f"DEBUG: Saving transaction: {obj.transaction_type} (Length: {len(obj.transaction_type)})"
        )
        super().save_model(request, obj, form, change)


class PropertyAdmin(admin.ModelAdmin):
    list_display = ["id", "name", "price", "rent_reward", "units_available"]
    list_editable = [
        "units_available"
    ]  # Make the units_available field editable in the list view


from django.db.models import F, Count, Q
import csv
from django.http import HttpResponse
from django.contrib import admin
from .models import TopSaverHistory
from django.utils import timezone
import calendar


# Action to export selected entries to CSV
def export_selected_to_csv(modeladmin, request, queryset):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=selected_top_savers.csv"

    writer = csv.writer(response)
    writer.writerow(["Month", "Rank", "Full Name", "Phone Number", "Email"])

    for obj in queryset.select_related("user"):
        user = obj.user
        if not user:
            continue

        full_name = f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}".strip()
        writer.writerow(
            [
                calendar.month_name[obj.month],
                obj.rank,
                full_name,
                getattr(user, "phone_number", ""),
                getattr(user, "email", ""),
            ]
        )

    return response


export_selected_to_csv.short_description = "Export selected top savers to CSV"


# Action to export all entries to CSV
def export_all_to_csv(modeladmin, request, queryset):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="top_saver_history.csv"'

    writer = csv.writer(response)
    writer.writerow(["Month", "Rank", "Full Name", "Phone Number", "Email"])

    for obj in TopSaverHistory.objects.select_related("user").all():
        user = obj.user
        if not user:
            continue

        full_name = f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}".strip()
        writer.writerow(
            [
                calendar.month_name[obj.month],
                obj.rank,
                full_name,
                getattr(user, "phone_number", ""),
                getattr(user, "email", ""),
            ]
        )

    return response


export_all_to_csv.short_description = "Export ALL top savers to CSV"


# Custom Admin for TopSaverHistory
class TopSaverHistoryAdmin(admin.ModelAdmin):
    list_display = (
        "get_month_name",
        "rank",
        "get_full_name",
        "get_phone_number",
        "get_email",
        "total_savings",
        "is_current_month",
    )
    search_fields = (
        "user__first_name",
        "user__last_name",
        "user__email",
        "user__phone_number",
        "month",
    )
    list_filter = ("month",)
    ordering = ("-month", "rank")
    list_per_page = 20
    actions = [export_selected_to_csv, export_all_to_csv]

    def get_month_name(self, obj):
        return calendar.month_name[obj.month]

    get_month_name.short_description = "Month"

    def get_full_name(self, obj):
        user = obj.user
        if not user:
            return "—"
        return f"{user.first_name} {user.last_name}".strip()

    get_full_name.short_description = "Full Name"

    def get_phone_number(self, obj):
        return getattr(obj.user, "phone_number", "—")

    get_phone_number.short_description = "Phone Number"

    def get_email(self, obj):
        return obj.user.email

    get_email.short_description = "Email"

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related("user").order_by("-month", "rank")

    def is_current_month(self, obj):
        now = timezone.now()
        return obj.month == now.month and obj.year == now.year

    is_current_month.boolean = True
    is_current_month.short_description = "Current Month"


admin.site.register(TopSaverHistory, TopSaverHistoryAdmin)


from django.contrib import admin
from django.utils import timezone
from django.utils.timezone import localtime
from .models import TargetSavings, TargetSavingsCompletion, Notification
import logging

logger = logging.getLogger(__name__)


@admin.register(TargetSavings)
class TargetSavingsAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "name",
        "target_amount",
        "current_amount",
        "progress_percentage",
        "frequency",
        "is_active",
        "is_cancelled",
        "formatted_next_deduction",
        "formatted_last_processed",
    ]
    list_filter = ["is_active", "is_cancelled", "frequency", "category"]
    search_fields = ["user__email", "name"]
    readonly_fields = ["current_amount", "progress_percentage", "last_processed"]
    actions = ["force_process_deduction", "mark_as_completed"]

    def progress_percentage(self, obj):
        return f"{obj.progress_percentage:.1f}%"

    progress_percentage.short_description = "Progress"

    def formatted_next_deduction(self, obj):
        if obj.next_deduction:
            return localtime(obj.next_deduction).strftime("%b %d, %Y, %I:%M %p")
        return "-"

    formatted_next_deduction.admin_order_field = "next_deduction"
    formatted_next_deduction.short_description = "Next deduction"

    def formatted_last_processed(self, obj):
        if obj.last_processed:
            return localtime(obj.last_processed).strftime("%b %d, %Y, %I:%M %p")
        return "-"

    formatted_last_processed.admin_order_field = "last_processed"
    formatted_last_processed.short_description = "Last processed"

    def force_process_deduction(self, request, queryset):
        results = {"processed": 0, "paused": 0, "failed": 0, "errors": []}

        for target in queryset:
            if target.is_active and not target.is_cancelled:
                try:
                    # DEBUG: Log current state before processing
                    logger.info(
                        f"🔄 Admin forcing deduction for target {target.id}: {target.name}"
                    )
                    logger.info(
                        f"   Attempts: {target.deduction_attempts}/{target.max_attempts}"
                    )
                    logger.info(f"   Current amount: {target.current_amount}")
                    logger.info(f"   Monthly payment: {target.monthly_payment}")
                    logger.info(f"   User savings: {target.user.savings}")
                    logger.info(f"   User investment: {target.user.investment}")
                    logger.info(f"   Funding source: {target.funding_source}")

                    # Check if deduction would actually fail
                    amount = target.monthly_payment or Decimal("0")
                    if target.funding_source == "SAVINGS":
                        will_fail = target.user.savings < amount
                    else:
                        will_fail = target.user.investment < amount

                    logger.info(f"   Will fail due to insufficient funds: {will_fail}")

                    success = target.process_deduction()

                    # Refresh the target to get updated data
                    target.refresh_from_db()

                    logger.info(f"   ✅ After processing:")
                    logger.info(
                        f"   Attempts: {target.deduction_attempts}/{target.max_attempts}"
                    )
                    logger.info(f"   Is active: {target.is_active}")
                    logger.info(f"   Success result: {success}")

                    if success:
                        results["processed"] += 1
                    elif not target.is_active:
                        results["paused"] += 1
                        logger.info(
                            f"🛑 Target {target.id} was PAUSED due to max attempts"
                        )
                    else:
                        results["failed"] += 1

                except Exception as e:
                    error_msg = f"Error processing target {target.name}: {str(e)}"
                    logger.error(error_msg)
                    results["errors"].append(error_msg)
                    results["failed"] += 1

        # Build result message
        message_parts = []
        if results["processed"] > 0:
            message_parts.append(
                f"Successfully processed {results['processed']} targets"
            )
        if results["paused"] > 0:
            message_parts.append(
                f"Paused {results['paused']} targets due to max attempts"
            )
        if results["failed"] > 0:
            message_parts.append(f"Failed to process {results['failed']} targets")
        if results["errors"]:
            message_parts.append(f"Encountered {len(results['errors'])} errors")

        final_message = ". ".join(message_parts)
        self.message_user(request, final_message)

        # Log detailed results
        logger.info(f"Admin force deduction results: {final_message}")

    force_process_deduction.short_description = (
        "Force process deduction for selected targets"
    )

    def mark_as_completed(self, request, queryset):
        completed_count = 0
        for target in queryset:
            if target.is_active and not target.is_cancelled:
                try:
                    # Check if completion record already exists
                    if hasattr(target, "completion_record"):
                        self.message_user(
                            request,
                            f"Target '{target.name}' already has a completion record",
                            level="WARNING",
                        )
                        continue

                    # Create a TargetSavingsCompletion record
                    completed_target = TargetSavingsCompletion.objects.create(
                        user=target.user,
                        target_savings=target,
                        completed_amount=target.current_amount,
                        bonus_amount=(
                            target.calculate_bonus()
                            if hasattr(target, "calculate_bonus")
                            else 0
                        ),
                        total_amount=target.current_amount
                        + (
                            target.calculate_bonus()
                            if hasattr(target, "calculate_bonus")
                            else 0
                        ),
                        completed_date=timezone.now().date(),
                        was_on_time=timezone.now().date() <= target.end_date,
                    )

                    # Deactivate the original target
                    target.is_active = False
                    target.save()
                    completed_count += 1

                    # Send completion notification/email
                    if hasattr(target, "send_completion_email"):
                        target.send_completion_email()

                except Exception as e:
                    self.message_user(
                        request,
                        f"Error completing target {target.name}: {str(e)}",
                        level="ERROR",
                    )

        self.message_user(request, f"Marked {completed_count} targets as completed")

    mark_as_completed.short_description = "Mark selected targets as completed"


@admin.register(TargetSavingsCompletion)
class TargetSavingsCompletionAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "target_name",
        "target_amount",
        "completed_amount",
        "bonus_amount",
        "total_amount",
        "was_on_time",
        "formatted_completed_date",
    ]
    list_filter = ["was_on_time"]
    search_fields = ["user__email", "target_savings__name"]
    readonly_fields = [
        "user",
        "target_savings",
        "completed_amount",
        "bonus_amount",
        "total_amount",
        "completed_date",
        "was_on_time",
        "created_at",
    ]
    list_select_related = ["user", "target_savings"]

    def target_name(self, obj):
        return obj.target_savings.name

    target_name.short_description = "Target Name"

    def target_amount(self, obj):
        return obj.target_savings.target_amount

    target_amount.short_description = "Target Amount"

    def formatted_completed_date(self, obj):
        if obj.completed_date:
            return obj.completed_date.strftime("%b %d, %Y")
        return "-"

    formatted_completed_date.admin_order_field = "completed_date"
    formatted_completed_date.short_description = "Completed Date"

    # Add action to revert completed targets back to active (optional)
    actions = ["revert_to_active"]

    def revert_to_active(self, request, queryset):
        reverted_count = 0
        for completion in queryset:
            try:
                target = completion.target_savings

                # Reactivate the target
                target.is_active = True
                target.save()

                # Delete the completion record
                completion.delete()
                reverted_count += 1

            except Exception as e:
                self.message_user(
                    request,
                    f"Error reverting target {completion.target_savings.name}: {str(e)}",
                    level="ERROR",
                )

        self.message_user(
            request, f"Reverted {reverted_count} targets to active status"
        )

    revert_to_active.short_description = "Revert selected targets to active status"


from django.contrib import admin
from .models import Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("user", "notification_type", "title", "is_read", "created_at")
    list_filter = ("notification_type", "is_read", "created_at")
    search_fields = ("user__email", "title", "message")
    readonly_fields = ("created_at",)
    actions = ["mark_as_read", "mark_as_unread"]

    def mark_as_read(self, request, queryset):
        queryset.update(is_read=True)

    mark_as_read.short_description = "Mark selected notifications as read"

    def mark_as_unread(self, request, queryset):
        queryset.update(is_read=False)

    mark_as_unread.short_description = "Mark selected notifications as unread"


from django import forms
from django.contrib import admin, messages
from .models import PushNotifications, CustomUser
from .utils import send_push_notification


class PushNotificationAdminForm(forms.ModelForm):
    send_to_all = forms.BooleanField(required=False, label="Send to all users")

    class Meta:
        model = PushNotifications
        fields = [
            "user",
            "title",
            "message",
            "notification_type",
            "data",
            "send_to_all",
        ]


@admin.register(PushNotifications)
class PushNotificationsAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "title",
        "notification_type",
        "is_read",
        "created_at",
        "platform",
    ]
    list_filter = ["notification_type", "is_read"]
    search_fields = ["title", "message", "user__email"]
    form = PushNotificationAdminForm

    def get_form(self, request, obj=None, **kwargs):
        form_class = super().get_form(request, obj, **kwargs)

        class AdminFormWithRequest(form_class):
            def __init__(self2, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self2.request = request  # Access to admin request if needed

        return AdminFormWithRequest

    def save_model(self, request, obj, form, change):
        title = form.cleaned_data["title"]
        message = form.cleaned_data["message"]
        notif_type = form.cleaned_data["notification_type"]
        data = form.cleaned_data.get("data") or {}
        send_to_all = form.cleaned_data.get("send_to_all", False)

        if send_to_all:
            users = CustomUser.objects.filter(is_active=True)
        else:
            users = [form.cleaned_data["user"]]

        count_sent = 0
        count_total = 0

        for user in users:
            response = send_push_notification(
                user=user,
                title=title,
                message=message,
                data=data,
                notif_type=notif_type,
            )
            count_total += 1
            if response:
                count_sent += 1

        messages.success(
            request,
            f"✅ Push created for {count_total} user(s), sent successfully to {count_sent}.",
        )

    def platform(self, obj):
        tokens = obj.user.expo_push_tokens or []
        platforms = {t.get("device_type", "Unknown").capitalize() for t in tokens}
        return ", ".join(platforms) if platforms else "Unknown"


# admin.py - Add these admin classes
class DailyROIAccrualAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "date",
        "savings_balance",
        "investment_balance",
        "savings_roi",
        "investment_roi",
        "total_roi",
    ]
    list_filter = ["date"]
    search_fields = ["user__email", "user__first_name", "user__last_name"]
    readonly_fields = [
        "user",
        "date",
        "savings_balance",
        "investment_balance",
        "savings_roi",
        "investment_roi",
        "total_roi",
    ]


class ROITransactionAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "amount",
        "roi_type",
        "accrued_date",
        "payout_date",
        "is_paid_out",
    ]
    list_filter = ["roi_type", "is_paid_out", "accrued_date", "payout_date"]
    search_fields = ["user__email", "user__first_name", "user__last_name"]
    readonly_fields = ["user", "amount", "roi_type", "accrued_date"]


admin.site.register(DailyROIAccrual, DailyROIAccrualAdmin)
admin.site.register(ROITransaction, ROITransactionAdmin)
admin.site.register(Card, CardAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(AutoSave, AutoSaveAdmin)
admin.site.register(AutoInvest, AutoInvestAdmin)
admin.site.register(Property, PropertyAdmin)
