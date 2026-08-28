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
    FinanceMetricSnapshot,
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
from django.contrib import messages
from django.utils.html import format_html
from authentication.tasks import (
    daily_metrics_task,
    weekly_metrics_task,
    monthly_metrics_task,
)

from .utils import (
    send_push_notification,
    send_generic_email,
    clear_local_dva_fields,
    sync_user_dva_from_paystack,
    deactivate_user_dva,
    recreate_user_dva,
    requery_dedicated_account,
    approve_quicksave_credit,
    approve_quickinvest_credit,
    send_ambassador_status_notification,
    grant_user_ambassador_status,
    revoke_user_ambassador_status,
    create_transaction,
)
from decimal import Decimal
from django.utils.html import format_html

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
        "balance_before",
        "balance_after",
        "date",
        "time",
        "description",
        "transaction_id",
    )
    readonly_fields = (
        "transaction_id",
        "date",
        "time",
        "balance_before",
        "balance_after",
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
from django.db.models import OuterRef, Subquery, Count, IntegerField
from django.db.models.functions import Coalesce


class CustomUserAdmin(UserAdmin):
    list_display = (
        "id",
        "email",
        "first_name",
        "last_name",
        "get_due_targets",
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
        "kyc_status",
        "is_staff",
        "is_active",
        "is_banned",  # 👈 show banned status
        "profile_picture",
        "pending_roi",
        "dva_status_display",
        "dva_account_number_display",
        "dva_bank_display",
        "paystack_customer_code_display",
    )
    list_filter = (
        "is_staff",
        "is_active",
        "is_banned",  # 👈 show banned status
        "kyc_updated",
        "kyc_status",
        "how_did_you_hear",
        "date_joined",
        "is_hired_referrer",
        "is_ambassador",
        "paystack_identified",
        "paystack_identification_status",
    )
    readonly_fields = (
        "get_total_referrals",
        "get_confirmed_referrals",
        "date_joined",
        "dva_status_display",
        "dva_account_number_display",
        "dva_bank_display",
        "paystack_customer_code_display",
    )

    actions = [
        "ban_user",
        "unban_user",
        "export_kyc_data",  # NEW: KYC-only export
        "export_to_csv",  # Add export action
        "send_custom_email",
        "view_kyc_details",
        "approve_kyc",
        "reject_kyc",
        "make_hired_referrer",
        "make_ambassador",
        "revoke_ambassador",
        "delete_selected",
        "deactivate_user",
        "notify_outdated_users",
        "say_hello",
        "simulate_quarterly_payout",
        "test_daily_roi_calculation",  # ← Add this
        "test_quarterly_payout",  # ← Add this
        "view_roi_summary",  # ← Add this
        "test_top_saver_reward",
        "sync_selected_dvas_from_paystack",
        "requery_selected_dvas",
        "deactivate_selected_dvas",
        "clear_selected_local_dvas",
        "recreate_selected_dvas",
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
                    "kyc_status",
                    "kyc_rejection_reason",
                ),
            },
        ),
        (
            "DVA / Paystack",
            {
                "fields": (
                    "paystack_customer_code",
                    "paystack_identified",
                    "paystack_identification_status",
                    "paystack_identification_reason",
                    "dva_status_display",
                    "dva_account_number_display",
                    "dva_bank_display",
                    "paystack_customer_code_display",
                    "dva_account_number",
                    "dva_account_name",
                    "dva_bank_name",
                    "dva_account_id",
                    "dva_assigned_at",
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
    search_fields = (
        "email",
        "first_name",
        "last_name",
        "how_did_you_hear",
        "kyc_status",
    )
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

    def get_due_targets(self, obj):
        from django.utils import timezone
        from authentication.models import TargetSavings

        return TargetSavings.objects.filter(
            user=obj,
            is_active=True,
            is_cancelled=False,
            next_deduction__lte=timezone.now(),
        ).count()

    get_due_targets.short_description = "Due Targets"

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

    # DVA
    def dva_status_display(self, obj):
        if obj.dva_account_number and obj.dva_account_id:
            return format_html(
                '<span style="color: green; font-weight: 600;">Assigned</span>'
            )

        if obj.paystack_identification_status == "processing":
            return format_html(
                '<span style="color: orange; font-weight: 600;">Processing</span>'
            )

        if obj.paystack_identification_reason == "NAME_MISMATCH":
            return format_html(
                '<span style="color: red; font-weight: 600;">Name Mismatch</span>'
            )

        if obj.paystack_identification_status == "failed":
            return format_html(
                '<span style="color: red; font-weight: 600;">Failed</span>'
            )

        return format_html('<span style="color: grey; font-weight: 600;">No DVA</span>')

    dva_status_display.short_description = "DVA Status"

    def dva_account_number_display(self, obj):
        return obj.dva_account_number or "—"

    dva_account_number_display.short_description = "DVA Number"

    def dva_bank_display(self, obj):
        return obj.dva_bank_name or "—"

    dva_bank_display.short_description = "DVA Bank"

    def paystack_customer_code_display(self, obj):
        return obj.paystack_customer_code or "—"

    paystack_customer_code_display.short_description = "Paystack Customer"

    @admin.action(description="🔄 Sync selected users' DVAs from Paystack")
    def sync_selected_dvas_from_paystack(self, request, queryset):
        success_count = 0
        failed_count = 0

        for user in queryset:
            ok, result = sync_user_dva_from_paystack(user)
            if ok:
                success_count += 1
            else:
                failed_count += 1
                self.message_user(
                    request,
                    f"Sync failed for {user.email}: {result.get('message')}",
                    level=messages.ERROR,
                )

        if success_count:
            self.message_user(
                request,
                f"{success_count} user(s) DVA synced successfully from Paystack.",
                level=messages.SUCCESS,
            )

        if failed_count and not success_count:
            self.message_user(
                request,
                "No DVA sync completed successfully.",
                level=messages.WARNING,
            )

    @admin.action(description="📡 Requery selected users' DVAs for incoming transfers")
    def requery_selected_dvas(self, request, queryset):
        success_count = 0
        failed_count = 0

        for user in queryset:
            ok, result = requery_dedicated_account(user)
            if ok:
                success_count += 1
            else:
                failed_count += 1
                self.message_user(
                    request,
                    f"Requery failed for {user.email}: {result.get('message')}",
                    level=messages.ERROR,
                )

        if success_count:
            self.message_user(
                request,
                f"Requery triggered successfully for {success_count} user(s).",
                level=messages.SUCCESS,
            )

        if failed_count and not success_count:
            self.message_user(
                request,
                "No DVA requery completed successfully.",
                level=messages.WARNING,
            )

    @admin.action(
        description="🛑 Deactivate selected users' DVAs on Paystack and clear local DVA"
    )
    def deactivate_selected_dvas(self, request, queryset):
        success_count = 0
        failed_count = 0

        for user in queryset:
            ok, result = deactivate_user_dva(user, clear_local=True)
            if ok:
                success_count += 1
            else:
                failed_count += 1
                self.message_user(
                    request,
                    f"Deactivate failed for {user.email}: {result.get('message')}",
                    level=messages.ERROR,
                )

        if success_count:
            self.message_user(
                request,
                f"{success_count} DVA(s) deactivated on Paystack and cleared locally.",
                level=messages.SUCCESS,
            )

        if failed_count and not success_count:
            self.message_user(
                request,
                "No DVA deactivation completed successfully.",
                level=messages.WARNING,
            )

    @admin.action(description="🧹 Clear selected users' local DVA fields only")
    def clear_selected_local_dvas(self, request, queryset):
        count = 0

        for user in queryset:
            clear_local_dva_fields(user, save=True)
            count += 1

        self.message_user(
            request,
            f"Cleared local DVA fields for {count} user(s).",
            level=messages.SUCCESS,
        )

    @admin.action(description="🏦 Recreate selected users' DVAs")
    def recreate_selected_dvas(self, request, queryset):
        success_count = 0
        failed_count = 0

        for user in queryset:
            ok, result = recreate_user_dva(user, preferred_bank="wema-bank")
            if ok:
                success_count += 1
            else:
                failed_count += 1
                self.message_user(
                    request,
                    f"Recreate failed for {user.email}: {result.get('message')}",
                    level=messages.ERROR,
                )

        if success_count:
            self.message_user(
                request,
                f"Recreated DVA successfully for {success_count} user(s).",
                level=messages.SUCCESS,
            )

        if failed_count and not success_count:
            self.message_user(
                request,
                "No DVA recreation completed successfully.",
                level=messages.WARNING,
            )

    def save_model(self, request, obj, form, change):
        previous_is_ambassador = None

        if change and obj.pk:
            previous_is_ambassador = (
                CustomUser.objects.filter(pk=obj.pk)
                .values_list("is_ambassador", flat=True)
                .first()
            )

        super().save_model(request, obj, form, change)

        if change and previous_is_ambassador is not None:
            if previous_is_ambassador != obj.is_ambassador:
                send_ambassador_status_notification(
                    user=obj,
                    became_ambassador=obj.is_ambassador,
                )

    @admin.action(description="🌟 Make selected users ambassadors")
    def make_ambassador(self, request, queryset):
        updated_count = 0

        for user in queryset:
            if grant_user_ambassador_status(user):
                updated_count += 1

        self.message_user(
            request,
            f"{updated_count} user(s) updated to ambassador and notified.",
            level=messages.SUCCESS,
        )

    @admin.action(description="❌ Revoke ambassador status")
    def revoke_ambassador(self, request, queryset):
        updated_count = 0

        for user in queryset:
            if revoke_user_ambassador_status(user):
                updated_count += 1

        self.message_user(
            request,
            f"{updated_count} user(s) ambassador status revoked and notified.",
            level=messages.SUCCESS,
        )

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

    @admin.action(description="Export selected users to CSV")
    def export_to_csv(self, request, queryset):
        # Create the response object and set the content type
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = (
            'attachment; filename="users_with_full_kyc.csv"'
        )

        # Create the CSV writer with UTF-8 encoding for special characters
        writer = csv.writer(response)

        # Write comprehensive header with ALL KYC fields
        writer.writerow(
            [
                "ID",
                "Email",
                "First Name",
                "Last Name",
                "Phone Number",
                "Date Joined",
                "KYC Status",
                "KYC Updated",
                # Personal Information
                "Gender",
                "Date of Birth",
                "Address",
                "State of Residence",
                "Country of Residence",
                # Employment & Financial
                "Employment Status",
                "Yearly Income",
                # Identification
                "Identification Type",
                "ID Upload URL",
                # Family Information
                "Mother's Maiden Name",
                "Relationship Status",
                # Next of Kin Information
                "Next of Kin Name",
                "Relationship with Next of Kin",
                "Next of Kin Phone Number",
                # Referral Source
                "How Did You Hear",  # ADDED - Shows user acquisition source
                # Account Information
                "Is Hired Referrer",
                "Is Ambassador",
                # Account Balances
                "Savings",
                "Investment",
                "Properties",
                "Wallet",
                "Total Savings and Investments",
                "Total Savings and Investments This Month",
                # Account Status
                "Is Staff",
                "Is Active",
                "Is Banned",
                "Profile Picture URL",
            ]
        )

        # Write user data rows
        for user in queryset:
            # Format date of birth if it exists
            dob = ""
            if user.date_of_birth and user.date_of_birth.year > 1900:
                dob = user.date_of_birth.strftime("%Y-%m-%d")

            # Format date joined
            date_joined = (
                user.date_joined.strftime("%Y-%m-%d %H:%M:%S")
                if user.date_joined
                else ""
            )

            # Get profile picture URL
            # Get profile picture URL safely
            profile_pic_url = ""
            if user.profile_picture:
                if hasattr(user.profile_picture, "url"):
                    profile_pic_url = user.profile_picture.url
                else:
                    profile_pic_url = str(user.profile_picture)

            # Get ID upload URL safely
            id_upload_url = ""
            if user.id_upload:
                if hasattr(user.id_upload, "url"):
                    id_upload_url = user.id_upload.url
                else:
                    id_upload_url = str(user.id_upload)

            # Format "How Did You Hear" for better readability
            how_did_you_hear_display = dict(
                user._meta.get_field("how_did_you_hear").choices
            ).get(user.how_did_you_hear, user.how_did_you_hear)

            writer.writerow(
                [
                    # Basic Info
                    user.id,
                    user.email,
                    user.first_name,
                    user.last_name,
                    user.phone_number,
                    date_joined,
                    user.kyc_status,
                    "Yes" if user.kyc_updated else "No",
                    # Personal Information
                    user.gender if user.gender != "Choose" else "",
                    dob,
                    user.address if user.address != "Enter Address" else "",
                    user.state if user.state != "Choose" else "",
                    user.country if user.country != "Nigeria" else "",
                    # Employment & Financial
                    (
                        user.employment_status
                        if user.employment_status != "Choose"
                        else ""
                    ),
                    user.yearly_income if user.yearly_income != "Choose" else "",
                    # Identification
                    (
                        user.identification_type
                        if user.identification_type != "Choose"
                        else ""
                    ),
                    request.build_absolute_uri(id_upload_url) if id_upload_url else "",
                    # Family Information
                    (
                        user.mothers_maiden_name
                        if user.mothers_maiden_name != "Enter Name"
                        else ""
                    ),
                    (
                        user.relationship_status
                        if user.relationship_status != "Choose"
                        else ""
                    ),
                    # Next of Kin Information
                    (
                        user.next_of_kin_name
                        if user.next_of_kin_name != "Enter Name"
                        else ""
                    ),
                    (
                        user.relationship_with_next_of_kin
                        if user.relationship_with_next_of_kin != "Choose"
                        else ""
                    ),
                    (
                        user.next_of_kin_phone_number
                        if user.next_of_kin_phone_number != "Enter Number"
                        else ""
                    ),
                    # Referral Source - ADDED
                    how_did_you_hear_display,  # Shows the full readable value
                    # Account Information
                    "Yes" if user.is_hired_referrer else "No",
                    "Yes" if user.is_ambassador else "No",
                    # Account Balances
                    str(user.savings),
                    str(user.investment),
                    str(user.properties),
                    str(user.wallet),
                    str(user.savings + user.investment),
                    str(getattr(user, "total_savings_and_investments_this_month", 0)),
                    # Account Status
                    "Yes" if user.is_staff else "No",
                    "Yes" if user.is_active else "No",
                    "Yes" if user.is_banned else "No",
                    (
                        request.build_absolute_uri(profile_pic_url)
                        if profile_pic_url
                        else ""
                    ),
                ]
            )

        return response

    export_to_csv.short_description = "Export selected users to CSV"

    @admin.action(description="Export KYC data only")
    def export_kyc_data(self, request, queryset):
        """Export only KYC-related fields for compliance reporting"""
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = (
            'attachment; filename="kyc_compliance_data.csv"'
        )

        writer = csv.writer(response)

        # KYC-specific headers
        writer.writerow(
            [
                "ID",
                "Email",
                "First Name",
                "Last Name",
                "Phone Number",
                "KYC Status",
                "KYC Submission Date",
                "Gender",
                "Date of Birth",
                "Address",
                "State",
                "Country",
                "Employment Status",
                "Yearly Income",
                "Identification Type",
                "ID Uploaded",
                "Mother's Maiden Name",
                "Relationship Status",
                "Next of Kin Name",
                "Next of Kin Relationship",
                "Next of Kin Phone",
            ]
        )

        for user in queryset:
            # Format dates
            dob = ""
            if user.date_of_birth and user.date_of_birth.year > 1900:
                dob = user.date_of_birth.strftime("%Y-%m-%d")

            # Find when KYC was last updated
            kyc_date = ""
            if user.kyc_status and user.kyc_status != "Not yet started":
                # Try to get from user's update time or use date_joined
                kyc_date = user.date_joined.strftime("%Y-%m-%d")

            writer.writerow(
                [
                    user.id,
                    user.email,
                    user.first_name,
                    user.last_name,
                    user.phone_number,
                    user.kyc_status,
                    kyc_date,
                    user.gender,
                    dob,
                    user.address,
                    user.state,
                    user.country,
                    user.employment_status,
                    user.yearly_income,
                    user.identification_type,
                    (
                        "Yes"
                        if user.id_upload
                        and not user.id_upload.name.endswith("placeholder.png")
                        else "No"
                    ),
                    user.mothers_maiden_name,
                    user.relationship_status,
                    user.next_of_kin_name,
                    user.relationship_with_next_of_kin,
                    user.next_of_kin_phone_number,
                ]
            )

        self.message_user(request, f"Exported KYC data for {queryset.count()} users.")
        return response

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
                            transaction_type="credit",
                            status="confirmed",
                            source="WALLET",
                            credited_to="WALLET",
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

    # ---------------------------------------------------
    # CENTRALIZED KYC TRANSITION HANDLER (SINGLE SOURCE)
    # ---------------------------------------------------
    def process_kyc_transition(self, user, new_status):
        """
        Handles KYC approval or rejection logic from both
        admin actions and manual save operations.
        """

        DEFAULT_REJECTION_REASON = (
            "We were unable to verify the information provided. "
            "Please review your details and re-upload clear and valid documents."
        )

        if new_status == "approved":
            CustomUser.objects.filter(pk=user.pk).update(
                kyc_status="approved",
                kyc_updated=True,
                kyc_rejection_reason=None,
                kyc_reviewed_at=timezone.now(),
            )

            # EMAIL (NON-BLOCKING)
            try:
                send_generic_email(
                    subject="🎉 Your KYC Has Been Approved",
                    message=f"""Hi {user.first_name},

                Great news! Your KYC verification has been successfully approved.

                You now have full access to all MyFund features.

                Keep growing your funds 🚀

                MyFund Team
                """,
                    recipient_list=[user.email],
                )
            except Exception as e:
                print(f"[KYC APPROVAL EMAIL FAILED] {user.email}: {e}")

            # PUSH (NON-BLOCKING)
            try:
                send_push_notification(
                    user=user,
                    title="KYC Approved ✅",
                    message="Your KYC has been approved. You now have full access. Enjoy!",
                    data={"kyc_status": "approved"},
                    notif_type="ACCOUNT",
                )
            except Exception as e:
                print(f"[KYC APPROVAL PUSH FAILED] {user.email}: {e}")

        elif new_status == "rejected":
            rejection_reason = (
                user.kyc_rejection_reason.strip()
                if user.kyc_rejection_reason
                else DEFAULT_REJECTION_REASON
            )

            CustomUser.objects.filter(pk=user.pk).update(
                kyc_status="rejected",
                kyc_updated=False,
                kyc_rejection_reason=rejection_reason,
                kyc_reviewed_at=timezone.now(),
            )

            # EMAIL (NON-BLOCKING)
            try:
                send_generic_email(
                    subject="KYC Verification Update – Action Required",
                    message=f"""Hi {user.first_name},

                We’ve reviewed your KYC submission and unfortunately couldn’t approve it.

                Reason:
                {rejection_reason}

                Please log into your MyFund account, correct the issue, and re-submit your KYC.

                MyFund Team
                www.myfundmobile.com
                """,
                    recipient_list=[user.email],
                )
            except Exception as e:
                print(f"[KYC REJECTION EMAIL FAILED] {user.email}: {e}")

            # PUSH (NON-BLOCKING)
            try:
                send_push_notification(
                    user=user,
                    title="KYC Needs Attention ❌",
                    message="Your KYC was rejected. Please review and re-upload.",
                    data={
                        "kyc_status": "rejected",
                        "kyc_rejection_reason": rejection_reason,
                    },
                    notif_type="ACCOUNT",
                )
            except Exception as e:
                print(f"[KYC REJECTION PUSH FAILED] {user.email}: {e}")

    # ---------------------------------------------------
    # ADMIN SAVE (MANUAL APPROVE / REJECT VIA SAVE BUTTON)
    # ---------------------------------------------------
    def save_model(self, request, obj, form, change):
        previous = None

        if obj.pk:
            previous = CustomUser.objects.filter(pk=obj.pk).first()

        super().save_model(request, obj, form, change)

        # No previous record (new user) → nothing to compare
        if not previous:
            return

        # Only react to meaningful KYC transitions
        if previous.kyc_status == "submitted" and obj.kyc_status in [
            "approved",
            "rejected",
        ]:
            self.process_kyc_transition(obj, obj.kyc_status)

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


def get_transfer_status_badge(obj):
    transaction = Transaction.objects.filter(
        user=obj.user, transaction_id=obj.transaction_id
    ).first()

    # 🟢 Approved (deeper green)
    if obj.is_approved:
        return format_html(
            '<span style="padding:4px 10px; border-radius:10px; background:#166534; color:#ffffff; font-size:11px; font-weight:600;">'
            "✅</span>"
        )

    # ⚫ Cleaned Up (deeper grey)
    if transaction and transaction.status.lower() == "abandoned":
        return format_html(
            '<span style="padding:4px 10px; border-radius:10px; background:#374151; color:#ffffff; font-size:11px; font-weight:600;">'
            "🧹</span>"
        )

    # 🟠 Pending (deeper orange)
    return format_html(
        '<span style="padding:4px 10px; border-radius:10px; background:#c2410c; color:#ffffff; font-size:11px; font-weight:600;">'
        "⏳</span>"
    )


@admin.register(BankTransferRequest)
class BankTransferRequestAdmin(admin.ModelAdmin):
    list_display = (
        "user_full_name",
        "status_badge",
        "amount",
        "user_email",
        "created_at",
    )

    list_filter = ("is_approved",)
    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "transaction_id",
    )

    actions = ["approve_bank_transfer", "mark_as_abandoned"]

    # ─────────────────────────────────────────────
    # DISPLAY HELPERS
    # ─────────────────────────────────────────────

    def user_email(self, obj):
        return obj.user.email

    user_email.short_description = "Email"

    def user_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"

    user_full_name.short_description = "Full Name"

    def status_badge(self, obj):
        return get_transfer_status_badge(obj)

    status_badge.short_description = "Status"

    # ─────────────────────────────────────────────
    # ACTIONS
    # ─────────────────────────────────────────────

    def approve_bank_transfer(self, request, queryset):
        for transfer_request in queryset:
            user = transfer_request.user

            ok, msg = approve_quicksave_credit(
                user=user,
                amount=transfer_request.amount,
                transaction_id=transfer_request.transaction_id,
                description="QuickSave (Transfer)",
                source="BANK_TRANSFER",
            )

            if not ok:
                self.message_user(request, f"{msg} for {user.email}", level="error")
                continue

            transfer_request.is_approved = True
            transfer_request.save(update_fields=["is_approved"])

        self.message_user(
            request,
            "Selected bank transfers approved successfully!",
            level="success",
        )

    @admin.action(description="🧹 Mark selected pending transfers as abandoned")
    def mark_as_abandoned(self, request, queryset):
        cleaned_count = 0

        for transfer_request in queryset.filter(is_approved=False):
            transaction = Transaction.objects.filter(
                user=transfer_request.user,
                transaction_id=transfer_request.transaction_id,
                status__iexact="pending",
            ).first()

            if transaction:
                transaction.status = "abandoned"
                transaction.description = "QuickSave (Abandoned)"
                transaction.save(update_fields=["status", "description"])
                cleaned_count += 1

        self.message_user(
            request,
            f"{cleaned_count} abandoned QuickSave transfer(s) cleaned up.",
            level=messages.SUCCESS,
        )

    approve_bank_transfer.short_description = "Approve selected bank transfers"


@admin.register(InvestTransferRequest)
class InvestTransferRequestAdmin(admin.ModelAdmin):
    list_display = (
        "user_full_name",
        "status_badge",
        "amount",
        "user_email",
        "created_at",
    )

    list_filter = ("is_approved",)
    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "transaction_id",
    )

    actions = ["approve_invest_transfer", "mark_as_abandoned"]

    # ─────────────────────────────────────────────
    # DISPLAY HELPERS
    # ─────────────────────────────────────────────

    def user_email(self, obj):
        return obj.user.email

    user_email.short_description = "Email"

    def user_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"

    user_full_name.short_description = "Full Name"

    def status_badge(self, obj):
        return get_transfer_status_badge(obj)

    status_badge.short_description = "Status"

    # ─────────────────────────────────────────────
    # ACTIONS
    # ─────────────────────────────────────────────

    def approve_invest_transfer(self, request, queryset):
        for transfer_request in queryset:
            user = transfer_request.user

            ok, msg = approve_quickinvest_credit(
                user=user,
                amount=transfer_request.amount,
                transaction_id=transfer_request.transaction_id,
                description="QuickInvest (Transfer)",
                source="BANK_TRANSFER",
            )

            if not ok:
                self.message_user(request, f"{msg} for {user.email}", level="error")
                continue

            transfer_request.is_approved = True
            transfer_request.save(update_fields=["is_approved"])

        self.message_user(
            request,
            "Selected investment transfers approved successfully!",
            level="success",
        )

    @admin.action(
        description="🧹 Mark selected pending QuickInvest transfers as abandoned"
    )
    def mark_as_abandoned(self, request, queryset):
        cleaned_count = 0

        for transfer_request in queryset.filter(is_approved=False):
            transaction = Transaction.objects.filter(
                user=transfer_request.user,
                transaction_id=transfer_request.transaction_id,
                status__iexact="pending",
            ).first()

            if transaction:
                transaction.status = "abandoned"
                transaction.description = "QuickInvest (Abandoned)"
                transaction.save(update_fields=["status", "description"])
                cleaned_count += 1

        self.message_user(
            request,
            f"{cleaned_count} abandoned QuickInvest transfer(s) cleaned up.",
            level=messages.SUCCESS,
        )

    approve_invest_transfer.short_description = "Approve selected investment transfers"


from django.contrib import admin, messages
from django.db import transaction as db_transaction
from django.utils import timezone

from .models import WithdrawalsRequestToAdmin, Transaction, BankAccount
from .utils import (
    process_scheduled_withdrawal,
    send_push_notification,
    send_generic_email,
)


class OverdueScheduledWithdrawalFilter(admin.SimpleListFilter):
    title = "scheduled withdrawal status"
    parameter_name = "scheduled_withdrawal_status"

    def lookups(self, request, model_admin):
        return (
            ("overdue", "Overdue scheduled withdrawals"),
            ("due_today", "Due today"),
            ("processed", "Processed scheduled withdrawals"),
        )

    def queryset(self, request, queryset):
        today = timezone.localdate()

        if self.value() == "overdue":
            return queryset.filter(
                withdrawal_type="scheduled",
                scheduled_processing_date__lt=today,
                is_processed=False,
            )

        if self.value() == "due_today":
            return queryset.filter(
                withdrawal_type="scheduled",
                scheduled_processing_date=today,
                is_processed=False,
            )

        if self.value() == "processed":
            return queryset.filter(
                withdrawal_type="scheduled",
                is_processed=True,
            )

        return queryset


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
        "target_bank_display",
        "target_account_number",
        "target_account_name_display",
        "created_at",
        "scheduled_processing_date",
        "transaction_id",
        "status",  # ✅ ADDED status to display
    )

    list_filter = (
        OverdueScheduledWithdrawalFilter,
        "is_approved",
        "is_processed",
        "source_account",
        "withdrawal_type",
        "status",
        "scheduled_processing_date",
    )

    search_fields = (
        "user__email",
        "transaction_id",
        "target_bank",
        "source_account",
        "target_account_number",
    )

    actions = ["approve_withdrawal", "force_credit_wallet"]

    # =========================
    # DISPLAY HELPERS (READ-ONLY)
    # =========================

    def target_bank_display(self, obj):
        if getattr(obj, "target_bank", None):
            return obj.target_bank

        bank = BankAccount.objects.filter(
            user=obj.user,
            account_number=obj.target_account_number,
        ).first()

        if bank:
            return bank.bank_name

        return "-"

    target_bank_display.short_description = "Target Bank"

    def target_account_name_display(self, obj):
        if getattr(obj, "target_account_name", None):
            return obj.target_account_name

        bank = BankAccount.objects.filter(
            user=obj.user,
            account_number=obj.target_account_number,
        ).first()

        if bank:
            return bank.account_name

        return "-"

    target_account_name_display.short_description = "Target Account Name"

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
    # ADMIN ACTIONS
    # =========================

    def approve_withdrawal(self, request, queryset):
        approved_count = 0
        skipped_scheduled = 0

        for withdrawal in queryset:
            if withdrawal.is_approved:
                continue

            # 🔴 This action is for immediate bank-payout withdrawals only -
            # it flips is_processed=True and never touches user.wallet,
            # since for an immediate withdrawal the money already left
            # savings/investment for the bank at request time. Scheduled
            # withdrawals instead need process_scheduled_withdrawal() (via
            # "Force credit wallet" below) to actually pay out - running
            # this action on one instead permanently stranded the money:
            # marked "completed" with is_processed=True (which blocks the
            # real crediting task/action from ever picking it up again),
            # but nothing ever landed in the user's wallet.
            if withdrawal.withdrawal_type == "scheduled":
                skipped_scheduled += 1
                continue

            user = withdrawal.user
            transaction_id = withdrawal.transaction_id

            try:
                with db_transaction.atomic():
                    withdrawal.is_approved = True
                    withdrawal.is_processed = True
                    withdrawal.withdrawal_type = "immediate"
                    withdrawal.scheduled_processing_date = None
                    withdrawal.status = "completed"

                    withdrawal.save(
                        update_fields=[
                            "is_approved",
                            "is_processed",
                            "withdrawal_type",
                            "scheduled_processing_date",
                            "status",
                        ]
                    )

                    transaction = Transaction.objects.get(
                        user=user, transaction_id=transaction_id
                    )

                    # Capture balance snapshot at approval time
                    source = (
                        withdrawal.source_account.lower()
                    )  # "savings", "investment", "wallet"
                    if source == "savings":
                        balance_before = (
                            user.savings + withdrawal.total_amount
                        )  # already debited when scheduled
                        balance_after = user.savings
                    elif source == "investment":
                        balance_before = user.investment + withdrawal.total_amount
                        balance_after = user.investment
                    else:
                        balance_before = user.wallet + withdrawal.total_amount
                        balance_after = user.wallet

                    transaction.status = "confirmed"
                    destination = "Bank"
                    source_display = withdrawal.source_account.capitalize()

                    transaction.description = f"{source_display} > {destination}"
                    transaction.balance_before = balance_before
                    transaction.balance_after = balance_after
                    transaction.save()

                    # Same refresh every deposit-completion path already
                    # triggers - without it, an approved immediate
                    # withdrawal debits savings/investment but the
                    # ambassador report's cached monthly figure never
                    # reflects it until the user's next deposit.
                    user.update_total_savings_and_investment_this_month()

                    approved_count += 1

                    # Push notification
                    send_push_notification(
                        user=user,
                        title="Withdrawal Successful! ✅",
                        message=(
                            f"{user.first_name}, your withdrawal of ₦{withdrawal.amount:,.2f} "
                            f"to your {withdrawal.target_bank} account has been processed successfully."
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
                    try:
                        send_generic_email(
                            subject="Withdrawal Successful ✔",
                            message=(
                                f"Hi {user.first_name},<br><br>"
                                f"Your withdrawal of ₦{withdrawal.amount:,.2f} from your "
                                f"{withdrawal.source_account.capitalize()} account "
                                f"has been processed successfully.<br><br>"
                                f"Transaction ID: {transaction_id}<br><br>"
                                f"MyFund Team"
                            ),
                            from_email="MyFund <info@myfundmobile.com>",
                            recipient_list=[user.email],
                        )
                    except Exception as email_error:
                        print(
                            f"Withdrawal approval email failed for {user.email}: {email_error}"
                        )

            except Exception as e:
                self.message_user(
                    request,
                    f"Error approving {transaction_id}: {str(e)}",
                    level="error",
                )

        if skipped_scheduled:
            self.message_user(
                request,
                f"Skipped {skipped_scheduled} scheduled withdrawal(s) - use "
                f"'Force credit wallet' for those instead, this action is "
                f"for immediate bank-payout withdrawals only.",
                level="warning",
            )

        if approved_count:
            self.message_user(
                request, f"{approved_count} withdrawal(s) approved successfully."
            )
        elif not skipped_scheduled:
            self.message_user(request, "No withdrawals were approved.")

    def force_credit_wallet(self, request, queryset):
        today = timezone.localdate()

        eligible_withdrawals = queryset.filter(
            withdrawal_type="scheduled",
            scheduled_processing_date__lte=today,
            is_processed=False,
        )

        processed_count = 0
        skipped_count = queryset.count() - eligible_withdrawals.count()
        failed_count = 0

        for withdrawal in eligible_withdrawals:
            try:
                result = process_scheduled_withdrawal(
                    withdrawal,
                    triggered_by=f"admin:{request.user}",
                )

                if result in ["processed", "already_credited", "already_processed"]:
                    processed_count += 1

            except Exception as e:
                failed_count += 1
                self.message_user(
                    request,
                    f"Failed to force credit {withdrawal.transaction_id}: {str(e)}",
                    level=messages.ERROR,
                )

        self.message_user(
            request,
            (
                f"Force credit completed. "
                f"Processed: {processed_count}. "
                f"Skipped: {skipped_count}. "
                f"Failed: {failed_count}."
            ),
            level=messages.SUCCESS if failed_count == 0 else messages.WARNING,
        )


class BankAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "bank_name",
        "account_number",
        "account_name",
        "bank_code",
        "paystack_recipient_code",
        "is_default",
    )
    list_filter = ("is_default", "bank_name")
    search_fields = (
        "user__email",
        "bank_name",
        "account_number",
        "account_name",
        "paystack_recipient_code",
    )


admin.site.register(BankAccount, BankAccountAdmin)


class CardAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "bank_name",
        "is_default",
    )
    list_filter = ("is_default",)
    search_fields = (
        "user__email",
        "bank_name",
        "card_last4_digits",
        "card_brand",
        "authorization_code",
    )


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


from django.contrib import admin
from django.utils import timezone
from .models import Transaction
from .utils import send_generic_email, send_push_notification


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
    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "description",
        "transaction_id",
        "referral_email",
    )

    actions = ["force_confirm_transactions"]

    # --- 1. THE DROPDOWN ACTION ---
    @admin.action(description="Force Confirm Selected Pending Transactions")
    def force_confirm_transactions(self, request, queryset):
        confirmed_count = 0

        for txn in queryset.filter(status="pending"):
            try:
                ok, msg = self._confirm_transaction_logic(txn)
                if ok:
                    confirmed_count += 1
            except Exception as e:
                self.message_user(
                    request,
                    f"Error confirming {txn.transaction_id}: {str(e)}",
                    level=messages.ERROR,
                )

        if confirmed_count:
            self.message_user(
                request,
                f"Successfully confirmed {confirmed_count} transaction(s), updated balances, and sent notifications.",
                level=messages.SUCCESS,
            )
        else:
            self.message_user(
                request,
                "No pending transactions were confirmed.",
                level=messages.WARNING,
            )

    # --- 2. THE MANUAL SAVE LOGIC ---
    def save_model(self, request, obj, form, change):
        # If an existing transaction is changed to 'confirmed' manually in the edit form
        if change and "status" in form.changed_data and obj.status == "confirmed":
            self._confirm_transaction_logic(obj)
        else:
            super().save_model(request, obj, form, change)

    # --- 3. THE CENTRAL BRAIN (Handles Balances, Referrals, and Notifications) ---
    def _confirm_transaction_logic(self, txn):
        """Safely confirms an existing pending transaction and credits the right balance."""
        from django.db import transaction as db_transaction

        with db_transaction.atomic():
            txn = (
                Transaction.objects.select_for_update()
                .select_related("user")
                .get(id=txn.id)
            )
            user = CustomUser.objects.select_for_update().get(id=txn.user_id)

            if txn.status == "confirmed":
                return False, "Already confirmed"

            amount = txn.amount or Decimal("0.00")
            description = txn.description or ""

            credited_to = str(txn.credited_to).upper()

            if credited_to == "WALLET":
                balance_before = user.wallet
                user.wallet += amount
                balance_after = user.wallet
                txn.credited_to = "WALLET"
                folder_name = "Wallet"

            elif credited_to == "INVESTMENT":
                balance_before = user.investment
                user.investment += amount
                balance_after = user.investment
                txn.credited_to = "INVESTMENT"
                folder_name = "Investment"

            else:
                balance_before = user.savings
                user.savings += amount
                balance_after = user.savings
                txn.credited_to = "SAVINGS"
                folder_name = "Savings"

            user.save(update_fields=["savings", "investment", "wallet"])

            txn.transaction_type = "credit"
            txn.status = "confirmed"
            txn.source = txn.source or "BANK_TRANSFER"
            txn.total_amount = amount
            txn.balance_before = balance_before
            txn.balance_after = balance_after
            txn.date = timezone.now().date()
            txn.save(
                update_fields=[
                    "transaction_type",
                    "status",
                    "source",
                    "credited_to",
                    "total_amount",
                    "balance_before",
                    "balance_after",
                    "date",
                ]
            )

        try:
            if hasattr(user, "confirm_referral_rewards"):
                user.refresh_from_db()
                user.confirm_referral_rewards(is_referrer=False)
        except Exception as e:
            print(f"Referral confirmation failed: {e}")

        try:
            send_generic_email(
                subject=f"{folder_name} Updated! ✅",
                message=(
                    f"Hi {user.first_name},<br><br>"
                    f"Your transfer of ₦{amount:,.2f} has been processed successfully "
                    f"and added to your {folder_name} account.<br><br>"
                    f"Keep growing your funds!<br><br>"
                    f"MyFund Team"
                ),
                recipient_list=[user.email],
            )
        except Exception as e:
            print(f"Force confirm email failed: {e}")

        try:
            send_push_notification(
                user=user,
                title=f"{folder_name} Updated! ✅",
                message=f"Hi {user.first_name}, your transfer of ₦{amount:,.0f} has been added to your {folder_name} account.",
                data={
                    "amount": str(amount),
                    "transaction_id": txn.transaction_id,
                    "type": folder_name,
                    "status": "confirmed",
                },
                notif_type="CREDIT",
            )
        except Exception as e:
            print(f"Force confirm push failed: {e}")

        return True, "Confirmed"

    def is_referral_transaction(self, obj):
        return bool(obj.referral_email)

    is_referral_transaction.boolean = True
    is_referral_transaction.short_description = "Is Referral?"


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
        "is_due",  # 👈 NEW
        "is_active",
        "is_cancelled",
        "formatted_next_deduction",
        "formatted_last_processed",
    ]

    list_filter = [
        "is_active",
        "is_cancelled",
        "frequency",
        "category",
        "due_status",  # 👈 NEW FILTER
    ]

    search_fields = ["user__email", "name"]

    readonly_fields = ["current_amount", "progress_percentage", "last_processed"]

    actions = ["force_process_deduction", "mark_as_completed"]

    # -----------------------------
    # 🔥 NEW: DUE CHECK COLUMN
    # -----------------------------
    def is_due(self, obj):
        from django.utils import timezone

        if obj.next_deduction:
            return obj.next_deduction <= timezone.now()
        return False

    is_due.boolean = True
    is_due.short_description = "Due Now"

    # -----------------------------
    # formatting helpers
    # -----------------------------
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

    # -----------------------------
    # 🔥 NEW: FILTER (Due / Not Due)
    # -----------------------------
    from django.contrib import admin
    from django.utils import timezone

    class DueStatusFilter(admin.SimpleListFilter):
        title = "Due Status"
        parameter_name = "due_status"

        def lookups(self, request, model_admin):
            return (
                ("due", "Due Now"),
                ("not_due", "Not Due"),
            )

        def queryset(self, request, queryset):
            if self.value() == "due":
                return queryset.filter(
                    is_active=True,
                    is_cancelled=False,
                    next_deduction__lte=timezone.now(),
                )

            if self.value() == "not_due":
                return queryset.filter(next_deduction__gt=timezone.now())

            return queryset

    list_filter = [
        "is_active",
        "is_cancelled",
        "frequency",
        "category",
        DueStatusFilter,  # 👈 IMPORTANT
    ]

    # -----------------------------
    # existing actions (UNCHANGED)
    # -----------------------------
    def force_process_deduction(self, request, queryset):
        results = {"processed": 0, "paused": 0, "failed": 0, "errors": []}

        for target in queryset:
            if target.is_active and not target.is_cancelled:
                try:
                    logger.info(
                        f"🔄 Admin forcing deduction for target {target.id}: {target.name}"
                    )

                    success = target.process_deduction()
                    target.refresh_from_db()

                    if success:
                        results["processed"] += 1
                    elif not target.is_active:
                        results["paused"] += 1
                    else:
                        results["failed"] += 1

                except Exception as e:
                    results["errors"].append(str(e))
                    results["failed"] += 1

        self.message_user(
            request,
            f"Processed: {results['processed']} | Failed: {results['failed']} | Paused: {results['paused']}",
        )

    force_process_deduction.short_description = "Force process deduction"

    def mark_as_completed(self, request, queryset):
        # Delegates to process_deduction() (same as force_process_deduction
        # above) so the 15% completion bonus is always credited via
        # _complete_target() rather than this action just flipping
        # is_active off with no payout, as it previously did.
        processed, skipped = 0, 0
        for target in queryset:
            try:
                if target.process_deduction():
                    processed += 1
                else:
                    skipped += 1
            except Exception as e:
                skipped += 1
                logger.error(f"Error marking target {target.id} as completed: {e}")

        self.message_user(
            request, f"Completed: {processed} | Skipped/unchanged: {skipped}"
        )


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


from django.contrib import admin
from .models import DvaDepositIntent


@admin.register(DvaDepositIntent)
class DvaDepositIntentAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "purpose",
        "amount",
        "status",
        "transaction_id",
        "paystack_reference",
        "created_at",
        "confirmed_at",
    )
    list_filter = ("purpose", "status", "created_at")
    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "transaction_id",
        "paystack_reference",
        "matched_account_number",
    )
    readonly_fields = (
        "user",
        "amount",
        "purpose",
        "status",
        "transaction_id",
        "paystack_reference",
        "matched_account_number",
        "created_at",
        "confirmed_at",
    )


from decimal import Decimal
from django.contrib import admin, messages
from django.db import transaction as db_transaction
from django.utils import timezone
from datetime import datetime
from .models import AmbassadorPointConfig, AmbassadorMonthlyReport, Transaction
from .utils import send_push_notification, send_generic_email


@admin.register(AmbassadorPointConfig)
class AmbassadorPointConfigAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "is_active",
        "signup_points",
        "signup_points_cap",
        "confirmed_points",
        "savings_points_per_10000",
        "savings_points_cap",
        "reshares_points",
        "updated_at",
    )

    def save_model(self, request, obj, form, change):
        if obj.is_active:
            AmbassadorPointConfig.objects.exclude(pk=obj.pk).update(is_active=False)
        super().save_model(request, obj, form, change)


@admin.register(AmbassadorMonthlyReport)
class AmbassadorMonthlyReportAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user_email",
        "user_phone",
        "user_first_name",
        "rank",
        "total_points_awarded",
        "status",
        "stipend_amount",
        "stipend_paid",
        "submitted_at",
        "approved_at",
        "formatted_month",
    )

    list_filter = (
        "month",
        "status",
        "stipend_paid",
    )

    date_hierarchy = "submitted_at"
    ordering = ("-month", "-submitted_at")

    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "month",
    )

    readonly_fields = (
        "submitted_at",
        "updated_at",
        "approved_at",
        "signup_points_awarded",
        "confirmed_points_awarded",
        "savings_points_awarded",
        "attendance_points_awarded",
        "coursera_points_awarded",
        "social_media_points_awarded",
        "abroad_points_awarded",
        "events_points_awarded",
        "reshares_points_awarded",
        "others_points_awarded",
        "total_points_awarded",
        "stipend_amount",
    )

    fieldsets = (
        (
            "Report Info",
            {
                "fields": (
                    "user",
                    "month",
                    "status",
                    "admin_note",
                    "approved_by",
                    "approved_at",
                    "submitted_at",
                    "updated_at",
                )
            },
        ),
        (
            "Submitted Values",
            {
                "fields": (
                    "signups_submitted",
                    "confirmed_submitted",
                    "savings_submitted",
                    "attendance_submitted",
                    "others_submitted",
                    "coursera_submitted",
                    "social_media_submitted",
                    "abroad_confirmed_submitted",
                    "events_submitted",
                    "reshares_submitted",
                    "notes",
                )
            },
        ),
        (
            "Evidence",
            {
                "fields": (
                    "coursera_certificate",
                    "social_media_evidence",
                    "abroad_signups_evidence",
                    "events_evidence",
                    "reshares_evidence",
                )
            },
        ),
        (
            "Approved Values",
            {
                "fields": (
                    "signups_approved",
                    "confirmed_approved",
                    "savings_approved",
                    "attendance_approved",
                    "others_approved",
                    "coursera_approved",
                    "social_media_approved",
                    "abroad_confirmed_approved",
                    "events_approved",
                    "reshares_approved",
                )
            },
        ),
        (
            "Points Breakdown",
            {
                "fields": (
                    "signup_points_awarded",
                    "confirmed_points_awarded",
                    "savings_points_awarded",
                    "attendance_points_awarded",
                    "coursera_points_awarded",
                    "social_media_points_awarded",
                    "abroad_points_awarded",
                    "events_points_awarded",
                    "reshares_points_awarded",
                    "others_points_awarded",
                    "total_points_awarded",
                )
            },
        ),
        (
            "Stipend",
            {
                "fields": (
                    "stipend_amount",
                    "stipend_paid",
                )
            },
        ),
    )

    actions = [
        "approve_reports",
        "reject_reports",
        "recalculate_selected_reports",
        "remove_ambassador_status",
    ]

    def formatted_month(self, obj):
        try:
            return datetime.strptime(obj.month, "%Y-%m").strftime("%b %Y")
        except:
            return obj.month

    formatted_month.short_description = "Month"
    formatted_month.admin_order_field = "month"

    def user_first_name(self, obj):
        return obj.user.first_name or obj.user.email

    user_first_name.short_description = "Name"
    user_first_name.admin_order_field = "user__first_name"

    def rank(self, obj):
        queryset = AmbassadorMonthlyReport.objects.filter(month=obj.month).order_by(
            "-stipend_amount", "-total_points_awarded", "submitted_at"
        )

        ids = list(queryset.values_list("id", flat=True))

        try:
            position = ids.index(obj.id) + 1
        except ValueError:
            return "-"

        if 10 <= position % 100 <= 20:
            suffix = "th"
        else:
            suffix = {1: "st", 2: "nd", 3: "rd"}.get(position % 10, "th")

        return f"{position}{suffix}"

    rank.short_description = "Rank"
    rank.admin_order_field = "stipend_amount"

    def user_email(self, obj):
        return obj.user.email

    user_email.short_description = "Email"
    user_email.admin_order_field = "user__email"

    def user_phone(self, obj):
        return obj.user.phone_number or "-"

    user_phone.short_description = "Phone"
    user_phone.admin_order_field = "user__phone_number"

    def credit_stipend_and_notify(self, report):
        user = report.user
        stipend_amount = Decimal(report.stipend_amount or 0)

        formatted_month = report.month
        try:
            formatted_month = datetime.strptime(report.month, "%Y-%m").strftime("%b %Y")
        except:
            pass

        # -----------------------------
        # CASE 1: ZERO PERFORMANCE
        # -----------------------------
        if stipend_amount <= 0:
            send_generic_email(
                subject="Ambassador Report Reviewed",
                message=(
                    f"Hi {user.first_name},<br><br>"
                    f"Your ambassador report for {formatted_month} has been reviewed.<br><br>"
                    f"No points were recorded for this period.<br><br>"
                    f"Don't worry — a new month is a fresh opportunity to grow. "
                    f"We're rooting for you to take action and earn more next time 💪<br><br>"
                    "MyFund"
                ),
                from_email="MyFund <info@myfundmobile.com>",
                recipient_list=[user.email],
            )

            send_push_notification(
                user=user,
                title="Ambassador Report Reviewed",
                message="No activity recorded this month. You can bounce back next month 💪",
                data={"report_id": report.id},
                notif_type="SYSTEM",
            )

            return False, "No stipend — encouragement sent."

        # -----------------------------
        # CASE 2: LOW PERFORMANCE (< ₦1000)
        # -----------------------------
        if stipend_amount < 1000:
            with db_transaction.atomic():
                locked_user = type(user).objects.select_for_update().get(pk=user.pk)

                locked_user.wallet = (
                    locked_user.wallet or Decimal("0.00")
                ) + stipend_amount
                locked_user.save(update_fields=["wallet"])

                Transaction.objects.create(
                    user=locked_user,
                    transaction_type="credit",
                    status="confirmed",
                    amount=stipend_amount,
                    description=f"{formatted_month} Stipend",
                    source="WALLET",
                )

                report.stipend_paid = True
                report.save(update_fields=["stipend_paid"])

            send_generic_email(
                subject="Ambassador Stipend Credited",
                message=(
                    f"Hi {user.first_name},<br><br>"
                    f"Your ambassador report for {formatted_month} has been reviewed.<br><br>"
                    f"Stipend credited: ₦{stipend_amount:,.2f}<br><br>"
                    f"Good effort 👍 — with a bit more consistency, you can earn much more next month.<br><br>"
                    "MyFund"
                ),
                from_email="MyFund <info@myfundmobile.com>",
                recipient_list=[user.email],
            )

            send_push_notification(
                user=user,
                title=f"{formatted_month} Stipend Credited ✅",
                message=(
                    f"Hi {user.first_name}, the stipends for {formatted_month} has been credited "
                    f"to your wallet. Keep developing your community for more rewards next month. Well done."
                ),
                data={"report_id": report.id},
                notif_type="SYSTEM",
            )

            return True, "Low stipend credited."

        # -----------------------------
        # CASE 3: NORMAL / HIGH PERFORMANCE
        # -----------------------------
        if report.stipend_paid:
            return False, "Already paid."

        with db_transaction.atomic():
            locked_user = type(user).objects.select_for_update().get(pk=user.pk)

            locked_user.wallet = (
                locked_user.wallet or Decimal("0.00")
            ) + stipend_amount
            locked_user.save(update_fields=["wallet"])

            Transaction.objects.create(
                user=locked_user,
                transaction_type="credit",
                status="confirmed",
                amount=stipend_amount,
                description=f"{formatted_month} Stipend",
                source="WALLET",
            )

            report.stipend_paid = True
            report.save(update_fields=["stipend_paid"])

        send_generic_email(
            subject=f"{formatted_month} Stipend Credited ✅",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Your ambassador report for {formatted_month} has been approved and your stipend has been credited.<br><br>"
                f"Amount: ₦{stipend_amount:,.2f}<br><br>"
                f"Focus on key metrics, especially confirmed referrals, to increase your earnings for the new month🔥<br><br>"
                f"Great work — keep it up 🔥<br><br>"
                "MyFund"
            ),
            from_email="MyFund <info@myfundmobile.com>",
            recipient_list=[user.email],
        )

        send_push_notification(
            user=user,
            title=f"{formatted_month} Stipend Credited ✅",
            message=(
                f"Hi {user.first_name}, the stipends for {formatted_month} has been credited "
                f"to your wallet. Keep developing your community for more rewards next month. Well done."
            ),
            data={"report_id": report.id},
            notif_type="SYSTEM",
        )

        return True, "Credited successfully."

    def notify_user_rejected(self, report):
        user = report.user

        send_generic_email(
            subject="Ambassador Report Update",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Your report for {report.month} was not approved.<br><br>"
                f"{report.admin_note or ''}"
            ),
            from_email="MyFund <info@myfundmobile.com>",
            recipient_list=[user.email],
        )

        send_push_notification(
            user=user,
            title="Ambassador Report Not Approved",
            message=f"Check your {report.month} report.",
            data={"report_id": report.id},
            notif_type="SYSTEM",
        )

    def save_model(self, request, obj, form, change):
        old_status = None
        old_paid = False

        if change and obj.pk:
            old = AmbassadorMonthlyReport.objects.get(pk=obj.pk)
            old_status = old.status
            old_paid = old.stipend_paid

        obj.recalculate_points()

        if obj.status == "approved" and not obj.approved_at:
            obj.approved_at = timezone.now()

        if obj.status == "approved" and not obj.approved_by:
            obj.approved_by = request.user

        super().save_model(request, obj, form, change)

        if old_status != "rejected" and obj.status == "rejected":
            self.notify_user_rejected(obj)

        if obj.status == "approved" and not old_paid and not obj.stipend_paid:
            success, msg = self.credit_stipend_and_notify(obj)
            self.message_user(
                request,
                msg,
                level=messages.SUCCESS if success else messages.WARNING,
            )

    @admin.action(description="✅ Approve selected reports")
    def approve_reports(self, request, queryset):
        for report in queryset:
            report.status = "approved"
            report.approved_by = request.user
            report.approved_at = timezone.now()
            report.recalculate_points()
            report.save()

            if not report.stipend_paid:
                self.credit_stipend_and_notify(report)

        self.message_user(request, "Approved.", level=messages.SUCCESS)

    @admin.action(description="❌ Reject selected reports")
    def reject_reports(self, request, queryset):
        for report in queryset:
            report.status = "rejected"
            report.save()
            self.notify_user_rejected(report)

        self.message_user(request, "Rejected.", level=messages.WARNING)

    @admin.action(description="🔄 Recalculate selected reports")
    def recalculate_selected_reports(self, request, queryset):
        for report in queryset:
            report.recalculate_points()
            report.save()

        self.message_user(request, "Recalculated.", level=messages.SUCCESS)

    @admin.action(description="❌ Remove Ambassador Status")
    def remove_ambassador_status(self, request, queryset):
        updated_count = 0

        for report in queryset:
            if revoke_user_ambassador_status(report.user):
                updated_count += 1

        self.message_user(
            request,
            f"{updated_count} ambassador(s) removed and notified.",
            level=messages.SUCCESS,
        )


@admin.register(FinanceMetricSnapshot)
class FinanceMetricSnapshotAdmin(admin.ModelAdmin):
    list_display = (
        "period_type",
        "period_start",
        "period_end",
        "total_revenue",
        "net_profit",
        "profit_margin",
        "abrupt_withdrawal_revenue",
        "float_gross_revenue",
        "roi_payable_to_users",
        "float_net_profit",
    )

    list_filter = ("period_type", "period_start")
    search_fields = ("period_type", "notes")
    readonly_fields = (
        "created_at",
        "updated_at",
    )

    actions = ["refresh_selected_snapshots"]

    @admin.action(description="Refresh selected finance snapshots")
    def refresh_selected_snapshots(self, request, queryset):
        from .finance_metrics import calculate_finance_metrics

        count = 0
        for snapshot in queryset:
            calculate_finance_metrics(
                period_type=snapshot.period_type,
                target_date=snapshot.period_start,
                save=True,
            )
            count += 1

        self.message_user(request, f"{count} finance snapshot(s) refreshed.")


@admin.action(description="📊 Send Daily Metrics Now")
def send_daily_metrics(modeladmin, request, queryset):

    daily_metrics_task.delay()


@admin.action(description="📈 Send Weekly Metrics Now")
def send_weekly_metrics(modeladmin, request, queryset):

    weekly_metrics_task.delay()


@admin.action(description="💰 Send Monthly Metrics Now")
def send_monthly_metrics(modeladmin, request, queryset):

    monthly_metrics_task.delay()


from django.contrib import admin
from authentication.models import PhoneChangeRequest
from authentication.services.phone_change import approve_phone_change


@admin.register(PhoneChangeRequest)
class PhoneChangeRequestAdmin(admin.ModelAdmin):

    list_display = (
        "user",
        "old_phone",
        "new_phone",
        "status",
        "created_at",
    )

    actions = ["approve_requests"]

    def approve_requests(self, request, queryset):
        for obj in queryset:
            try:
                approve_phone_change(obj.id, request.user)
            except Exception as e:
                self.message_user(request, f"Failed: {e}", level="error")

        self.message_user(request, "Selected requests approved successfully")

    approve_requests.short_description = "Approve selected phone change requests"


from authentication.models import Employee, PayrollRun, PayrollEntry
from authentication.payroll import create_draft_entries, send_pending_entries

from django.contrib.auth import get_user_model
from authentication.utils import (
    send_push_notification,
    send_generic_email,
)

User = get_user_model()


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):

    list_display = (
        "name",
        "email",
        "department",
        "monthly_amount",
        "is_active",
        "total_paid_display",
        "last_payment_display",
        "date_added",
    )

    list_filter = (
        "is_active",
        "department",
    )

    search_fields = (
        "name",
        "email",
    )

    readonly_fields = (
        "total_paid_display",
        "last_payment_display",
    )

    actions = [
        "create_draft_payroll",
        "quick_test_payroll",
        "quick_live_payroll",
    ]

    def total_paid_display(self, obj):

        total = (
            PayrollEntry.objects.filter(employee=obj, status="credited").aggregate(
                total=Sum("amount")
            )["total"]
            or 0
        )

        return f"₦{total:,.2f}"

    total_paid_display.short_description = "Total Paid (All Time)"

    def last_payment_display(self, obj):

        last = (
            PayrollEntry.objects.filter(employee=obj, status="credited")
            .order_by("-created_at")
            .first()
        )

        return last.created_at.strftime("%b %d, %Y") if last else "—"

    last_payment_display.short_description = "Last Paid"

    def save_model(self, request, obj, form, change):

        old_status = None
        old_department = None
        old_amount = None

        if change:
            old_employee = (
                Employee.objects.filter(pk=obj.pk)
                .values(
                    "is_active",
                    "department",
                    "monthly_amount",
                )
                .first()
            )

            if old_employee:
                old_status = old_employee["is_active"]
                old_department = old_employee["department"]
                old_amount = old_employee["monthly_amount"]

        super().save_model(request, obj, form, change)

        try:

            user = User.objects.get(email__iexact=obj.email)

            # NOTE: this used to also sync user.is_staff = obj.is_active,
            # silently granting real Django admin/API access to anyone
            # marked as an active payroll employee. That's what caused
            # ordinary staff to start receiving admin-only push
            # notifications (other users' transaction alerts). Payroll
            # status must never grant admin/API access - is_staff is set
            # manually per-account when someone is actually made an admin.

            status_changed = old_status is None or old_status != obj.is_active

            department_changed = (
                old_department is not None and old_department != obj.department
            )

            amount_changed = old_amount is not None and old_amount != obj.monthly_amount

            # No employee details changed
            if not (status_changed or department_changed or amount_changed):
                return

            # ==============================
            # EMPLOYEE ACTIVATED / ADDED
            # ==============================

            if status_changed and obj.is_active:

                title = "🎉 Welcome to the MyFund Team!"

                message = (
                    "Hi {first_name}, "
                    "welcome to the MyFund team! "
                    "You have joined the {department} department "
                    "with a monthly allowance of ₦{monthly_amount}. "
                    "We are excited to have you onboard. 🚀"
                )

                email_subject = "🎉 Welcome to MyFund, {first_name}!"

                email_message = """
    <p>
    Hi <strong>{first_name}</strong>,
    </p>

    <p>
    Congratulations and welcome to the <strong>MyFund team! 🎉</strong>
    </p>

    <p>
    You have officially joined the 
    <strong>{department} department</strong>.
    </p>

    <p>
    Your employee access has been activated.
    </p>

    <p>
    Your monthly team allowance is:
    </p>

    <p>
    <strong>₦{monthly_amount}</strong>
    </p>

    <p>
    You are now part of a team building solutions that make property ownership
    and wealth creation more accessible across Africa.
    </p>

    <p>
    We are excited about the skills, ideas, and energy you will bring to the
    MyFund journey.
    </p>

    <p>
    Welcome aboard! 🚀
    </p>

    <p>
    Warm regards,<br>
    <strong>The MyFund Team</strong>
    </p>
    """

            # ==============================
            # EMPLOYEE DEACTIVATED
            # ==============================

            elif status_changed and not obj.is_active:

                title = "MyFund Team Access Update"

                message = (
                    "Hi {first_name}, "
                    "your MyFund employee access has been updated. "
                    "Thank you for your contributions and support."
                )

                email_subject = "MyFund Employee Access Update"

                email_message = """
    <p>
    Hi <strong>{first_name}</strong>,
    </p>

    <p>
    Your MyFund employee access has been updated.
    </p>

    <p>
    Your team access has been deactivated.
    </p>

    <p>
    Thank you for your contributions, dedication, and support during your time
    with MyFund.
    </p>

    <p>
    We appreciate the impact you have made.
    </p>

    <p>
    Warm regards,<br>
    <strong>The MyFund Team</strong>
    </p>
    """

            # ==============================
            # EMPLOYEE PROFILE UPDATED
            # ==============================

            else:

                title = "MyFund Employee Profile Updated"

                message = (
                    "Hi {first_name}, "
                    "your MyFund employee profile has been updated. "
                    "Department: {department}. "
                    "Monthly allowance: ₦{monthly_amount}."
                )

                email_subject = "MyFund Employee Details Updated"

                email_message = """
    <p>
    Hi <strong>{first_name}</strong>,
    </p>

    <p>
    Your MyFund employee details have been updated successfully.
    </p>

    <p>
    Here are your updated details:
    </p>

    <p>
    <strong>Department:</strong> {department}
    </p>

    <p>
    <strong>Monthly Allowance:</strong> ₦{monthly_amount}
    </p>

    <p>
    Your employee access remains active, and we appreciate your continued
    contribution to the MyFund journey.
    </p>

    <p>
    If you have any questions about this update, please contact the MyFund team.
    </p>

    <p>
    Warm regards,<br>
    <strong>The MyFund Team</strong>
    </p>
    """

            # ==============================
            # SEND PUSH NOTIFICATION
            # ==============================

            send_push_notification(
                user=user,
                title=title,
                message=message,
                notif_type="STAFF_STATUS",
                extra_context={
                    "department": obj.department,
                    "monthly_amount": f"{obj.monthly_amount:,.2f}",
                },
            )

            # ==============================
            # SEND EMAIL
            # ==============================

            send_generic_email(
                subject=email_subject,
                message=email_message,
                recipient_list=[user.email],
                extra_context={
                    "department": obj.department,
                    "monthly_amount": f"{obj.monthly_amount:,.2f}",
                },
            )

        except User.DoesNotExist:

            self.message_user(
                request,
                f"No user account found for {obj.email}. "
                "Employee saved but staff status was not updated.",
                level=messages.WARNING,
            )

    @admin.action(description="📝 CREATE PAYMENT DRAFT (edit details)")
    def create_draft_payroll(self, request, queryset):

        month_label = timezone.now().strftime("%B %Y")

        run = create_draft_entries(
            queryset,
            month_label,
            executed_by=request.user.email,
        )

        self.message_user(
            request,
            f"Draft created for {month_label}: {queryset.count()} entries.",
            level=messages.SUCCESS,
        )

    @admin.action(description="💸 PAY Selected Employees")
    def quick_live_payroll(self, request, queryset):

        month_label = timezone.now().strftime("%B %Y")

        run = create_draft_entries(
            queryset,
            month_label,
            executed_by=request.user.email,
        )

        results = send_pending_entries(run.entries.all(), test=False)

        self.message_user(
            request,
            f"Live paid: {len(results)} entries.",
            level=messages.SUCCESS,
        )


class PayrollEntryInline(admin.TabularInline):
    model = PayrollEntry
    extra = 0
    fields = (
        "employee",
        "email",
        "name",
        "amount",
        "description",
        "balance_before",
        "balance_after",
        "status",
        "created_at",
    )
    readonly_fields = (
        "employee",
        "email",
        "balance_before",
        "balance_after",
        "status",
        "created_at",
    )
    can_delete = False


@admin.register(PayrollRun)
class PayrollRunAdmin(admin.ModelAdmin):
    list_display = ("month_label", "reason", "executed_at", "executed_by")
    list_filter = ("month_label",)
    inlines = [PayrollEntryInline]


@admin.register(PayrollEntry)
class PayrollEntryAdmin(admin.ModelAdmin):
    list_display = (
        "run",
        "name",
        "email",
        "amount",
        "description",
        "status",
        "created_at",
    )
    list_filter = ("status", "run")
    search_fields = ("name", "email")
    fields = ("run", "employee", "email", "name", "amount", "description", "status")
    readonly_fields = ("run", "employee", "email", "name", "status")
    actions = ["send_test", "send_live"]

    @admin.action(description="🧪 Send TEST for selected pending entries")
    def send_test(self, request, queryset):
        results = send_pending_entries(queryset, test=True)
        self.message_user(
            request,
            f"Test sent: {len(results)} entries. Check valueplusrecords@gmail.com.",
            level=messages.SUCCESS,
        )

    @admin.action(description="💸 Send LIVE for selected pending entries")
    def send_live(self, request, queryset):
        results = send_pending_entries(queryset, test=False)
        self.message_user(
            request, f"Live sent: {len(results)} entries.", level=messages.SUCCESS
        )


admin.site.register(DailyROIAccrual, DailyROIAccrualAdmin)
admin.site.register(ROITransaction, ROITransactionAdmin)
admin.site.register(Card, CardAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(AutoSave, AutoSaveAdmin)
admin.site.register(AutoInvest, AutoInvestAdmin)
admin.site.register(Property, PropertyAdmin)


from .models import (
    Group,
    GroupOwnership,
    Contribution,
    GroupDeparture,
    GroupIncomeEvent,
    GroupIncomeDistribution,
)


class GroupAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "property",
        "created_by",
        "goal_amount",
        "total_raised",
        "status",
        "group_type",
        "deadline",
        "created_at",
        "completed_at",
        "reminder_sent",
    ]
    list_editable = ["status"]
    list_filter = ["status", "group_type"]
    search_fields = ["id", "property__name", "created_by__email"]
    actions = ["trigger_test_rent_payment"]

    def save_model(self, request, obj, form, change):
        # list_editable's inline status column (and the detail-page edit
        # form) let staff flip a group straight to "completed" without ever
        # going through contribute_to_groupbuy - which is the only other
        # place completed_at gets set and user.properties gets credited.
        # Do both here too, the moment that transition is spotted, so a
        # manually-completed group behaves identically to a naturally
        # completed one (rent payout dates, the properties counter, etc).
        was_completed = (
            change and obj.pk
            and Group.objects.filter(pk=obj.pk, status="completed").exists()
        )

        if obj.status == "completed" and not was_completed and not obj.completed_at:
            from django.utils import timezone

            obj.completed_at = timezone.now()

        super().save_model(request, obj, form, change)

        if obj.status == "completed" and not was_completed:
            from .utils import credit_groupbuy_ownership_properties

            credited = credit_groupbuy_ownership_properties(obj)
            if credited:
                self.message_user(
                    request,
                    f"Credited {credited} member(s) +1 property for this "
                    f"newly-completed GroupBuy.",
                    level=messages.SUCCESS,
                )

    @admin.action(description="💰 Trigger test rent payment (distribute this period's income now)")
    def trigger_test_rent_payment(self, request, queryset):
        """
        Runs the real distribution code path (auto_distribute_groupbuy_income,
        force=True) for just the selected group(s) right now, instead of
        waiting for the monthly period to actually elapse - for demos/testing.
        Same GroupIncomeEvent/GroupIncomeDistribution/wallet-credit
        transactions as the automatic monthly sweep or the staff dashboard's
        manual distribute-income action, so this is a real payment, not a
        simulated one.
        """
        from .utils import auto_distribute_groupbuy_income

        non_completed = [g for g in queryset if g.status != "completed"]
        completed_ids = [g.id for g in queryset if g.status == "completed"]

        if non_completed:
            self.message_user(
                request,
                f"Skipped {len(non_completed)} group(s) that aren't 'completed' "
                f"yet - a GroupBuy has to be fully funded before it can pay rent.",
                level=messages.WARNING,
            )

        if not completed_ids:
            return

        result = auto_distribute_groupbuy_income(group_ids=completed_ids, force=True)

        for event in result["events"]:
            self.message_user(
                request,
                f"✅ Paid ₦{event['amount']:,.2f} for {event['property']} "
                f"({event['period_start']} – {event['period_end']}), "
                f"group {event['group_id']}.",
                level=messages.SUCCESS,
            )
            try:
                from .tasks import distribute_groupbuy_income_notifications

                # send_email=True (unlike the routine monthly sweep) - this
                # is a one-off demo/test trigger, so a visible, hard-to-miss
                # confirmation matters more than the recurring-cost concern
                # that keeps the automatic monthly payout push-only.
                distribute_groupbuy_income_notifications.delay(
                    event["event_id"], send_email=True
                )
            except Exception:
                pass

        for skip in result["skipped"]:
            self.message_user(
                request,
                f"⚠️ Group {skip['group_id']}: {skip['reason']}",
                level=messages.WARNING,
            )

        if not result["events"] and not result["skipped"]:
            self.message_user(
                request, "Nothing to distribute.", level=messages.WARNING
            )


class GroupOwnershipAdmin(admin.ModelAdmin):
    list_display = ["id", "group", "user", "total_contributed", "ownership_percentage"]
    list_filter = ["group"]
    search_fields = ["user__email", "group__id"]


class ContributionAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "group",
        "user",
        "amount",
        "payment_status",
        "source",
        "created_at",
    ]
    list_filter = ["payment_status", "source"]
    search_fields = ["user__email", "group__id"]


class GroupDepartureAdmin(admin.ModelAdmin):
    list_display = ["id", "group", "user", "reason", "refunded_amount", "left_at"]
    list_filter = ["reason"]
    search_fields = ["user__email", "group__id"]


class GroupIncomeEventAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "group",
        "amount",
        "period_start",
        "period_end",
        "status",
        "total_distributed",
        "recorded_by",
        "created_at",
    ]
    list_filter = ["status"]
    search_fields = ["group__id", "group__property__name"]


class GroupIncomeDistributionAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "income_event",
        "user",
        "ownership_percentage",
        "amount",
        "status",
        "created_at",
    ]
    list_filter = ["status"]
    search_fields = ["user__email", "income_event__id"]


admin.site.register(Group, GroupAdmin)
admin.site.register(GroupOwnership, GroupOwnershipAdmin)
admin.site.register(Contribution, ContributionAdmin)
admin.site.register(GroupDeparture, GroupDepartureAdmin)
admin.site.register(GroupIncomeEvent, GroupIncomeEventAdmin)
admin.site.register(GroupIncomeDistribution, GroupIncomeDistributionAdmin)


from .models import AdminNotifyRecipient


@admin.register(AdminNotifyRecipient)
class AdminNotifyRecipientAdmin(admin.ModelAdmin):
    list_display = [
        "email",
        "label",
        "notify_transactions",
        "notify_groupbuy",
        "notify_signups",
        "notify_system",
        "is_active",
        "created_at",
    ]
    list_editable = [
        "notify_transactions",
        "notify_groupbuy",
        "notify_signups",
        "notify_system",
        "is_active",
    ]
    search_fields = ["email", "label"]


from .models import AppVersionConfig


@admin.register(AppVersionConfig)
class AppVersionConfigAdmin(admin.ModelAdmin):
    list_display = [
        "minimum_required_version",
        "latest_version",
        "updated_at",
    ]

    def has_add_permission(self, request):
        # Singleton - block "Add" once the one row exists (get_solo() also
        # auto-creates it on first read, so in practice this is almost
        # always already there).
        return not AppVersionConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False
