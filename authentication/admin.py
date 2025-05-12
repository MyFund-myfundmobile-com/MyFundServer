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
)
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework.response import Response
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib import admin
from django.db.models import (
    Sum,
    F,
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


class UserPasswordInline(admin.StackedInline):
    model = UserPassword
    can_delete = False
    verbose_name_plural = "Password"


class CustomUserAdmin(UserAdmin):
    list_display = (
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "total_referrals",
        "confirmed_referrals",
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
        "profile_picture",
    )
    list_filter = (
        "is_staff",
        "is_active",
        "kyc_updated",
        "how_did_you_hear",
        "date_joined",
        "is_hired_referrer",
        "is_ambassador",
    )
    actions = [
        "export_to_csv",  # Add export action
        "send_custom_email",
        "view_kyc_details",
        "approve_kyc",
        "reject_kyc",
        "make_hired_referrer",
        "make_ambassador",
        "delete_selected",
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
                    "total_referrals",
                    "confirmed_referrals",
                )
            },
        ),
        (
            "Account Balances",
            {"fields": ("savings", "investment", "properties", "wallet")},
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
    inlines = [TransactionInline, UserPasswordInline]

    def total_referrals(self, obj):
        return Transaction.objects.filter(referral_email=obj.email).count()

    def confirmed_referrals(self, obj):
        return Transaction.objects.filter(
            referral_email=obj.email, status="confirmed"
        ).count()

    total_referrals.short_description = "Total Signups"
    confirmed_referrals.short_description = "Confirmed Signups"

    total_referrals.short_description = "Total Referrals"

    confirmed_referrals.short_description = "Confirmed Referrals"

    def total_referrals_display(self, obj):
        return getattr(obj, "_total_referrals", 0)

    total_referrals_display.short_description = "Total Referrals"
    total_referrals_display.admin_order_field = "_total_referrals"

    def confirmed_referrals_display(self, obj):
        return getattr(obj, "_confirmed_referrals", 0)

    confirmed_referrals_display.short_description = "Confirmed Referrals"
    confirmed_referrals_display.admin_order_field = "_confirmed_referrals"

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

    def make_hired_referrer(self, request, queryset):
        updated_count = queryset.update(is_hired_referrer=True)

    def make_ambassador(self, request, queryset):
        updated_count = queryset.update(is_ambassador=True)

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

        # Redirect to the changelist view after processing

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
            CustomUser.objects.all()
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
            is_referrer = True
            user.confirm_referral_rewards(is_referrer=is_referrer)

            # After processing an investment transfer transaction
            user.update_total_savings_and_investment_this_month()

            # ✅ Send Approval Email
            subject = "QuickSave Updated! ✔"
            message = f"Hi {user.first_name},\n\nYour bank transfer of ₦{transfer_request.amount} has been approved and added to your savings!\n\nKeep growing your funds! \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            send_mail(subject, message, "MyFund <info@myfundmobile.com>", [user.email])

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
        "user",
        "source_account",  # Added this line to display source account
        "amount",
        "target_bank",
        "target_account_number",
        "transaction_id",
        "is_approved",
        "created_at",
    )
    list_filter = (
        "is_approved",
        "source_account",
    )  # Optionally, add source_account to filter options
    search_fields = (
        "user__email",
        "transaction_id",
        "target_bank",
        "source_account",  # Added this line to allow searching by source account
        "target_account_number",
    )
    actions = ["approve_withdrawal"]

    def approve_withdrawal(self, request, queryset):
        for withdrawal_request in queryset:
            user = withdrawal_request.user
            amount = withdrawal_request.amount
            transaction_id = withdrawal_request.transaction_id

            # Skip already approved requests
            if withdrawal_request.is_approved:
                continue

            with db_transaction.atomic():  # Ensure consistency
                # Deduct amount from user's balance
                if withdrawal_request.source_account == "savings":
                    user.savings -= amount
                elif withdrawal_request.source_account == "investment":
                    user.investment -= amount
                elif withdrawal_request.source_account == "wallet":
                    user.wallet -= amount

                user.save()

                # Mark withdrawal as approved
                withdrawal_request.is_approved = True
                withdrawal_request.save()

                # Update the transaction record's status
                try:
                    transaction = Transaction.objects.get(
                        user=user, transaction_id=transaction_id
                    )
                    transaction.status = "confirmed"  # Update status
                    transaction.description = f"{withdrawal_request.source_account.capitalize()} > Bank"  # Fix description update
                    transaction.save()  # Save changes

                except Transaction.DoesNotExist:
                    self.message_user(
                        request,
                        f"Transaction {transaction_id} not found for user {user.email}!",
                        level="error",
                    )
                    continue  # Skip this withdrawal if no matching transaction exists

                # Send email notification
                subject = "Withdrawal Approved! ✔"
                message = (
                    f"Hi {user.first_name},\n\n"
                    f"Your withdrawal of ₦{amount} to {withdrawal_request.target_bank} "
                    f"({withdrawal_request.target_account_number}) has been processed successfully!\n\n"
                    f"Thank you for using MyFund.\n\n"
                    f"MyFund\nSave, Buy Properties, Earn Rent\n"
                    f"www.myfundmobile.com\n"
                    f"13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                )
                send_mail(
                    subject, message, "MyFund <message@myfundmobile.com>", [user.email]
                )

        self.message_user(request, "Selected withdrawals have been approved.")


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("sender", "recipient", "content", "timestamp")
    list_filter = ("timestamp",)
    search_fields = ("sender__email", "recipient__email", "content")

    actions = ["reply_to_selected_messages"]  # Add a custom action


def reply_to_messages(modeladmin, request, queryset):
    for message in queryset:
        # Implement your reply logic here, e.g., sending a notification to the user
        # or performing any other actions needed to send a reply.
        pass


reply_to_messages.short_description = "Reply to selected messages"
admin.site.add_action(reply_to_messages)


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
        "status",  # Added status here
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
        "description",
        "transaction_id",
        "transaction_type",
        "status",  # Allow searching by status
        "amount",
        "referral__user__email",
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


from django.db.models import F
import csv
from django.http import HttpResponse
from django.contrib import admin
from .models import TopSaverHistory
from django.utils import timezone
import calendar


# Action to export to CSV
def export_to_csv(modeladmin, request, queryset):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=top_savers.csv"

    writer = csv.writer(response)
    writer.writerow(["Month", "Year", "Rank", "User", "Total Savings"])

    for obj in queryset:
        month_name = calendar.month_name[
            obj.month
        ]  # Convert month number to month name
        writer.writerow(
            [
                month_name,  # Month name instead of number
                obj.year,
                obj.rank,
                obj.user.first_name + " " + obj.user.last_name,
                obj.total_savings,
            ]
        )

    return response


export_to_csv.short_description = "Export to CSV"


# Custom Admin for TopSaverHistory
class TopSaverHistoryAdmin(admin.ModelAdmin):
    list_display = (
        "get_month_name",  # Use custom method for month name
        "year",
        "rank",
        "user",
        "total_savings",
        "is_current_month",
    )
    search_fields = ("user__first_name", "user__last_name", "month", "year")
    list_filter = ("month", "year")
    ordering = ("-year", "-month", "rank")
    list_per_page = 20
    actions = [export_to_csv]

    # Method to convert month number to month name
    def get_month_name(self, obj):
        return calendar.month_name[obj.month]  # Convert month number to name

    get_month_name.short_description = "Month"

    # Custom queryset to highlight the current month's top savers
    def get_queryset(self, request):
        queryset = super().get_queryset(request)

        # Optionally, this filters to show the current month's data as well,
        # you can customize this to suit your needs (e.g., current month vs historical).
        now = timezone.now()
        current_month = now.month
        current_year = now.year

        # Optionally, filter for current month only (if you want to show only current month by default)
        # queryset = queryset.filter(month=current_month, year=current_year)

        return queryset.order_by("-year", "-month", "rank")

    # Optionally, add a method to highlight the current month in the admin list view
    def is_current_month(self, obj):
        now = timezone.now()
        return obj.month == now.month and obj.year == now.year

    is_current_month.boolean = True
    is_current_month.short_description = "Current Month"


@admin.register(TargetSavings)
class TargetSavingsAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "name",
        "target_amount",
        "current_amount",
        "progress_percentage",
        "is_active",
        "next_deduction",
        "funding_source",
    )
    list_filter = ("is_active", "frequency", "category")
    search_fields = ("user__email", "name")
    readonly_fields = ("progress_percentage",)
    fieldsets = (
        (None, {"fields": ("user", "name", "target_amount", "current_amount")}),
        ("Settings", {"fields": ("frequency", "funding_source", "payment_method")}),
        ("Dates", {"fields": ("start_date", "end_date", "next_deduction")}),
        ("Status", {"fields": ("is_active", "is_cancelled", "cancellation_charge")}),
    )

    def progress_percentage(self, obj):
        return f"{obj.progress_percentage:.2f}%"

    progress_percentage.short_description = "Progress"


# Register TopSaverHistory with customized admin
admin.site.register(TopSaverHistory, TopSaverHistoryAdmin)
admin.site.register(Card, CardAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(AutoSave, AutoSaveAdmin)
admin.site.register(AutoInvest, AutoInvestAdmin)
admin.site.register(Property, PropertyAdmin)
