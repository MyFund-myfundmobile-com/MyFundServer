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
from .models import CustomUser, CustomUserMetrics, Referral, UserPassword


class TransactionInline(admin.TabularInline):
    model = Transaction
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
        "date_joined",
        "profile_picture",
        "kyc_updated",
        "is_staff",
        "is_active",
        "preferred_asset",
        "savings_goal_amount",
        "time_period",
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
        "send_custom_email",
        "view_kyc_details",
        "approve_kyc",
        "reject_kyc",
        "make_hired_referrer",
        "make_ambassador",
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
                    "is_hired_referrer",
                    "groups",
                    "user_permissions",
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
                transaction__date__year=current_month_start.year,
                transaction__date__month=current_month_start.month,
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
            message = f"Hi {user.first_name},\n\nYour bank transfer of ₦{transfer_request.amount} has been approved and added to your savings!\n\Keep growing your funds! \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
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
        approved_users = []

        for request in queryset:
            request.is_approved = True
            request.save()

            # Update user's investment
            user = request.user
            user.investment += int(request.amount)
            user.save()

            # Call the confirm_referral_rewards method here
            is_referrer = True
            user.confirm_referral_rewards(is_referrer=is_referrer)

            # Create a transaction record
            transaction = Transaction.objects.create(
                user=user,
                transaction_type="credit",
                amount=request.amount,
                date=timezone.now().date(),
                time=timezone.now().time(),
                description=f"QuickInvest (Confirmed)",
                transaction_id=str(uuid.uuid4())[:10],
            )
            transaction.save()

            # Send an approval email to the user
            subject = "QuickInvest Updated! ✔"
            message = f"Hi {user.first_name}, \n\nYour investment transfer request for ₦{request.amount} has been approved and credited to your INVESTMENT account!\n\nThank you for using MyFund. \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            approved_users.append(user)

            # After processing an investment transfer transaction
            user.update_total_savings_and_investment_this_month()

    approve_invest_transfer.short_description = "Approve selected investment transfers"

    def reject_invest_transfer(self, request, queryset):
        for request in queryset:
            user = request.user

            # Create a transaction record
            transaction = Transaction.objects.create(
                user=user,
                transaction_type="debit",
                amount=request.amount,
                date=timezone.now().date(),
                time=timezone.now().time(),
                description=f"QuickInvest (Failed)",
                transaction_id=str(uuid.uuid4())[:10],
            )
            transaction.save()

            # Send a rejection email to the user
            subject = "QuickInvest Failed. ❌"
            message = f"Hi {request.user.first_name}, \n\nYour investment transfer request for ₦{request.amount} could not be confirmed. Kindly check and try again.\n\nThank you for using MyFund. \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [request.user.email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            # Delete the rejected request
            request.delete()

    reject_invest_transfer.short_description = "Reject selected investment transfers"


from django.contrib import admin
from django.db import transaction as db_transaction
from django.core.mail import send_mail
from .models import WithdrawalsRequestToAdmin, Transaction


@admin.register(WithdrawalsRequestToAdmin)
class PendingWithdrawalsAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "amount",
        "target_bank",
        "target_account_number",
        "transaction_id",
        "is_approved",
        "created_at",
    )
    list_filter = ("is_approved",)
    search_fields = (
        "user__email",
        "transaction_id",
        "target_bank",
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
                    transaction.status = "confirmed"  # Correct field update
                    transaction.save()
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


class AutoSaveAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "frequency",
        "amount",
        "active",
    )  # Add 'amount' to the list of displayed fields


class AutoInvestAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "frequency", "amount", "active")


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
    )
    list_filter = ("transaction_type", "status", "date")  # Added status filter
    search_fields = (
        "user__email",
        "description",
        "transaction_id",
        "transaction_type",
        "status",  # Allow searching by status
        "amount",
    )

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


class ReferralAdmin(admin.ModelAdmin):
    list_display = ("user", "referrer", "created_at")
    search_fields = ("user__email", "referrer__email")
    list_filter = ("created_at",)
    ordering = ("-created_at",)

    def get_queryset(self, request):
        """Optimize the queryset by prefetching related user and referrer data."""
        qs = super().get_queryset(request)
        return qs.select_related("user", "referrer")


admin.site.register(Card, CardAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(AutoSave, AutoSaveAdmin)
admin.site.register(AutoInvest, AutoInvestAdmin)
admin.site.register(Property, PropertyAdmin)
admin.site.register(Referral, ReferralAdmin)
