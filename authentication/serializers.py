import os

from django.http import JsonResponse
from rest_framework import serializers, status
from django.contrib.auth.models import User
from .models import CustomUser, Message, UserPassword
from django.db import transaction
from django.contrib.auth.hashers import make_password
import logging
from django.db.models import Q

logger = logging.getLogger(__name__)


class SignupSerializer(serializers.ModelSerializer):
    referral = serializers.EmailField(
        required=False,
        allow_blank=True,  # This allows empty string as valid input
        allow_null=True,  # This allows null as valid input
        label="Referral Email (optional)",
    )
    how_did_you_hear = serializers.ChoiceField(
        choices=[
            ("SM", "Social Media - Facebook, Instagram, etc."),
            ("IMs", "Instant Messaging - WhatsApp, Telegram, etc."),
            ("FF", "Family and Friend"),
            ("GS", "Google Search"),
            ("REC", "Recommended"),
            ("CFG", "Cashflow Game"),
            ("OTHER", "Other"),
        ],
        default="OTHER",
    )

    class Meta:
        model = CustomUser
        fields = [
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "referral",
            "how_did_you_hear",
            "password",
        ]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["how_did_you_hear"] = dict(
            self.fields["how_did_you_hear"].choices
        ).get(instance.how_did_you_hear)
        return representation

    def create(self, validated_data):

        referral_code = validated_data.pop("referral", None)
        request = self.context.get("request")

        password = request.data.get("password")

        if not password:
            raise serializers.ValidationError({"password": "Password is required."})

        with transaction.atomic():
            # Create the user normally
            user = CustomUser.objects.create(**validated_data)

            # Save password in CustomUser so authenticate() works
            user.set_password(password)  # <-- this hashes and stores it
            user.save()

            # Also store in UserPassword if you still want legacy record
            UserPassword.objects.get_or_create(
                user=user, defaults={"password": make_password(password)}
            )

        if referral_code:
            referrer = CustomUser.objects.filter(
                Q(email__iexact=referral_code) | Q(phone_number__iexact=referral_code)
            ).first()
            if referrer:
                user.referral = referrer
                user.save()
                logger.info("Referral applied successfully")
            else:
                logger.warning(f"Invalid referral code: {referral_code}")

        return user


class ConfirmOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate_otp(self, value):
        """
        Ensure OTP is always a 6-character string, even if frontend sends an int.
        """
        value_str = str(value).zfill(6)  # pads numbers like 123 -> '000123'
        return value_str


from django.conf import settings  # Import settings to get the MEDIA_URL


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    is_confirmed = serializers.BooleanField(read_only=True)
    profile_picture = serializers.SerializerMethodField()
    date_joined = serializers.DateTimeField(format="%d %b. %Y   |   %I:%M%p")
    is_subscribed = serializers.BooleanField(read_only=True)
    total_referrals = serializers.IntegerField(read_only=True)
    confirmed_referrals = serializers.IntegerField(read_only=True)
    wealth_stage = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            # Existing fields
            "id",
            "first_name",
            "last_name",
            "email",
            "password",
            "phone_number",
            "referral",
            "profile_picture",
            "how_did_you_hear",
            "is_confirmed",
            "date_joined",
            "is_subscribed",
            # New admin fields
            "kyc_status",
            "savings_goal_amount",
            "savings",
            "investment",
            "properties",
            "wallet",
            "total_savings_and_investments_this_month",
            "is_hired_referrer",
            "is_ambassador",
            "autosave_enabled",
            "autoinvest_enabled",
            # KYC fields
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
            "state",
            "country",
            # DVA / Paystack fields
            "dva_account_number",
            "dva_account_name",
            "dva_bank_name",
            "dva_assigned_at",
            "dva_account_id",
            "paystack_identified",
            "paystack_identification_status",
            "paystack_identification_reason",
            # Add new referral fields
            "total_referrals",
            "confirmed_referrals",
            "wealth_stage",
        ]

    def get_date_joined(self, obj):
        return obj.date_joined.strftime("%d %b. %Y   |   %I:%M%p")

    def get_profile_picture(self, obj):
        if isinstance(obj.profile_picture, str):
            if "http" not in obj.profile_picture:
                return f"{settings.MEDIA_URL}{obj.profile_picture}"
            return obj.profile_picture

        if obj.profile_picture and hasattr(obj.profile_picture, "url"):
            if "http" not in obj.profile_picture.url:
                return f"{settings.MEDIA_URL}{obj.profile_picture.url}"
            return obj.profile_picture.url

        return None

    def get_wealth_stage(self, obj):
        import math

        total = obj.savings_and_investments
        if total == 0:
            stage = 1
        else:
            stage = min(int(math.log10(total + 1)) + 1, 9)
        return stage

    def create(self, validated_data):
        password = validated_data.pop("password")

        # Create the user instance first
        password = validated_data.pop("password")
        user = CustomUser.objects.create(**validated_data)

        # Set password on CustomUser for login
        user.set_password(password)
        user.save()

        # Optionally keep UserPassword record if still needed
        UserPassword.objects.get_or_create(
            user=user, defaults={"password": make_password(password)}
        )

        return user

    def update(self, instance, validated_data):
        if "password" in validated_data:
            password = validated_data.pop("password")

            if instance.password_record:
                instance.password_record.set_password(password)
                instance.password_record.save()
            else:
                UserPassword.objects.create(user=instance, password=password)

        return super().update(instance, validated_data)


class AdminUserListSerializer(UserSerializer):
    """
    UserSerializer plus the admin-only status flags (is_banned, is_active,
    is_staff, is_deleted) that regular self-profile serialization
    deliberately leaves out - used only by admin-gated endpoints
    (all_users_list, admin_user_detail) so these fields never leak into a
    user's own profile view.
    """

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + [
            "is_banned",
            "is_active",
            "is_staff",
            "is_deleted",
        ]


from .models import Transaction as _AdminTransaction


class AdminTransactionListSerializer(serializers.ModelSerializer):
    """
    Transaction fields plus nested minimal user identity (email/name) -
    used only by the admin-gated all_transactions_list endpoint, which
    needs to show who a transaction belongs to without a second lookup.
    """

    user_email = serializers.EmailField(source="user.email", read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta:
        model = _AdminTransaction
        fields = [
            "id",
            "transaction_id",
            "user",
            "user_email",
            "user_name",
            "transaction_type",
            "status",
            "source",
            "credited_to",
            "amount",
            "service_charge",
            "total_amount",
            "balance_before",
            "balance_after",
            "description",
            "date",
            "time",
        ]

    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()


from authentication.models import CustomUser


class KYCUpdateSerializer(serializers.ModelSerializer):
    id_upload = serializers.ImageField(
        max_length=None, use_url=True
    )  # This handles image uploads

    class Meta:
        model = CustomUser
        fields = "__all__"


class KYCStatusUpdateSerializer(serializers.Serializer):
    kyc_status = serializers.CharField(max_length=30)


from django.contrib.auth import authenticate


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        # Retrieve user using case-insensitive email match
        user = authenticate(
            request=self.context.get("request"), email__iexact=email, password=password
        )

        if user:
            if not user.is_active:
                raise serializers.ValidationError("User account is not active.")
            return user
        else:
            raise serializers.ValidationError("Invalid email or password.")


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField()


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["first_name", "last_name", "phone_number"]

    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class ProfilePictureUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["profile_picture"]


class SavingsGoalUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["preferred_asset", "savings_goal_amount", "time_period"]


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = "__all__"


class OutgoingMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = "__all__"  # Or list the specific fields you want to include


class IncomingMessageSerializer(serializers.Serializer):
    content = serializers.CharField()
    # Add other fields as needed


from .models import BankAccount, Card, TargetSavings


class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = "__all__"  # Or list the specific fields you want to include


class AccountBalancesSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["savings", "investment", "properties", "wallet"]


# serializers.py
from rest_framework import serializers
from .models import TargetSavings
from decimal import Decimal
from django.utils import timezone
from dateutil.relativedelta import relativedelta


class TargetSavingsSerializer(serializers.ModelSerializer):
    progress_percentage = serializers.DecimalField(
        max_digits=5, decimal_places=2, read_only=True
    )
    target_amount = serializers.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal("100.00")
    )
    monthly_payment = serializers.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal("100.00")
    )
    start_date = serializers.DateField(format="%Y-%m-%d", required=False)
    end_date = serializers.DateField(format="%Y-%m-%d", input_formats=["%Y-%m-%d"])
    is_completed = serializers.BooleanField(read_only=True)
    funding_source = serializers.ChoiceField(
        choices=[("SAVINGS", "Savings"), ("INVESTMENT", "Investment")]
    )

    funding_source = serializers.ChoiceField(
        choices=[("SAVINGS", "SAVINGS"), ("INVESTMENT", "INVESTMENT")],
        required=True,
    )

    frequency = serializers.ChoiceField(
        choices=[("DAILY", "Daily"), ("WEEKLY", "Weekly"), ("MONTHLY", "Monthly")],
        required=True,
    )

    def validate(self, data):
        user = self.context["request"].user

        # 🔴 CRITICAL SECURITY CHECK: Prevent banned/inactive users
        if hasattr(user, "is_banned") and user.is_banned:
            raise serializers.ValidationError(
                {"detail": "Your account has been banned. Please contact support."}
            )

        if not user.is_active:
            raise serializers.ValidationError(
                {"detail": "Your account is inactive. Please contact support."}
            )

        # Ensure end_date is in the future
        if data["end_date"] < timezone.now().date():
            raise serializers.ValidationError(
                {"end_date": "End date must be in the future"}
            )

        # Validate that monthly payment is reasonable compared to target
        target_amount = data.get("target_amount")
        monthly_payment = data.get("monthly_payment")

        if target_amount and monthly_payment:
            if monthly_payment > target_amount:
                raise serializers.ValidationError(
                    {"monthly_payment": "Monthly payment cannot exceed target amount"}
                )

        return data

    def update(self, instance, validated_data):
        # 🔴 SECURITY: target_amount/end_date drive process_deduction()'s
        # completion check and the 15% bonus's prorated-months calculation.
        # They can't be marked read_only (the create flow needs to accept
        # them from the client), but they - along with monthly_payment/
        # funding_source/frequency, which drive the debit schedule - must
        # never be editable on an *existing* plan via this same serializer.
        # Without this guard, a user could PATCH target_amount down below
        # their already-saved current_amount to fake instant completion,
        # and/or push end_date years out to inflate the bonus multiplier,
        # collecting an arbitrarily large bonus for money they never
        # actually saved for the stated term. No mobile client currently
        # sends PATCH/PUT to this endpoint, so this closes the hole with no
        # behavior change for legitimate use - only "name" and "category"
        # remain editable post-creation.
        locked_fields = {
            "target_amount",
            "end_date",
            "monthly_payment",
            "funding_source",
            "frequency",
        }
        attempted = locked_fields & set(validated_data.keys())
        if attempted:
            raise serializers.ValidationError(
                {
                    field: "This field cannot be changed after the plan is created."
                    for field in attempted
                }
            )
        return super().update(instance, validated_data)

    class Meta:
        model = TargetSavings
        fields = [
            "id",
            "user",
            "name",
            "target_amount",
            "current_amount",
            "start_date",
            "end_date",
            "category",
            "is_active",
            "monthly_payment",
            "frequency",
            "funding_source",
            "progress_percentage",
            "is_completed",
            "next_deduction",
            "last_processed",
        ]
        read_only_fields = [
            "user",
            "current_amount",
            "start_date",
            "progress_percentage",
            "is_active",
            "is_completed",
            "next_deduction",
            "last_processed",
        ]
        extra_kwargs = {
            "end_date": {"required": True},
            "start_date": {"required": False},
        }


from django.utils import timezone
import requests, uuid
from django.core.mail import send_mail


class CardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Card
        fields = (
            "id",
            "authorization_code",
            "bank_name",
            "card_type",
            "card_first6_digits",
            "card_last4_digits",
            "card_owner_name",
            "expiry_month",
            "expiry_year",
            "is_default",
        )
        read_only_fields = ("id", "is_default")

    def to_representation(self, instance):
        """Return None for cards without valid authorization_code so they can be filtered out"""
        if not instance.authorization_code or instance.authorization_code == "":
            return None

        return super().to_representation(instance)

    # def create(self, validated_data):
    #     unique_reference = str(uuid.uuid4())
    #     user = self.context["request"].user
    #     pin = validated_data.pop("pin")
    #     expiry_date = validated_data.pop(
    #         "expiry_date"
    #     )  # Get the expiry_date as a string
    #     # Parse the expiry_date in MM/YY format
    #     expiry_month, expiry_year = expiry_date.split("/")
    #     expiry_date = f"{expiry_month}/{expiry_year}"  # Convert to a valid date format

    #     # Verify the card with Paystack
    #     paystack_secret_key = os.environ.get(
    #         "PAYSTACK_KEY_LIVE",
    #         default="  ",
    #     )
    #     card_number = validated_data["card_number"]
    #     cvv = validated_data["cvv"]
    #     validated_data["expiry_date"] = expiry_date  # Add this line
    #     validated_data["pin"] = pin

    #     paystack_url = "https://api.paystack.co/charge"
    #     payload = {
    #         "card": {
    #             "number": card_number,
    #             "cvv": cvv,
    #             "expiry_month": expiry_month,
    #             "expiry_year": expiry_year,
    #         },
    #         "email": user.email,
    #         "amount": 50 * 100,  # Amount in kobo (N50)
    #         "reference": unique_reference,  # You need to generate a unique reference
    #     }
    #     headers = {
    #         "Authorization": f"Bearer {paystack_secret_key}",
    #         "Content-Type": "application/json",
    #     }

    #     print("Payload:", payload)
    #     print("Headers:", headers)
    #     print("User email:", user.email)

    #     response = requests.post(paystack_url, json=payload, headers=headers)
    #     paystack_response = response.json()
    #     print(paystack_response)

    #     if paystack_response.get("status"):
    #         validated_data["user"] = user
    #         card = Card.objects.create(**validated_data)

    #         subject = "New Card Added Successfully"
    #         message = f"Well done {user.first_name},\n\nYour card has been successfully added to your account. \n\nKeep growing your funds.🥂\n\nMyFund"
    #         from_email = "MyFund <info@mg.myfundmobile.com>"
    #         recipient_list = [user.email]

    #         send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    #         return {
    #             "id": card.id,
    #             "bank_name": card.bank_name,
    #             "card_number": card.card_number,
    #             "expiry_date": expiry_date,  # Return the parsed expiry_date
    #             "cvv": card.cvv,
    #             "pin": card.pin,
    #             "is_default": card.is_default,
    #             "reference": paystack_response.get("data", {}).get("reference"),
    #         }

    #     else:
    #         print(
    #             "Paystack API Error Response:", paystack_response
    #         )  # Add this line for debugging
    #         raise serializers.ValidationError(
    #             "Failed to verify card and process the payment."
    #         )


from .models import Transaction, WithdrawalsRequestToAdmin


class TransactionSerializer(serializers.ModelSerializer):
    # Add is_processed as a SerializerMethodField
    is_processed = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = "__all__"
        extra_kwargs = {"transaction_id": {"read_only": True}}

    def get_is_processed(self, obj):
        # Check if this transaction has a corresponding withdrawal request
        try:
            withdrawal = WithdrawalsRequestToAdmin.objects.get(
                transaction_id=obj.transaction_id
            )
            return withdrawal.is_processed
        except WithdrawalsRequestToAdmin.DoesNotExist:
            # If no withdrawal request, it's not a scheduled withdrawal
            return True  # Or False depending on your logic


class QuickSaveSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    card_id = serializers.IntegerField()


from .models import AutoSave


class AutoSaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutoSave
        fields = "__all__"


class QuickInvestSerializer(serializers.Serializer):
    card_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)


class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = "__all__"


from .models import Property


class BuyPropertySerializer(serializers.Serializer):
    property = serializers.PrimaryKeyRelatedField(queryset=Property.objects.all())
    num_units = serializers.IntegerField()
    payment_source = serializers.ChoiceField(
        choices=["savings", "investment", "wallet", "saved_cards", "bank_transfer"]
    )


class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = [
            "id",
            "name",
            "description",
            "price",
            "rent_reward",
            "units_available",
            "owner",
        ]


from django.db.models import Sum


# serializers.py
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "id",
            "first_name",
            "profile_picture",
            "email",
            "total_savings_and_investments_this_month",
        ]


from .models import AlertMessage


class AlertMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertMessage
        fields = "__all__"


from rest_framework import serializers
from .models import EmailTemplate


class EmailTemplateSerializer(serializers.ModelSerializer):
    design = serializers.SerializerMethodField()

    class Meta:
        model = EmailTemplate
        fields = [
            "id",
            "title",
            "design",  # JSON (for Unlayer)
            "design_html",  # HTML (for preview/send)
            "last_update",
        ]

    def get_design(self, obj):
        if not obj.design_body:
            return {"body": {}, "counters": {}, "schemaVersion": 1}

        if isinstance(obj.design_body, str):
            try:
                parsed = json.loads(obj.design_body)
                return (
                    parsed
                    if parsed and isinstance(parsed, dict)
                    else {"body": {}, "counters": {}, "schemaVersion": 1}
                )
            except Exception:
                return {"body": {}, "counters": {}, "schemaVersion": 1}
        return obj.design_body


from rest_framework import serializers
from .models import Group
from authentication.models import CustomUser


def _resolve_profile_picture_url(profile_picture):
    """Same resolution rules as UserSerializer.get_profile_picture, factored
    out so GroupSerializer can attach contributor avatars without dragging in
    the full UserSerializer."""
    if isinstance(profile_picture, str):
        if profile_picture and "http" not in profile_picture:
            return f"{settings.MEDIA_URL}{profile_picture}"
        return profile_picture or None

    if profile_picture and hasattr(profile_picture, "url"):
        if "http" not in profile_picture.url:
            return f"{settings.MEDIA_URL}{profile_picture.url}"
        return profile_picture.url

    return None


class GroupSerializer(serializers.ModelSerializer):
    # You may want to serialize user-related fields as well. For example, including the creator's username.
    created_by = serializers.SerializerMethodField()

    def get_created_by(self, obj):
        return obj.created_by.email

    # Customizing `invited_users` to return unique emails instead of the primary key
    invited_users = serializers.SerializerMethodField()

    # Customizing `contributors` to return unique emails instead of the primary key
    contributors = serializers.SerializerMethodField()

    def get_invited_users(self, obj):
        return list(
            set(user.email for user in obj.invited_users.all())
        )  # Get unique emails of invited users

    def get_contributors(self, obj):
        # Returns contributor identity + avatar so clients can render a
        # profile-picture stack instead of a plain headcount.
        seen_emails = set()
        contributors = []
        for user in obj.contributors.all():
            if user.email in seen_emails:
                continue
            seen_emails.add(user.email)
            contributors.append(
                {
                    "email": user.email,
                    "first_name": user.first_name,
                    "profile_picture": _resolve_profile_picture_url(
                        user.profile_picture
                    ),
                }
            )
        return contributors

    # Nest the property details so clients don't need a second round-trip
    property = serializers.SerializerMethodField()

    def get_property(self, obj):
        return PropertySerializer(obj.property).data

    status = serializers.ChoiceField(
        choices=Group.GROUP_STATUS
    )  # Assuming you have defined choices for status
    group_type = serializers.ChoiceField(
        choices=Group.GROUP_TYPE
    )  # Assuming choices are defined for group type
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Group
        fields = [
            "id",
            "property_id",
            "property",
            "created_by",
            "goal_amount",
            "minimum_contribution",
            "total_raised",
            "status",
            "group_type",
            "invited_users",
            "contributors",
            "deadline",
            "created_at",
        ]


# from rest_framework import serializers
from .models import Contribution

# from django.contrib.auth import get_user_model

# User = get_user_model()


class ContributionSerializer(serializers.ModelSerializer):
    # Serializing the user field to return the user's email
    user_email = serializers.SerializerMethodField()

    def get_user_email(self, obj):
        return obj.user.email  # Return user's email

    # Serializing the group field to return the group id or name (can be customized)
    group_id = serializers.SerializerMethodField()

    def get_group_id(self, obj):
        return (
            obj.group.id
        )  # Return group ID (you could customize this to return other group info)

    # Choice fields for payment_status and source
    payment_status = serializers.ChoiceField(choices=Contribution.PAYMENT_STATUS)
    source = serializers.ChoiceField(choices=Contribution.SOURCE_CHOICES)

    # If you want to include the ownership percentage, assuming it exists
    ownership_percentage = serializers.SerializerMethodField()

    def get_ownership_percentage(self, obj):
        if obj.group.total_raised > 0:
            # Calculate the ownership percentage
            return (obj.amount / obj.group.goal_amount) * 100
        return 0.0

    # Created date field
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Contribution
        fields = [
            "id",
            "group_id",
            "user_email",
            "amount",
            "payment_status",
            "source",
            "ownership_percentage",
            "created_at",
        ]


from .models import GroupIncomeEvent, GroupIncomeDistribution


class GroupIncomeEventSerializer(serializers.ModelSerializer):
    property_name = serializers.SerializerMethodField()
    recorded_by_email = serializers.SerializerMethodField()

    def get_property_name(self, obj):
        return obj.group.property.name

    def get_recorded_by_email(self, obj):
        return obj.recorded_by.email if obj.recorded_by else None

    class Meta:
        model = GroupIncomeEvent
        fields = [
            "id",
            "group_id",
            "property_name",
            "recorded_by_email",
            "amount",
            "period_start",
            "period_end",
            "description",
            "status",
            "total_distributed",
            "created_at",
            "completed_at",
        ]


class GroupIncomeDistributionSerializer(serializers.ModelSerializer):
    property_name = serializers.SerializerMethodField()
    group_id = serializers.SerializerMethodField()
    period_start = serializers.DateField(source="income_event.period_start", read_only=True)
    period_end = serializers.DateField(source="income_event.period_end", read_only=True)
    description = serializers.CharField(source="income_event.description", read_only=True)

    def get_property_name(self, obj):
        return obj.income_event.group.property.name

    def get_group_id(self, obj):
        return obj.income_event.group_id

    class Meta:
        model = GroupIncomeDistribution
        fields = [
            "id",
            "income_event",
            "group_id",
            "property_name",
            "period_start",
            "period_end",
            "description",
            "ownership_percentage",
            "amount",
            "status",
            "created_at",
        ]


from .models import SavingsGoal


class SavingsGoalSerializer(serializers.ModelSerializer):

    user = serializers.SerializerMethodField()

    def get_user(self, obj):
        return obj.user.email  # Return user's email

    class Meta:
        model = SavingsGoal
        fields = [
            "id",
            "user",
            "name",
            "target_amount",
            "saved_amount",
            "deadline",
            "auto_debit_enabled",
            "contribution_type",
            "created_at",
        ]


from rest_framework import serializers
from .models import MonthlyFinancialRecord


class MonthlyFinancialRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonthlyFinancialRecord
        fields = ["month", "total_savings", "total_investments"]
        read_only_fields = ["created_at", "updated_at"]


from .models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = [
            "id",
            "notification_type",
            "title",
            "message",
            "is_read",
            "created_at",
            "data",
        ]
        read_only_fields = ["id", "created_at"]


from .models import PushNotifications


class PushNotificationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PushNotifications
        fields = "__all__"


from .models import DailyROIAccrual


class DailyROISerializer(serializers.ModelSerializer):
    class Meta:
        model = DailyROIAccrual
        fields = ["date", "savings_roi", "investment_roi", "total_roi"]


from rest_framework import serializers
from .models import AmbassadorMonthlyReport


class AmbassadorMonthlyReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = AmbassadorMonthlyReport
        fields = "__all__"
        read_only_fields = ("user", "status", "submitted_at")

    def validate_month(self, value):
        if len(value) != 7 or value[4] != "-":
            raise serializers.ValidationError("Month must be in YYYY-MM format.")
        return value

    def validate(self, attrs):
        request = self.context.get("request")
        user = request.user
        month = attrs.get("month")

        if not getattr(user, "is_ambassador", False):
            raise serializers.ValidationError("Only ambassadors can submit reports.")

        already_exists = AmbassadorMonthlyReport.objects.filter(
            user=user,
            month=month,
        ).exists()

        if already_exists:
            raise serializers.ValidationError(
                {
                    "message": f"You have already submitted your ambassador report for {month}."
                }
            )

        return attrs

    def create(self, validated_data):
        request = self.context.get("request")
        validated_data["user"] = request.user

        report = AmbassadorMonthlyReport(**validated_data)
        report.copy_submitted_to_approved_defaults()
        report.recalculate_points()
        report.save()
        return report


from django.utils import timezone
from .models import AmbassadorAttendanceSubmission, CustomUser

from datetime import datetime
from rest_framework import serializers
from .models import AmbassadorAttendanceSubmission, CustomUser


class AmbassadorAttendanceSubmissionSerializer(serializers.Serializer):
    email = serializers.EmailField()
    attendance_date = serializers.DateField(input_formats=["%Y-%m-%d"])
    takeaway = serializers.CharField()
    recommendation = serializers.CharField()

    def validate_email(self, value):
        email = value.strip().lower()

        try:
            user = CustomUser.objects.get(email=email, is_ambassador=True)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError(
                "No ambassador account was found with that email address."
            )

        self.context["attendance_user"] = user
        return email

    def validate(self, attrs):
        user = self.context["attendance_user"]
        attendance_date = attrs["attendance_date"]

        month = attendance_date.strftime("%Y-%m")
        week_key = attendance_date.strftime("%Y-W%U")

        already_submitted = AmbassadorAttendanceSubmission.objects.filter(
            user=user,
            week_key=week_key,
        ).exists()

        if already_submitted:
            raise serializers.ValidationError(
                {
                    "message": "Attendance has already been submitted for this week with this email address."
                }
            )

        attrs["user"] = user
        attrs["week_key"] = week_key
        attrs["month"] = month
        attrs["email"] = attrs["email"].strip().lower()
        return attrs

    def create(self, validated_data):
        return AmbassadorAttendanceSubmission.objects.create(**validated_data)
