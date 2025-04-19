import os

from django.http import JsonResponse
from rest_framework import serializers, status
from django.contrib.auth.models import User
from .models import CustomUser, Message, UserPassword
from django.db import transaction
from django.contrib.auth.hashers import make_password
import logging

logger = logging.getLogger(__name__)


class SignupSerializer(serializers.ModelSerializer):
    referral = serializers.CharField(
        max_length=40, required=False
    )  # Allow referral code to be optional
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
            # Create the user without password field
            user = CustomUser.objects.create(**validated_data)

            # Save password in related UserPassword model
            user_password, created = UserPassword.objects.get_or_create(
                user=user, defaults={"password": make_password(password)}
            )
            user.save()

        if referral_code:
            try:
                referrer = CustomUser.objects.get(email=referral_code)
                user.referral = referrer
                user.save()
                logger.info("Referral applied successfully")
            except CustomUser.DoesNotExist:
                logger.warning(f"Invalid referral code: {referral_code}")

        return user


class ConfirmOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)  # Assuming OTP is a 6-digit string


from django.conf import settings  # Import settings to get the MEDIA_URL


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    is_confirmed = serializers.BooleanField(read_only=True)
    profile_picture = serializers.SerializerMethodField()
    date_joined = serializers.DateTimeField(format="%d %b. %Y   |   %I:%M%p")
    is_subscribed = serializers.BooleanField(read_only=True)

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
            "is_hired_referrer",
            "is_ambassador",
            "autosave_enabled",
            "autoinvest_enabled",
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

    def create(self, validated_data):
        password = validated_data.pop("password")

        # Create the user instance first
        user = CustomUser.objects.create(**validated_data)

        # Create the password record manually if it doesn't exist
        if not hasattr(user, "password_record"):
            password_record = UserPassword.objects.create(user=user, password=password)
            user.password_record = password_record
            user.save()
        else:
            user.password_record.set_password(password)
            user.password_record.save()

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


from .models import BankAccount, Card
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated


class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = "__all__"  # Or list the specific fields you want to include


class AccountBalancesSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["savings", "investment", "properties", "wallet"]


from django.utils import timezone
import requests, uuid
from django.core.mail import send_mail


class CardSerializer(serializers.ModelSerializer):
    expiry_date = serializers.CharField(
        max_length=5
    )  # Update the field to a CharField for MM/YY input

    class Meta:
        model = Card
        fields = (
            "id",
            "bank_name",
            "card_number",
            "expiry_date",
            "cvv",
            "pin",
            "is_default",
        )
        read_only_fields = ("id", "is_default")

    def create(self, validated_data):
        unique_reference = str(uuid.uuid4())
        user = self.context["request"].user
        pin = validated_data.pop("pin")
        expiry_date = validated_data.pop(
            "expiry_date"
        )  # Get the expiry_date as a string
        # Parse the expiry_date in MM/YY format
        expiry_month, expiry_year = expiry_date.split("/")
        expiry_date = f"{expiry_month}/{expiry_year}"  # Convert to a valid date format

        # Verify the card with Paystack
        paystack_secret_key = os.environ.get(
            "PAYSTACK_KEY_LIVE",
            default="  ",
        )
        card_number = validated_data["card_number"]
        cvv = validated_data["cvv"]
        validated_data["expiry_date"] = expiry_date  # Add this line
        validated_data["pin"] = pin

        paystack_url = "https://api.paystack.co/charge"
        payload = {
            "card": {
                "number": card_number,
                "cvv": cvv,
                "expiry_month": expiry_month,
                "expiry_year": expiry_year,
            },
            "email": user.email,
            "amount": 50 * 100,  # Amount in kobo (N50)
            "reference": unique_reference,  # You need to generate a unique reference
        }
        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }

        print("Payload:", payload)
        print("Headers:", headers)
        print("User email:", user.email)

        response = requests.post(paystack_url, json=payload, headers=headers)
        paystack_response = response.json()
        print(paystack_response)

        if paystack_response.get("status"):
            validated_data["user"] = user
            card = Card.objects.create(**validated_data)

            subject = "New Card Added Successfully"
            message = f"Well done {user.first_name},\n\nYour card has been successfully added to your account. \n\nKeep growing your funds.🥂\n\nMyFund"
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            return {
                "id": card.id,
                "bank_name": card.bank_name,
                "card_number": card.card_number,
                "expiry_date": expiry_date,  # Return the parsed expiry_date
                "cvv": card.cvv,
                "pin": card.pin,
                "is_default": card.is_default,
                "reference": paystack_response.get("data", {}).get("reference"),
            }

        else:
            print(
                "Paystack API Error Response:", paystack_response
            )  # Add this line for debugging
            raise serializers.ValidationError(
                "Failed to verify card and process the payment."
            )


from .models import Transaction


class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = "__all__"


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
        fields = ['id', 'name', 'description', 'price', 'rent_reward', 'units_available', 'owner']


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
    class Meta:
        model = EmailTemplate
        fields = "__all__"


from rest_framework import serializers
from .models import Group
from authentication.models import CustomUser


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
        return list(
            set(user.email for user in obj.contributors.all())
        )  # Get unique emails of contributors

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
