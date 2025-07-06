from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.utils import timezone
import random
import string
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from django.db.models import Sum
from django.contrib.auth.hashers import make_password, check_password
from django.db import transaction
import logging
from django.db.models import F

logger = logging.getLogger(__name__)


def default_notification_preferences():
    return {
        "transaction_credits": True,
        "transaction_debits": True,
        "system_messages": True,
        "admin_messages": True,
        "pending_transactions": True,
    }


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        user.date_joined = timezone.now()

        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


import uuid
from datetime import date
from decimal import Decimal


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    referral_reward_granted = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    reset_token = models.CharField(max_length=64, null=True, blank=True)
    reset_token_expires = models.DateTimeField(null=True, blank=True)
    profile_picture = models.CharField(max_length=200, null=True, blank=True)
    is_confirmed = models.BooleanField(default=False)
    is_subscribed = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True, db_index=True)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    referral = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    pending_referral_reward = models.DecimalField(
        max_digits=10, decimal_places=2, default=0
    )

    how_did_you_hear = models.CharField(
        max_length=50,
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

    myfund_pin = models.BinaryField(null=True, blank=True)

    preferred_asset = models.CharField(max_length=50, blank=True, null=True)
    savings_goal_amount = models.DecimalField(
        max_digits=11, decimal_places=2, blank=True, null=True
    )
    time_period = models.PositiveIntegerField(blank=True, null=True)

    bank_accounts = models.ManyToManyField(
        "BankAccount", related_name="owners", blank=True
    )
    cards = models.ManyToManyField("Card", related_name="owners", blank=True)

    savings = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    investment = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    properties = models.PositiveIntegerField(default=0)
    wallet = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    savings_and_investments = models.DecimalField(
        max_digits=11, decimal_places=2, default=0
    )
    total_savings_and_investments_this_month = models.DecimalField(
        max_digits=11, decimal_places=2, default=0
    )

    top_saver_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, default=0
    )

    autosave_enabled = models.BooleanField(default=False)  # Add this field
    autoinvest_enabled = models.BooleanField(default=False)  # Add this field

    is_first_time_signup = models.BooleanField(default=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    is_hired_referrer = models.BooleanField(default=False)
    is_ambassador = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name", "phone_number"]

    # Push notifications-related fields
    expo_push_tokens = models.JSONField(default=list)
    notification_preferences = models.JSONField(
        default=default_notification_preferences
    )

    # KYC-related fields
    gender = models.CharField(
        max_length=10,
        choices=[("Male", "Male"), ("Female", "Female"), ("Non-binary", "Non-binary")],
        default="Choose",
    )
    relationship_status = models.CharField(
        max_length=20,
        choices=[
            ("Single", "Single"),
            ("Married", "Married"),
            ("Divorced", "Divorced"),
            ("Separated", "Separated"),
            ("Remarried", "Remarried"),
            ("Widowed", "Widowed"),
            ("Others", "Others"),
        ],
        default="Choose",
    )
    employment_status = models.CharField(
        max_length=20,
        choices=[
            ("Unemployed", "Unemployed"),
            ("Employed", "Employed"),
            ("Self-employed", "Self-employed"),
            ("Business", "Business"),
            ("Retired", "Retired"),
            ("Student", "Student"),
            ("Others", "Others"),
        ],
        default="Choose",
    )
    yearly_income = models.CharField(
        max_length=30,
        choices=[
            ("Less than N200000", "Less than N200000"),
            ("N200001 - N500000", "N200001 - N500000"),
            ("N500001 - N1 million", "N500001 - N1 million"),
            ("N1 million - N5 million", "N1 million - N5 million"),
            ("N5 million - N10 million", "N5 million - N10 million"),
            ("N10 million - N20 million", "N10 million - N20 million"),
            ("Above N20 million", "Above N20 million"),
        ],
        default="Choose",
    )
    date_of_birth = models.DateField(default=date(1900, 1, 1))
    address = models.TextField(default="Enter Address")
    mothers_maiden_name = models.CharField(max_length=100, default="Enter Name")
    identification_type = models.CharField(
        max_length=50,
        choices=[
            ("International Passport", "International Passport"),
            ("Driver's License", "Driver's License"),
            ("National ID Card (NIN)", "National ID Card (NIN)"),
            ("Permanent Voter's Card", "Permanent Voter's Card"),
            ("Bank Verification Number (BVN)", "Bank Verification Number (BVN)"),
            ("Others", "Others"),
        ],
        default="Choose",
    )
    id_upload = models.ImageField(
        upload_to="kyc_documents/", default="kyc_documents/placeholder.png"
    )
    next_of_kin_name = models.CharField(max_length=100, default="Enter Name")
    relationship_with_next_of_kin = models.CharField(
        max_length=20,
        choices=[
            ("Brother", "Brother"),
            ("Sister", "Sister"),
            ("Spouse", "Spouse"),
            ("Father", "Father"),
            ("Mother", "Mother"),
            ("Daughter", "Daughter"),
            ("Son", "Son"),
            ("Friend", "Friend"),
            ("Relative", "Relative"),
            ("Others", "Others"),
        ],
        default="Choose",
    )
    next_of_kin_phone_number = models.CharField(max_length=15, default="Enter Number")
    state = models.CharField(
        max_length=100,
        choices=[
            (state, state)
            for state in [
                "Abia",
                "Adamawa",
                "Akwa Ibom",
                "Anambra",
                "Bauchi",
                "Bayelsa",
                "Benue",
                "Borno",
                "Cross River",
                "Delta",
                "Ebonyi",
                "Edo",
                "Ekiti",
                "Enugu",
                "Gombe",
                "Imo",
                "Jigawa",
                "Kaduna",
                "Kano",
                "Katsina",
                "Kebbi",
                "Kogi",
                "Kwara",
                "Lagos",
                "Nasarawa",
                "Niger",
                "Ogun",
                "Ondo",
                "Osun",
                "Oyo",
                "Plateau",
                "Rivers",
                "Sokoto",
                "Taraba",
                "Yobe",
                "Zamfara",
            ]
        ],
        default="Choose",
    )
    country = models.CharField(
        max_length=100,
        choices=[
            (country, country)
            for country in [
                "Afghanistan",
                "Albania",
                "Algeria",
                "Andorra",
                "Angola",
                "Antigua and Barbuda",
                "Argentina",
                "Armenia",
                "Australia",
                "Austria",
                "Azerbaijan",
                "Bahamas",
                "Bahrain",
                "Bangladesh",
                "Barbados",
                "Belarus",
                "Belgium",
                "Belize",
                "Benin",
                "Bhutan",
                "Bolivia",
                "Bosnia and Herzegovina",
                "Botswana",
                "Brazil",
                "Brunei",
                "Bulgaria",
                "Burkina Faso",
                "Burundi",
                "Cabo Verde",
                "Cambodia",
                "Cameroon",
                "Canada",
                "Central African Republic",
                "Chad",
                "Chile",
                "China",
                "Colombia",
                "Comoros",
                "Congo",
                "Costa Rica",
                "Croatia",
                "Cuba",
                "Cyprus",
                "Czech Republic",
                "Democratic Republic of the Congo",
                "Denmark",
                "Djibouti",
                "Dominica",
                "Dominican Republic",
                "Ecuador",
                "Egypt",
                "El Salvador",
                "Equatorial Guinea",
                "Eritrea",
                "Estonia",
                "Eswatini",
                "Ethiopia",
                "Fiji",
                "Finland",
                "France",
                "Gabon",
                "Gambia",
                "Georgia",
                "Germany",
                "Ghana",
                "Greece",
                "Grenada",
                "Guatemala",
                "Guinea",
                "Guinea-Bissau",
                "Guyana",
                "Haiti",
                "Honduras",
                "Hungary",
                "Iceland",
                "India",
                "Indonesia",
                "Iran",
                "Iraq",
                "Ireland",
                "Israel",
                "Italy",
                "Ivory Coast",
                "Jamaica",
                "Japan",
                "Jordan",
                "Kazakhstan",
                "Kenya",
                "Kiribati",
                "Korea, North",
                "Korea, South",
                "Kuwait",
                "Kyrgyzstan",
                "Laos",
                "Latvia",
                "Lebanon",
                "Lesotho",
                "Liberia",
                "Libya",
                "Liechtenstein",
                "Lithuania",
                "Luxembourg",
                "Madagascar",
                "Malawi",
                "Malaysia",
                "Maldives",
                "Mali",
                "Malta",
                "Marshall Islands",
                "Mauritania",
                "Mauritius",
                "Mexico",
                "Micronesia",
                "Moldova",
                "Monaco",
                "Mongolia",
                "Montenegro",
                "Morocco",
                "Mozambique",
                "Myanmar",
                "Namibia",
                "Nauru",
                "Nepal",
                "Netherlands",
                "New Zealand",
                "Nicaragua",
                "Niger",
                "Nigeria",
                "North Macedonia",
                "Norway",
                "Oman",
                "Pakistan",
                "Palau",
                "Panama",
                "Papua New Guinea",
                "Paraguay",
                "Peru",
                "Philippines",
                "Poland",
                "Portugal",
                "Qatar",
                "Romania",
                "Russia",
                "Rwanda",
                "Saint Kitts and Nevis",
                "Saint Lucia",
                "Saint Vincent and the Grenadines",
                "Samoa",
                "San Marino",
                "Sao Tome and Principe",
                "Saudi Arabia",
                "Senegal",
                "Serbia",
                "Seychelles",
                "Sierra Leone",
                "Singapore",
                "Slovakia",
                "Slovenia",
                "Solomon Islands",
                "Somalia",
                "South Africa",
                "South Sudan",
                "Spain",
                "Sri Lanka",
                "Sudan",
                "Suriname",
                "Sweden",
                "Switzerland",
                "Syria",
                "Taiwan",
                "Tajikistan",
                "Tanzania",
                "Thailand",
                "Timor-Leste",
                "Togo",
                "Tonga",
                "Trinidad and Tobago",
                "Tunisia",
                "Turkey",
                "Turkmenistan",
                "Tuvalu",
                "Uganda",
                "Ukraine",
                "United Arab Emirates",
                "United Kingdom",
                "United States",
                "Uruguay",
                "Uzbekistan",
                "Vanuatu",
                "Vatican City",
                "Venezuela",
                "Vietnam",
                "Yemen",
                "Zambia",
                "Zimbabwe",
            ]
        ],
        default="Nigeria",
    )

    # KYC status
    kyc_updated = models.BooleanField(default=False)
    kyc_status = models.CharField(max_length=20, default="Not yet started")
    admin_approval_status = models.CharField(max_length=20, default="Not yet started")

    notification_preferences = models.JSONField(default=dict, null=True, blank=True)

    password_record = models.OneToOneField(
        "UserPassword",
        on_delete=models.CASCADE,
        related_name="custom_user",
        null=True,
        blank=True,
    )
    password = None

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        # Update the savings_and_investments field
        self.savings_and_investments = Decimal(str(self.savings)) + Decimal(
            str(self.investment)
        )

        if self.profile_picture:
            self.profile_picture = self.profile_picture.replace(
                "https://myfund.onrender.com", "", 1
            )

        super().save(*args, **kwargs)

    @property
    def myfund_pin_encrypted(self):
        return self.myfund_pin

    def generate_reset_token(self):
        token = "".join(random.choices(string.ascii_letters + string.digits, k=64))
        self.reset_token = token
        self.reset_token_expires = timezone.now() + timezone.timedelta(hours=1)
        self.save()

    def send_password_reset_email(self):
        subject = "Password Reset for MyFund"
        reset_url = (
            "https://tolulopeahmed.github.io/password-reset-confirmation/?token="
            + self.reset_token
        )
        context = {
            "first_name": self.first_name,
            "reset_url": reset_url,
        }

        text_message = strip_tags(render_to_string("password_reset_email.txt", context))
        html_message = render_to_string("password_reset_email.html", context)

        from_email = settings.EMAIL_HOST_USER
        recipient_list = [self.email]

        msg = EmailMultiAlternatives(subject, text_message, from_email, recipient_list)
        msg.attach_alternative(html_message, "text/html")
        msg.send()

    def confirm_referral_rewards(self, is_referrer):
        if self.referral and not self.referral_reward_granted:
            # Determine the savings threshold based on whether referrer is an ambassador
            savings_threshold = 10000 if self.referral.is_ambassador else 20000
            investment_threshold = 100000  # Keep investment threshold the same

            # Check if savings or investment has crossed the threshold for the first time
            first_time_savings_threshold = self.savings >= savings_threshold
            first_time_investment_threshold = self.investment >= investment_threshold

            if first_time_savings_threshold or first_time_investment_threshold:
                # Mark referral reward as granted to prevent duplicate credits
                self.referral_reward_granted = True
                self.save(update_fields=["referral_reward_granted"])

                # Update referred user's pending transaction to confirmed
                referred_transaction = Transaction.objects.filter(
                    user=self, transaction_type="credit", status="pending"
                ).first()

                if referred_transaction:
                    referred_transaction.status = "confirmed"
                    referred_transaction.description = "Referral Reward"
                    referred_transaction.save()

                    # Ensure wallet and transaction amounts match correctly
                    self.wallet += referred_transaction.amount
                    self.pending_referral_reward -= referred_transaction.amount
                    self.save(update_fields=["wallet", "pending_referral_reward"])

                # Update referrer's pending transaction to confirmed
                referrer_transaction = Transaction.objects.filter(
                    user=self.referral,
                    referral_email=self.email,
                    transaction_type="credit",
                    status="pending",
                ).first()

                if referrer_transaction:
                    referrer_transaction.status = "confirmed"
                    referrer_transaction.description = "Referral Reward"
                    referrer_transaction.save()

                    # Ensure wallet and transaction amounts match correctly
                    self.referral.wallet += referrer_transaction.amount
                    self.referral.pending_referral_reward -= referrer_transaction.amount
                    self.referral.save(
                        update_fields=["wallet", "pending_referral_reward"]
                    )

                # Send confirmation emails
                self.send_confirmation_email(self, is_referrer=False)
                self.send_confirmation_email(self.referral, is_referrer=True)

                logger.info(
                    f"Referral rewards confirmed for {self.email} and {self.referral.email}"
                )

    def send_confirmation_email(self, user, is_referrer):
        if is_referrer:
            ambassador_note = (
                "\n\nP.S. As our valued Ambassador, you qualified for early referral rewards. Keep up the great work!"
                if user.is_ambassador
                else ""
            )
            subject = f"Congrats!🎊🥂 Referral Reward for {self.first_name} Confirmed!"
            message = (
                f"Congratulations {user.first_name},\n\n"
                f"You have received a referral reward of ₦500.00 in your wallet for referring {self.first_name}."
                f"{ambassador_note}"
                f"\n\nThank you for using MyFund and referring others!"
                f"\n\nKeep growing your funds.🥂"
                f"\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            )
        else:
            subject = f"Congrats!🎊🥂 Referral Reward Confirmed!"
            message = (
                f"Congratulations {self.first_name}, \n\n"
                f"You have received a referral reward of ₦500.00 in your wallet thanks to your referral."
                f"\n\nThank you for using MyFund!"
                f"\n\nKeep growing your funds.🥂"
                f"\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            )

        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    def calculate_user_percentage_to_top_saver(self):
        top_saver = (
            CustomUser.objects.filter(
                total_savings_and_investments_this_month__gt=0  # Only consider users with savings this month
            )
            .order_by("-total_savings_and_investments_this_month")
            .first()
        )

        if top_saver and top_saver.total_savings_and_investments_this_month > 0:
            user_percentage = (
                self.total_savings_and_investments_this_month
                / top_saver.total_savings_and_investments_this_month
            ) * 100
        else:
            user_percentage = 0
        return user_percentage

    def update_total_savings_and_investment_this_month(self):
        now = timezone.now()
        current_month = now.month
        current_year = now.year

        # Use first_name or email instead of username
        print(f"Calculating savings for User: {self.first_name} (ID: {self.id})")

        try:
            # Filter confirmed credit transactions for the current month
            savings_and_investment_credits = Transaction.objects.filter(
                user=self,
                transaction_type="credit",
                status="confirmed",
                date__month=current_month,
                date__year=current_year,
            )

            print(f"Total Transactions Found: {savings_and_investment_credits.count()}")

            # Sum the credit amounts
            total_credits = savings_and_investment_credits.aggregate(
                total_credits=Sum("amount")
            )["total_credits"]

            print(f"Total Credits Calculated: {total_credits}")

            if total_credits is not None:
                self.total_savings_and_investments_this_month = total_credits
            else:
                self.total_savings_and_investments_this_month = 0

            self.save()
            print(
                f"User {self.first_name} - Updated total savings: {self.total_savings_and_investments_this_month}"
            )
        except Exception as e:
            print(f"Error calculating savings for {self.first_name}: {e}")

    def set_password(self, raw_password):
        with transaction.atomic():
            if self.password_record:
                self.password_record.password = make_password(raw_password)
                self.password_record.save()
            else:
                self.password_record, created = UserPassword.objects.get_or_create(
                    user=self, defaults={"password": make_password(raw_password)}
                )

    def check_password(self, raw_password):
        """Check the provided password with stored password."""
        if self.password_record:
            return self.password_record.check_password(raw_password)
        return False


class MonthlySavings(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="monthly_savings"
    )
    month = models.PositiveIntegerField()
    year = models.PositiveIntegerField()
    savings = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    investment = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ["user", "month", "year"]


# models.py
from django.db import models
from django.utils import timezone


class TopSaverHistory(models.Model):
    month = models.PositiveIntegerField()
    year = models.PositiveIntegerField()
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    total_savings = models.DecimalField(max_digits=10, decimal_places=2)
    rank = models.PositiveIntegerField()

    def __str__(self):
        return (
            f"Top Saver {self.rank} - {self.user.first_name} ({self.month}/{self.year})"
        )

    class Meta:
        unique_together = ("month", "year", "rank")


class PasswordReset(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)


class CustomUserMetrics(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    total_savings_and_investments = models.DecimalField(max_digits=10, decimal_places=2)
    total_wallet = models.DecimalField(max_digits=10, decimal_places=2)
    total_active_users = models.IntegerField()
    total_dormant_users = models.IntegerField()
    pending_kyc_approvals = models.IntegerField()
    total_savings_and_investments_this_month = models.DecimalField(
        max_digits=10, decimal_places=2
    )


from django.db import models
from django.contrib.auth import get_user_model


class GPTMessage(models.Model):
    sender = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["timestamp"]

    def __str__(self):
        return f"From {self.sender}: {self.content}"


class Message(models.Model):
    sender = models.ForeignKey(
        get_user_model(), on_delete=models.CASCADE, related_name="sent_messages"
    )
    recipient = models.ForeignKey(
        get_user_model(), on_delete=models.CASCADE, related_name="received_messages"
    )
    content = models.TextField()
    image = models.ImageField(
        upload_to="chat_images/", null=True, blank=True
    )  # Add this line for the image field
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["timestamp"]

    def __str__(self):
        return f"From {self.sender} to {self.recipient}: {self.content}"


from django.contrib.auth import get_user_model
from django.contrib.auth.models import User


class BankAccount(models.Model):
    user = models.ForeignKey(
        get_user_model(), on_delete=models.CASCADE, related_name="owned_bank_accounts"
    )  # Change related_name here
    bank_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=20, unique=True)
    account_name = models.CharField(max_length=100, default="Default Account Name")
    is_default = models.BooleanField(default=False)

    bank_code = models.CharField(max_length=10, default="")  # Add a default value
    paystack_recipient_code = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.user} - {self.user.email} - {self.bank_name} ({self.account_number})"


class Card(models.Model):
    user = models.ForeignKey(
        get_user_model(), on_delete=models.CASCADE, related_name="owned_cards"
    )
    bank_name = models.CharField(max_length=100)
    card_number = models.CharField(max_length=19)
    expiry_date = models.CharField(max_length=5)
    cvv = models.CharField(max_length=4)
    pin = models.CharField(max_length=4, default="0000")  # Add the PIN field
    is_default = models.BooleanField(default=False)

    def __str__(self):
        card_last_digits = self.card_number[-4:]
        return (
            f"{self.user.email}'s Card ending in {card_last_digits} ({self.bank_name})"
        )


# Update the models to use settings.AUTH_USER_MODEL
class AccountBalance(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    savings = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    investment = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    properties = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    wallet = models.DecimalField(max_digits=10, decimal_places=2, default=0)


from django.core.validators import RegexValidator


class TargetSavings(models.Model):
    CATEGORY_CHOICES = [
        ("RENT_ACCOMMODATION", "Rent & Accommodation"),
        ("EDUCATION", "Education"),
        ("PHONE", "Phone/Gadget"),
        ("CAR", "Car"),
        ("BUSINESS", "Business"),
        ("JAPA", "Japa"),
        ("EMERGENCY", "Emergency"),
        ("TRAVEL", "Travel"),
        ("FEES_DEBT", "Fees/Debt"),
        ("INVESTMENT", "Investment"),
        ("GADGETS", "Gadgets"),
        ("BIRTHDAY", "Birthday"),
        ("ANNIVERSARY", "Anniversary"),
        ("OTHERS", "Others"),
    ]

    FREQUENCY_CHOICES = [
        ("DAILY", "Daily"),
        ("WEEKLY", "Weekly"),
        ("MONTHLY", "Monthly"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="target_savings",
    )
    name = models.CharField(max_length=100)
    target_amount = models.DecimalField(max_digits=12, decimal_places=2)
    current_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField()
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        validators=[
            RegexValidator(
                regex="^[A-Z_]+$", message="Category must be uppercase with underscores"
            )
        ],
    )
    is_active = models.BooleanField(default=True)
    monthly_payment = models.DecimalField(
        max_digits=12, decimal_places=2, blank=True, null=True
    )

    funding_source = models.CharField(
        max_length=20,
        choices=[
            ("SAVINGS", "Savings"),
            ("INVESTMENT", "Investment"),
            ("CARD", "Card"),
        ],
        default="SAVINGS",
    )
    payment_method = models.CharField(
        max_length=50, blank=True, null=True
    )  # Store card ID if used
    frequency = models.CharField(
        max_length=10, choices=FREQUENCY_CHOICES, default="MONTHLY"
    )
    next_deduction = models.DateTimeField(null=True, blank=True)
    cancellation_charge = models.DecimalField(
        max_digits=12, decimal_places=2, default=0
    )
    is_cancelled = models.BooleanField(default=False)

    @property
    def progress_percentage(self):
        if self.target_amount == 0:
            return 0
        return (self.current_amount / self.target_amount) * 100

    def __str__(self):
        return f"{self.user.email}'s {self.name} Target"


class Transaction(models.Model):
    TRANSACTION_TYPES = (
        ("credit", "Credit"),
        ("debit", "Debit"),
    )

    STATUS_TYPES = (
        ("pending", "Pending"),
        ("confirmed", "Confirmed"),
        ("failed", "Failed"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="user_transactions",
    )

    referral = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="referral_transactions",
    )

    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    status = models.CharField(
        max_length=20, choices=STATUS_TYPES, default="pending", db_index=True
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateTimeField(auto_now_add=True)
    time = models.TimeField(auto_now_add=True)
    description = models.CharField(
        max_length=255, default="No description available", db_index=True
    )
    transaction_id = models.CharField(
        max_length=255,
        unique=True,
        default=uuid.uuid4,
        editable=False,
        db_index=True,
    )
    paystack_auth_code = models.CharField(
        max_length=255,
        editable=False,
        default='',
        blank=True,
    )
    paystack_access_code = models.CharField(
        max_length=255,
        null=True,
        editable=False,
        db_index=True,
    )
    paystack_auth_code = models.CharField(
        max_length=255, null=True, blank=True, default=None, editable=False
    )

    service_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    referral_email = models.EmailField(
        max_length=255, blank=True, null=True, db_index=True
    )
    target_savings = models.ForeignKey(
        TargetSavings, on_delete=models.SET_NULL, null=True, blank=True
    )

    def save(self, *args, **kwargs):
        self.total_amount = self.amount + self.service_charge
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} - {self.status} - {self.paystack_auth_code} - {self.date}"


class PushNotifications(models.Model):
    NOTIFICATION_TYPES = (
        ("CREDIT", "Credit Transaction"),
        ("DEBIT", "Debit Transaction"),
        ("SYSTEM", "System Notification"),
        ("ADMIN", "Admin Message"),
        ("GROUP", "Group Contribution"),
        ("PENDING", "Pending Transaction"),
    )

    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="push_notifications"
    )
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} - {self.user.email}"


class AutoSave(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    card = models.ForeignKey(Card, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    frequency = models.CharField(
        max_length=10,
        choices=[
            ("hourly", "Hourly"),
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ],
    )
    active = models.BooleanField(default=True)

    # Paystack subscription details
    paystack_sub_id = models.CharField(max_length=255, null=True, blank=True)
    paystack_sub_code = models.CharField(max_length=255, null=True, blank=True)
    paystack_sub_token = models.CharField(max_length=255, null=True, blank=True)
    paystack_trans_ref = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        user_name = f"{self.user.first_name} ({self.user.email})"
        amount_saved = (
            f"₦{self.amount}" if self.amount is not None else "Amount not available"
        )
        paystack_details = self.get_paystack_details()

        return f"AutoSave for {user_name} - {amount_saved} ({self.frequency}) - {paystack_details}"

    def get_paystack_details(self):
        """Return Paystack subscription details as a dictionary."""
        return (
            {
                "paystack_sub_id": self.paystack_sub_id,
                "paystack_sub_code": self.paystack_sub_code,
                "paystack_sub_token": self.paystack_sub_token,
                "paystack_trans_ref": self.paystack_trans_ref,
            }
            if self.paystack_sub_id
            or self.paystack_sub_code
            or self.paystack_sub_token
            or self.paystack_trans_ref
            else {"message": "No Paystack details"}
        )


class AutoInvest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    card = models.ForeignKey(Card, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    frequency = models.CharField(
        max_length=10,
        choices=[
            ("hourly", "Hourly"),
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ],
    )
    active = models.BooleanField(default=True)

    # Paystack subscription details
    paystack_sub_id = models.CharField(max_length=255, null=True, blank=True)
    paystack_sub_code = models.CharField(max_length=255, null=True, blank=True)
    paystack_sub_token = models.CharField(max_length=255, null=True, blank=True)
    paystack_trans_ref = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        user_name = f"{self.user.first_name} ({self.user.email})"
        amount_invested = (
            f"₦{self.amount}" if self.amount is not None else "Amount not available"
        )
        paystack_details = self.get_paystack_details()

        return f"AutoInvest for {user_name} - {amount_invested} ({self.frequency}) - {paystack_details}"

    def get_paystack_details(self):
        """Return Paystack subscription details as a dictionary."""
        return (
            {
                "paystack_sub_id": self.paystack_sub_id,
                "paystack_sub_code": self.paystack_sub_code,
                "paystack_sub_token": self.paystack_sub_token,
                "paystack_trans_ref": self.paystack_trans_ref,
            }
            if self.paystack_sub_id
            or self.paystack_sub_code
            or self.paystack_sub_token
            or self.paystack_trans_ref
            else {"message": "No Paystack details"}
        )


class Property(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=11, decimal_places=2)
    rent_reward = models.DecimalField(max_digits=11, decimal_places=2)
    units_available = models.PositiveIntegerField()
    owner = models.ForeignKey(
        get_user_model(),
        on_delete=models.SET_NULL,
        null=True,
        related_name="owned_properties",
    )

    def __str__(self):
        return self.name


class AlertMessage(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.TextField()
    date = models.DateTimeField()
    # Add any other fields you need for your alert message

    def __str__(self):
        return self.text


class BankTransferRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    transaction_id = models.CharField(max_length=50, unique=False, default="")


class InvestTransferRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    transaction_id = models.CharField(max_length=10, unique=False, default="")


class WithdrawalsRequestToAdmin(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_id = models.CharField(max_length=50, unique=False, default="")
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    # Add missing fields (from your previous code)
    source_account = models.CharField(max_length=255, default="savings")
    target_bank = models.CharField(max_length=100, default="Palmpay")
    target_account_number = models.CharField(max_length=50, default="8033924595")

    # >>> ADD THESE TWO NEW FIELDS <<<
    withdrawal_type = models.CharField(
        max_length=50, default="immediate"
    )  # e.g., 'immediate' or 'scheduled'
    scheduled_processing_date = models.DateField(
        null=True, blank=True
    )  # Date when scheduled withdrawal should be processed

    def __str__(self):
        return f"Withdrawal request for {self.user.email} - {self.amount}"

    class Meta:
        ordering = ["-created_at"]  # Optional: order by most recent first


class EmailTemplate(models.Model):
    title = models.CharField(max_length=255, unique=True)  # Ensure title is unique
    design_body = models.TextField()
    design_html = models.TextField()
    last_update = models.DateTimeField()

    def __str__(self):
        return self.title


class UserPassword(models.Model):
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name="user_password",
    )
    password = models.CharField(max_length=255)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return f"Password record for {self.user.email}"


from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()


class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ("TRANSACTION", "Transaction"),
        ("MESSAGE", "Message"),
        ("SYSTEM", "System"),
        ("ADMIN", "Admin"),
        ("UPDATE", "App Update"),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="notifications"
    )
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=100)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    data = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.notification_type} notification for {self.user.email}"


class DeviceToken(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="device_tokens"
    )
    token = models.CharField(max_length=255, unique=True)
    device_type = models.CharField(
        max_length=10, choices=[("IOS", "iOS"), ("ANDROID", "Android")]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email}'s {self.device_type} device"


class Group(models.Model):
    GROUP_STATUS = [
        ("active", "Active"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    GROUP_TYPE = [
        ("public", "Public"),
        ("private", "Private"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    property = models.ForeignKey("Property", on_delete=models.CASCADE)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        related_name="created_groups",
    )
    total_raised = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    goal_amount = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    minimum_contribution = models.DecimalField(
        max_digits=11, decimal_places=2, default=0
    )
    status = models.CharField(max_length=10, choices=GROUP_STATUS)
    group_type = models.CharField(max_length=7, choices=GROUP_TYPE)
    invited_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, related_name="invited_groups", blank=True
    )
    contributors = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="contributed_groups",
        through="Contribution",
    )
    deadline = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return (
            f"Group {self.id} for Property {self.property.name} (Status: {self.status})"
        )


class Contribution(models.Model):
    PAYMENT_STATUS = [
        ("Pending", "Pending"),
        ("Confirmed", "Confirmed"),
        ("Failed", "Failed"),
        ("Refunded", "Refunded"),
    ]

    SOURCE_CHOICES = [
        ("Savings", "Savings"),
        ("Investment", "Investment"),
        ("Wallet", "Wallet"),
    ]

    id = models.AutoField(primary_key=True)
    group = models.ForeignKey(
        Group, on_delete=models.CASCADE, related_name="contributions"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="contributions"
    )
    amount = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUS)
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES)
    ownership_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, default=0
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Contribution by {self.user.email} to Group {self.group.id} (Amount: {self.amount}, Source: {self.source}, Ownership: {self.ownership_percentage}%)"


class SavingsGoal(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    target_amount = models.DecimalField(max_digits=10, decimal_places=2)
    saved_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    deadline = models.DateField()
    auto_debit_enabled = models.BooleanField(
        default=False
    )  # Changed to auto_debit_enabled
    contribution_type = models.CharField(
        max_length=50,
        choices=[
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class MonthlyFinancialRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    month = models.DateField()  # Stores first day of each month
    total_savings = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_investments = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "month")
        ordering = ["-month"]

    def __str__(self):
        return f"{self.user.email} - {self.month.strftime('%B %Y')}"
