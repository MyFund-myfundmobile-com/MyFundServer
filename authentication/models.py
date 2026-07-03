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
from django.core.exceptions import ValidationError


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    referral_reward_granted = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    reset_token = models.CharField(max_length=64, null=True, blank=True)
    reset_token_expires = models.DateTimeField(null=True, blank=True)
    profile_picture = models.CharField(max_length=1000, null=True, blank=True)
    is_confirmed = models.BooleanField(default=False)
    referral_reward_confirmed_at = models.DateTimeField(null=True, blank=True)
    is_subscribed = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True, db_index=True)
    is_deleted = models.BooleanField(default=False)
    last_otp_sent_at = models.DateTimeField(null=True, blank=True)
    pin_reset_otp = models.CharField(max_length=6, blank=True, null=True)
    pin_reset_otp_expiry = models.DateTimeField(null=True, blank=True)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    referral = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    pending_referral_reward = models.DecimalField(
        max_digits=10, decimal_places=2, default=0
    )
    last_referral_rank = models.IntegerField(null=True, blank=True)
    last_top_saver_rank = models.PositiveIntegerField(
        null=True, blank=True, help_text="Previous Top Savers ranking position"
    )
    updated_at = models.DateTimeField(auto_now=True)  # 👈 Add this here

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

    savings = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    investment = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    properties = models.PositiveIntegerField(default=0)
    wallet = models.DecimalField(max_digits=11, decimal_places=2, default=0)

    # PAYSTACK DVA
    paystack_customer_code = models.CharField(max_length=255, null=True, blank=True)
    dva_account_number = models.CharField(max_length=20, null=True, blank=True)
    dva_account_name = models.CharField(max_length=255, null=True, blank=True)
    dva_bank_name = models.CharField(max_length=100, null=True, blank=True)
    dva_assigned_at = models.DateTimeField(null=True, blank=True)
    dva_account_id = models.CharField(max_length=50, null=True, blank=True)
    paystack_identified = models.BooleanField(default=False)
    paystack_identification_status = models.CharField(
        max_length=30, null=True, blank=True
    )
    paystack_identification_reason = models.TextField(null=True, blank=True)

    # DIVIDENDS
    pending_roi = models.DecimalField(max_digits=11, decimal_places=2, default=0)
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

    is_active = models.BooleanField(default=True, db_index=True)
    is_banned = models.BooleanField(default=False, db_index=True)
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
    KYC_STATUS_CHOICES = (
        ("not_started", "Not Started"),
        ("submitted", "Submitted (Pending Review)"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    )

    kyc_status = models.CharField(
        max_length=20,
        choices=KYC_STATUS_CHOICES,
        default="not_started",
    )

    kyc_updated = models.BooleanField(default=False)  # keep for backward compatibility
    kyc_rejection_reason = models.TextField(blank=True, null=True)
    kyc_reviewed_at = models.DateTimeField(null=True, blank=True)

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

        if self.profile_picture and "myfund.onrender.com" in self.profile_picture:
            # Legacy URL cleanup: strip old Render domain to get the path,
            # then repoint to ImageKit
            path = self.profile_picture.replace("https://myfund.onrender.com", "")
            self.profile_picture = f"https://ik.imagekit.io/myfundmobile{path}"

        super().save(*args, **kwargs)

    def clean(self):
        super().clean()
        if self.date_of_birth:
            today = date.today()

            # Prevent future dates
            if self.date_of_birth > today:
                raise ValidationError(
                    {"date_of_birth": "Birth date cannot be in the future."}
                )

            # Check minimum age (13+)
            age = (
                today.year
                - self.date_of_birth.year
                - (
                    (today.month, today.day)
                    < (self.date_of_birth.month, self.date_of_birth.day)
                )
            )
            if age < 13:
                raise ValidationError(
                    {"date_of_birth": "Users must be at least 13 years old."}
                )

    def get_daily_savings_roi_rate(self):
        """Calculate daily savings ROI rate (13% per annum)"""
        from decimal import Decimal

        return Decimal("0.13") / Decimal("365")

    def get_daily_investment_roi_rate(self):
        """Calculate daily investment ROI rate (20% per annum)"""
        from decimal import Decimal

        return Decimal("0.20") / Decimal("365")

    def calculate_daily_roi(self, date=None):
        """Calculate ROI for a specific date based on current balances"""
        from django.utils import timezone
        from decimal import Decimal

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

    @property
    def myfund_pin_encrypted(self):
        return self.myfund_pin

    def delete(self, *args, **kwargs):
        self.is_deleted = True
        self.save()

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

    def send_welcome_email(self):
        from authentication.utils import send_generic_email

        """
        Sends the Welcome email to this user.
        Safe to call from confirm_otp background thread.
        """
        subject = f"{self.first_name}, WELCOME TO MyFund! 🥂🎊🔥"
        savings_image_url = "https://drive.google.com/uc?export=view&id=1bOVTTicGZJgUKX2aTm2SAqyX-8qfH41Q"
        logo_url = "https://drive.google.com/uc?export=view&id=1K7sBCm3mgW5jQ1Cfh73LQDZuvGuNFTKw"

        message_html = f"""
        <p>Hi {self.first_name},</p>
        <p>I'm personally welcoming you to the MyFund family.</p>
        <p>By signing up, you've entered the 4th step toward financial freedom,
        <strong>SAVINGS</strong> (click WealthMap on the app for details).</p>
        <p><img src="{savings_image_url}" alt="Savings Step Image" style="display: block; margin: 10px auto; max-width: 100%; height: auto;"></p>
        <p>The app tracks your progress as you save towards buying properties for a lifetime rental (passive) income.</p>
        <p>Once again, you're welcome!</p>
        <br>
    <p style="display: inline-flex; align-items: center; margin: 0;">
        <img src="{logo_url}" alt="Dr Tee"
            style="width: 50px; height: 50px; border-radius: 50%; margin-right: 10px;">
        <span>
            <strong style="font-size: 16px;">Tolulope Ahmed (Dr Tee)</strong><br>
            <span style="font-size: 12px; font-style: italic; color: #555;">
            CEO/Co-founder, MyFund
            </span>
        </span>
        </p>
        """

        try:
            send_generic_email(
                subject=subject,
                message=message_html,
                recipient_list=[self.email],
                from_email="MyFund <info@mg.myfundmobile.com>",
                template="email/email.html",  # <-- add this
            )
            logger.info(f"✅ Welcome email sent to {self.email}")
        except Exception as e:
            logger.warning(f"❌ Welcome email failed for {self.email}: {e}")

    def create_pending_referral_reward(self):
        """
        Creates pending referral reward transactions for new signup,
        sends referral emails and pushes.
        """
        from .utils import send_push_notification, send_generic_email

        # Prevent duplicates
        if Transaction.objects.filter(
            user=self, description="Referral Reward"
        ).exists():
            logger.info(f"Pending referral reward already exists for {self.email}")
            return

        transaction_id = str(uuid.uuid4())[:10]

        # Referred user reward (pending)
        Transaction.objects.create(
            user=self,
            referral_email=self.referral.email if self.referral else None,
            transaction_type="credit",
            status="pending",
            amount=500,
            description="Referral Reward",
            transaction_id=transaction_id,
            total_amount=500,
        )

        self.pending_referral_reward = 500
        self.save(update_fields=["pending_referral_reward"])

        # Referrer reward (pending)
        if not self.referral.is_hired_referrer:
            transaction_id = str(uuid.uuid4())[:10]
            Transaction.objects.create(
                user=self.referral,
                referral_email=self.email,
                transaction_type="credit",
                status="pending",
                amount=500,
                description="Referral Reward",
                transaction_id=transaction_id,
                total_amount=500,
            )

            self.referral.pending_referral_reward = F("pending_referral_reward") + 500
            self.referral.save(update_fields=["pending_referral_reward"])

            # Send email to referrer
            subject = f"{self.referral.first_name}, Your Referral Reward is Pending..."
            message = f"""
            Hi {self.referral.first_name},<br><br>
            Your referral reward of ₦500 is pending. When your friend ({self.email}) makes their first savings/investment, it will be confirmed in your wallet.<br><br>
            Thank you for using MyFund!<br><br>
            Keep growing your funds.🥂<br><br>
            """
            try:
                send_generic_email(
                    subject=subject,
                    message=message,
                    recipient_list=[self.referral.email],
                    from_email="MyFund <info@mg.myfundmobile.com>",
                    template="email/email.html",
                )
            except Exception as e:
                logger.warning(
                    f"⚠️ Referral email to referrer failed for {self.referral.email}: {e}"
                )

        # Send email to referred user
        subject = f"{self.first_name}, Your ₦500 Referral Reward is Pending"
        message = f"""
        Hi {self.first_name},<br><br>
        You have received a welcome referral reward bonus of ₦500 for signing up with a referral email.
        It will be confirmed in your Wallet when you make your first savings.<br><br>
        Thank you for using MyFund!<br><br>
        Keep growing your funds.🥂<br><br>
        """
        try:
            send_generic_email(
                subject=subject,
                message=message,
                recipient_list=[self.email],
                from_email="MyFund <info@mg.myfundmobile.com>",
                template="email/email.html",
            )
        except Exception as e:
            logger.warning(
                f"⚠️ Referral email to referred user failed for {self.email}: {e}"
            )

        # Send push notifications
        try:
            send_push_notification(
                user=self,
                title="₦500 Referral Reward Pending 💰",
                message=f"{self.first_name}, you’ve earned ₦500 referral reward. Complete your first savings to confirm it in your Wallet.",
                data={"type": "referral_pending"},
            )
            send_push_notification(
                user=self.referral,
                title="₦500 Referral Reward Pending 💰",
                message=f"{self.referral.first_name}, your friend, {self.first_name} signed up. ₦500 referral reward pending for you. It'll be confirmed when they make their first savings.",
                data={"type": "referral_pending"},
            )
        except Exception as e:
            logger.warning(f"Referral push failed: {e}")

    def confirm_referral_rewards(self, is_referrer):
        if self.referral and not self.referral_reward_granted:
            current_time = timezone.now()
            is_december_promo = current_time.month == 12 and current_time.year == 2025

            if is_december_promo:
                savings_threshold = 5000
            else:
                if self.referral.is_ambassador:
                    savings_threshold = 10000
                else:
                    savings_threshold = 20000

            investment_threshold = 100000

            qualifies_by_savings = self.savings >= savings_threshold
            qualifies_by_investment = self.investment >= investment_threshold

            if qualifies_by_savings or qualifies_by_investment:
                self.referral_reward_granted = True
                self.referral_reward_confirmed_at = current_time
                self.save(
                    update_fields=[
                        "referral_reward_granted",
                        "referral_reward_confirmed_at",
                    ]
                )

                # Confirm referred user's pending transaction
                referred_transaction = Transaction.objects.filter(
                    user=self,
                    transaction_type="credit",
                    status="pending",
                    description="Referral Reward",
                ).first()

                if referred_transaction:
                    previous_balance = self.wallet
                    new_balance = previous_balance + referred_transaction.amount

                    referred_transaction.status = "confirmed"
                    referred_transaction.description = "Referral Reward"
                    referred_transaction.credited_to = "WALLET"
                    referred_transaction.balance_before = previous_balance
                    referred_transaction.balance_after = new_balance
                    referred_transaction.total_amount = referred_transaction.amount
                    referred_transaction.save(
                        update_fields=[
                            "status",
                            "description",
                            "credited_to",
                            "balance_before",
                            "balance_after",
                            "total_amount",
                        ]
                    )

                    self.wallet = new_balance
                    self.pending_referral_reward -= referred_transaction.amount
                    self.save(update_fields=["wallet", "pending_referral_reward"])

                # Confirm referrer's pending transaction
                referrer_transaction = Transaction.objects.filter(
                    user=self.referral,
                    referral_email=self.email,
                    transaction_type="credit",
                    status="pending",
                    description="Referral Reward",
                ).first()

                if referrer_transaction:
                    previous_balance = self.referral.wallet
                    new_balance = previous_balance + referrer_transaction.amount

                    referrer_transaction.status = "confirmed"
                    referrer_transaction.description = "Referral Reward"
                    referrer_transaction.credited_to = "WALLET"
                    referrer_transaction.balance_before = previous_balance
                    referrer_transaction.balance_after = new_balance
                    referrer_transaction.total_amount = referrer_transaction.amount
                    referrer_transaction.save(
                        update_fields=[
                            "status",
                            "description",
                            "credited_to",
                            "balance_before",
                            "balance_after",
                            "total_amount",
                        ]
                    )

                    self.referral.wallet = new_balance
                    self.referral.pending_referral_reward -= referrer_transaction.amount
                    self.referral.save(
                        update_fields=["wallet", "pending_referral_reward"]
                    )

                from .utils import send_push_notification

                if referred_transaction:
                    send_push_notification(
                        user=self,
                        title="Referral Reward Received! 🎉",
                        message=f"You've got ₦{referred_transaction.amount:,.2f} for signing up on MyFund. Thank you for using MyFund!",
                        data={
                            "amount": str(referred_transaction.amount),
                            "transaction_id": referred_transaction.transaction_id,
                            "type": "Referral",
                            "role": "referred",
                            "status": "confirmed",
                        },
                        notif_type="CREDIT",
                    )

                if referrer_transaction:
                    send_push_notification(
                        user=self.referral,
                        title="Referral Reward Confirmed! 🎊",
                        message=f"You've earned ₦{referrer_transaction.amount:,.2f} for referring {self.first_name} and improved your chances for more rewards. Check the Referral List for your ranking. Keep it up!",
                        data={
                            "amount": str(referrer_transaction.amount),
                            "transaction_id": referrer_transaction.transaction_id,
                            "type": "Referral",
                            "role": "referrer",
                            "status": "confirmed",
                        },
                        notif_type="CREDIT",
                    )

                self.send_confirmation_email(self, is_referrer=False)
                self.send_confirmation_email(self.referral, is_referrer=True)

                logger.info(
                    f"Referral rewards confirmed for {self.email} and {self.referral.email}"
                )

    def send_confirmation_email(self, user, is_referrer):
        current_time = timezone.now()
        is_december_promo = current_time.month == 12 and current_time.year == 2025

        if is_referrer:
            ambassador_note = (
                "\n\nP.S. As our valued Ambassador, you qualified for early referral rewards. Keep up the great work!"
                if user.is_ambassador
                else ""
            )

            december_note = (
                "\n\nP.S. For December Savings Challenge, for early referral rewards. Keep up the great work!"
                if is_december_promo
                else ""
            )

            subject = f"Congrats!🎊🥂 Referral Reward for {self.first_name} Confirmed!"
            message = (
                f"Congratulations {user.first_name},\n\n"
                f"You have received a referral reward of ₦500.00 in your wallet for referring {self.first_name}."
                f"{ambassador_note}"
                f"{december_note}"
                f"\n\nThank you for using MyFund and referring others!"
                f"\n\nKeep growing your funds.🥂"
                f"\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            )
        else:
            december_note = (
                "\n\nP.S. For December Savings Challenge, for early referral rewards. Keep up the great work!"
                if is_december_promo
                else ""
            )

            subject = f"Congrats!🎊🥂 Referral Reward Confirmed!"
            message = (
                f"Congratulations {self.first_name}, \n\n"
                f"You have received a referral reward of ₦500.00 in your wallet thanks to your referral."
                f"{december_note}"
                f"\n\nThank you for using MyFund!"
                f"\n\nKeep growing your funds.🥂"
                f"\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            )

        from authentication.utils import send_generic_email

        try:
            send_generic_email(
                subject=subject,
                message=message,
                recipient_list=[user.email],
                from_email="MyFund <info@mg.myfundmobile.com>",
                template="email/email.html",  # <-- ensures your header/footer template is used
            )
            logger.info(f"✅ Confirmation email sent to {user.email}")
        except Exception as e:
            logger.warning(f"❌ Confirmation email failed for {user.email}: {e}")

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
            # Save the user first if it's new (no primary key yet)
            if not self.pk:
                super().save()

            if self.password_record:
                self.password_record.password = make_password(raw_password)
                self.password_record.save()
            else:
                self.password_record, created = UserPassword.objects.get_or_create(
                    user=self, defaults={"password": make_password(raw_password)}
                )
                # If it already existed, update the password
                if not created:
                    self.password_record.password = make_password(raw_password)
                    self.password_record.save()

    def check_password(self, raw_password):
        """Check the provided password with stored password."""
        if self.password_record:
            return self.password_record.check_password(raw_password)
        return False

    class Meta:
        indexes = [
            models.Index(
                fields=["is_deleted", "date_joined"]
            ),  # ✅ Critical for user queries
            models.Index(
                fields=["is_deleted", "savings", "investment"]
            ),  # ✅ For FUM calculations
            models.Index(fields=["referral_id"]),  # ✅ For referral stats
            models.Index(fields=["is_ambassador"]),  # ✅ For influencer stats
            models.Index(
                fields=["is_active", "is_banned"]
            ),  # ✅ ADDED: Critical for ROI & admin filters
            models.Index(
                fields=["date_joined", "is_deleted"]
            ),  # ✅ ADDED: For admin list queries
            models.Index(
                fields=["referral_id", "date_joined"]
            ),  # ✅ ADDED: For referral queries
        ]


class OTPDeliveryLog(models.Model):
    DELIVERY_STATUS_CHOICES = [
        ("pending", "Pending"),
        ("delivered", "Delivered"),
        ("bounced", "Bounced"),
        ("dropped", "Dropped"),
        ("failed", "Failed"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="otp_logs",
    )

    otp = models.CharField(max_length=6)

    email_status = models.CharField(
        max_length=20,
        choices=DELIVERY_STATUS_CHOICES,
        default="pending",
    )

    sms_sent = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} - {self.otp}"


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


# models.py - Add these models
class ROITransaction(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="roi_transactions"
    )
    amount = models.DecimalField(max_digits=11, decimal_places=2)
    roi_type = models.CharField(
        max_length=10, choices=[("SAVINGS", "Savings"), ("INVESTMENT", "Investment")]
    )
    accrued_date = models.DateField()
    payout_date = models.DateField(null=True, blank=True)
    is_paid_out = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class DailyROIAccrual(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="daily_roi_accruals"
    )
    date = models.DateField()
    savings_balance = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    investment_balance = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    savings_roi = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    investment_roi = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    total_roi = models.DecimalField(max_digits=11, decimal_places=2, default=0)

    class Meta:
        unique_together = ["user", "date"]


from django.db import models
from django.utils import timezone


class TopSaverHistory(models.Model):
    month = models.PositiveIntegerField()
    year = models.PositiveIntegerField()
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,  # previously models.CASCADE
        related_name="top_saver_history",
        null=True,  # important to allow nulls if we're setting null
        blank=True,
    )

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


class CardManager(models.Manager):
    """Custom manager to exclude cards without valid authorization codes"""

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .exclude(
                models.Q(authorization_code="")
                | models.Q(authorization_code__isnull=True)
            )
        )

    def all_including_invalid(self):
        return super().get_queryset()


class Card(models.Model):
    user = models.ForeignKey(
        get_user_model(),
        on_delete=models.CASCADE,
        related_name="owned_cards",
    )

    authorization_code = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        db_index=True,
    )

    card_owner_name = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        default="",
    )
    signature = models.CharField(max_length=255, null=True, blank=True, db_index=True)

    card_type = models.CharField(max_length=50, null=True, blank=True)
    card_brand = models.CharField(max_length=50, null=True, blank=True)
    card_first6_digits = models.CharField(max_length=6, null=True, blank=True)
    card_last4_digits = models.CharField(max_length=4, null=True, blank=True)
    expiry_month = models.CharField(max_length=2, null=True, blank=True)
    expiry_year = models.CharField(max_length=4, null=True, blank=True)

    bank_name = models.CharField(max_length=100, null=True, blank=True)
    country_code = models.CharField(max_length=10, null=True, blank=True, default="NG")

    reusable = models.BooleanField(default=False)
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CardManager()
    all_objects = models.Manager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "is_active", "is_default"]),
            models.Index(fields=["user", "is_active", "reusable"]),
            models.Index(fields=["authorization_code"]),
            models.Index(fields=["signature"]),
        ]

    def save(self, *args, **kwargs):
        if self.is_default and self.user_id:
            Card.all_objects.filter(user=self.user, is_default=True).exclude(
                id=self.id
            ).update(is_default=False)

        if not self.is_active:
            self.is_default = False

        super().save(*args, **kwargs)

    def __str__(self):
        brand = (self.card_brand or self.card_type or "Card").upper()
        last4 = self.card_last4_digits or "****"
        bank = self.bank_name or "Unknown Bank"
        return f"{self.user.email} - {brand} •••• {last4} ({bank})"


# Update the models to use settings.AUTH_USER_MODEL
class AccountBalance(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    savings = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    investment = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    properties = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    wallet = models.DecimalField(max_digits=10, decimal_places=2, default=0)


class PhoneChangeRequest(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("verified", "Verified"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    )

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    old_phone = models.CharField(max_length=20)
    new_phone = models.CharField(max_length=20)

    old_phone_otp_verified = models.BooleanField(default=False)
    new_phone_otp_verified = models.BooleanField(default=False)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    old_phone_otp = models.CharField(max_length=6, null=True, blank=True)
    new_phone_otp = models.CharField(max_length=6, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)


from django.db import models
from django.conf import settings


class DvaDepositIntent(models.Model):
    PURPOSE_CHOICES = (
        ("SAVINGS", "Savings"),
        ("INVESTMENT", "Investment"),
    )

    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("confirmed", "Confirmed"),
        ("expired", "Expired"),
        ("failed", "Failed"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="dva_deposit_intents",
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    transaction_id = models.CharField(max_length=50, unique=True)
    paystack_reference = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        unique=True,
    )
    matched_account_number = models.CharField(max_length=20, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - {self.purpose} - {self.amount} - {self.status}"


from django.db import models
from django.conf import settings
from django.core.validators import RegexValidator
from decimal import Decimal, InvalidOperation
import uuid
import logging
from dateutil.relativedelta import relativedelta
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal

logger = logging.getLogger(__name__)


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
        ("HOURLY", "Hourly"),
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
    FUNDING_SOURCE_CHOICES = [
        ("SAVINGS", "Savings"),
        ("INVESTMENT", "Investment"),
    ]

    funding_source = models.CharField(
        max_length=20,
        choices=FUNDING_SOURCE_CHOICES,
        default="SAVINGS",
    )

    payment_method = models.CharField(max_length=50, blank=True, null=True)
    frequency = models.CharField(
        max_length=10, choices=FREQUENCY_CHOICES, default="MONTHLY"
    )
    next_deduction = models.DateTimeField(null=True, blank=True)
    next_retry = models.DateTimeField(null=True, blank=True)
    cancellation_charge = models.DecimalField(
        max_digits=12, decimal_places=2, default=0
    )
    is_cancelled = models.BooleanField(default=False)
    last_processed = models.DateTimeField(null=True, blank=True)
    deduction_attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=4)

    class Meta:
        indexes = [
            models.Index(fields=["is_active", "next_deduction"]),
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["is_active", "next_retry"]),
        ]

    @property
    def progress_percentage(self):
        if self.target_amount == 0:
            return 0
        return (self.current_amount / self.target_amount) * 100

    @property
    def is_completed(self):
        return self.current_amount >= self.target_amount

    def __str__(self):
        return f"{self.user.email}'s {self.name} Target"

    def calculate_next_deduction_time(self):
        """Calculate next deduction time based on frequency"""
        now = timezone.now()
        if self.frequency == "HOURLY":
            return now + relativedelta(hours=1)
        elif self.frequency == "DAILY":
            return now + relativedelta(days=1)
        elif self.frequency == "WEEKLY":
            return now + relativedelta(weeks=1)
        else:  # MONTHLY
            return now + relativedelta(months=1)

    def update_next_deduction_date(self):
        """Update next deduction date based on frequency and last processing time"""
        base_time = self.last_processed if self.last_processed else timezone.now()

        if self.frequency == "HOURLY":
            self.next_deduction = base_time + timedelta(hours=1)
        elif self.frequency == "DAILY":
            self.next_deduction = base_time + timedelta(days=1)
        elif self.frequency == "WEEKLY":
            self.next_deduction = base_time + timedelta(weeks=1)
        elif self.frequency == "MONTHLY":
            # For monthly, use relativedelta for proper month handling
            self.next_deduction = base_time + relativedelta(months=1)

    def schedule_retry(self):
        """Schedule retry based on frequency"""
        now = timezone.now()

        if self.frequency == "HOURLY":
            self.next_retry = now + timedelta(minutes=30)  # Retry in 30 minutes
        elif self.frequency == "DAILY":
            self.next_retry = now + timedelta(hours=6)  # Retry in 6 hours
        elif self.frequency == "WEEKLY":
            self.next_retry = now + timedelta(days=1)  # Retry in 1 day
        elif self.frequency == "MONTHLY":
            self.next_retry = now + timedelta(days=2)  # Retry in 2 days

    def get_retry_interval_display(self):
        """Get human-readable retry interval"""
        if self.frequency == "HOURLY":
            return "30 minutes"
        elif self.frequency == "DAILY":
            return "6 hours"
        elif self.frequency == "WEEKLY":
            return "1 day"
        elif self.frequency == "MONTHLY":
            return "2 days"
        return "soon"

    def process_deduction(self):
        """Process the periodic deduction for this target savings with robust handling for max attempts.

        Important changes:
        1. Persist deduction_attempts and other DB changes before sending external notifications.
        2. Use transaction.on_commit to run email/push after DB commit so failures in notification code do not rollback DB state.
        3. Use update_fields on saves to minimize accidental overwrites.
        """
        from django.db import transaction
        from .utils import send_generic_email, send_push_notification

        try:
            with transaction.atomic():
                # Re-fetch inside the transaction to avoid stale data/race conditions
                target = TargetSavings.objects.select_for_update().get(id=self.id)
                user = target.user.__class__.objects.select_for_update().get(
                    id=target.user.id
                )

                # Skip if no longer actionable
                # Skip if no longer actionable
                if target.is_completed or target.is_cancelled or not target.is_active:
                    logger.info(
                        f"Target {target.id} is completed/cancelled/inactive, skipping deduction"
                    )
                    return False

                # 🔴 ADDED: Check if user is banned or inactive
                if user.is_banned or not user.is_active:
                    logger.warning(
                        f"User {user.email} (ID: {user.id}) is banned/inactive but target {target.id} still exists. Pausing target."
                    )
                    target.is_active = False
                    target.save(update_fields=["is_active"])
                    return False

                # Base amount (guard against None)
                amount = target.monthly_payment or Decimal("0")

                # Adjust amount if it would overshoot the target
                if target.current_amount + amount > target.target_amount:
                    amount = target.target_amount - target.current_amount

                deduction_success = False
                source = None

                # Check and debit funding source
                if (
                    target.funding_source == "SAVINGS"
                    and user.savings >= amount
                    and amount > 0
                ):
                    user.savings -= amount
                    source = "SAVINGS"
                    deduction_success = True
                elif (
                    target.funding_source == "INVESTMENT"
                    and user.investment >= amount
                    and amount > 0
                ):
                    user.investment -= amount
                    source = "INVESTMENT"
                    deduction_success = True

                # always update last_processed timestamp
                target.last_processed = timezone.now()

                # FAILURE PATH (insufficient funds or invalid amount)
                if not deduction_success or amount <= 0:
                    target.deduction_attempts += 1
                    target.save(update_fields=["deduction_attempts", "last_processed"])

                    # Final failure: pause + refund + completion record
                    if target.deduction_attempts >= target.max_attempts:
                        # Pause target
                        target.is_active = False
                        target.is_cancelled = True  # mark clearly as cancelled/paused
                        target.next_retry = None
                        target.last_processed = timezone.now()
                        target.save(
                            update_fields=[
                                "is_active",
                                "is_cancelled",
                                "next_retry",
                                "last_processed",
                                "deduction_attempts",
                            ]
                        )

                        # Refund 99%
                        # 🚫 BANNED USERS DO NOT GET REFUNDS
                        if user.is_banned:
                            logger.warning(
                                f"Banned user {user.email} attempted refund on target {target.id}. Blocking refund."
                            )
                            refund_amount = Decimal("0")
                            charge = target.current_amount
                        charge = target.current_amount - refund_amount

                        if refund_amount > 0:
                            if target.funding_source == "SAVINGS":
                                user.savings += refund_amount
                                user.save(update_fields=["savings"])
                            else:
                                user.investment += refund_amount
                                user.save(update_fields=["investment"])

                            Transaction.objects.create(
                                user=user,
                                transaction_type="debit",
                                status="confirmed",
                                amount=refund_amount,
                                description=f"{target.name} - Failed",
                                service_charge=charge,
                                total_amount=refund_amount,
                                target_savings=target,
                                source="TARGET_REFUND",
                                transaction_id=f"[{target.id}]-{uuid.uuid4().hex[:12]}_MAX_ATTEMPTS_REFUND",
                            )

                        # Create FAILED completion record
                        TargetSavingsCompletion.objects.update_or_create(
                            user=user,
                            target_savings=target,
                            defaults={
                                "completed_amount": target.current_amount,
                                "bonus_amount": 0,
                                "total_amount": refund_amount,
                                "completed_date": timezone.now().date(),
                                "was_on_time": False,
                                "status": "FAILED",
                            },
                        )

                        # Reset current_amount so plan is visibly closed out
                        target.current_amount = 0
                        target.save(update_fields=["current_amount"])

                        # Notify after commit
                        def _notify_final():
                            try:
                                target.send_failed_deduction_email(max_attempts=True)
                            except Exception as e:
                                logger.exception(
                                    f"Error sending final failed-deduction email: {e}"
                                )
                            try:
                                send_push_notification(
                                    user,
                                    title=f"{target.name} Plan Paused 🛑",
                                    message=(
                                        f"{self.user.first_name}, your {target.name} plan was paused after {target.max_attempts} failed attempts. "
                                        f"₦{refund_amount:,.2f} has been refunded to your {target.funding_source.lower()} account. Kindly reactivate to get back on track."
                                    ),
                                    data={
                                        "target_id": target.id,
                                        "type": "DEDUCTION_FAILED_FINAL",
                                        "refund_amount": float(refund_amount or 0),
                                    },
                                )
                            except Exception as e:
                                logger.exception(
                                    f"Error sending final failed-deduction push: {e}"
                                )

                        transaction.on_commit(_notify_final)
                        return False

                    # Non-final failure: schedule a retry and notify (after commit)
                    else:
                        target.schedule_retry()
                        target.save(update_fields=["next_retry"])

                        def _notify_retry():
                            try:
                                target.send_failed_deduction_email(max_attempts=False)
                            except Exception as e:
                                logger.exception(
                                    f"Error sending retry failed-deduction email for target {target.id}: {e}"
                                )
                            try:
                                send_push_notification(
                                    user,
                                    title=f"{target.name} AutoSave Failed ❌",
                                    message=(
                                        f"{self.user.first_name}, autosave of ₦{amount:,.2f} failed for your {target.name} goal due to insufficient funds. "
                                        f"We'll retry in {target.get_retry_interval_display()}. Attempt {target.deduction_attempts} of {target.max_attempts}."
                                    ),
                                    data={
                                        "target_id": target.id,
                                        "type": "DEDUCTION_FAILED_RETRY",
                                        "attempt": target.deduction_attempts,
                                        "max_attempts": target.max_attempts,
                                    },
                                )
                            except Exception as e:
                                logger.exception(
                                    f"Error sending retry failed-deduction push for target {target.id}: {e}"
                                )

                        transaction.on_commit(_notify_retry)
                        return False

                # SUCCESS PATH
                # persist the user balance change
                if source:
                    user.save(update_fields=[source.lower()])

                # Update the target balance and reset attempts
                target.current_amount += amount
                target.deduction_attempts = 0
                target.last_processed = timezone.now()
                target.next_retry = None

                # If target completed, handle completion flow
                if target.current_amount >= target.target_amount:

                    today = timezone.now().date()
                    bonus = Decimal("0")
                    completed_amount = target.current_amount

                    if today <= target.end_date:
                        # 🔹 Use prorated 13% p.a. bonus
                        months = max(
                            1,
                            (target.end_date.year - target.start_date.year) * 12
                            + (target.end_date.month - target.start_date.month),
                        )
                        bonus = (
                            completed_amount
                            * Decimal("0.15")
                            * Decimal(months)
                            / Decimal(12)
                        ).quantize(Decimal("0.01"))

                    user.wallet += completed_amount + bonus
                    user.save(update_fields=["wallet"])

                    # zero out and deactivate target
                    target.current_amount = Decimal("0")
                    target.is_active = False
                    target.save()

                    TargetSavingsCompletion.objects.create(
                        user=user,
                        target_savings=target,
                        completed_amount=completed_amount,
                        bonus_amount=bonus,
                        total_amount=completed_amount + bonus,
                        completed_date=today,
                        was_on_time=today <= target.end_date,
                    )

                    Transaction.objects.create(
                        user=user,
                        transaction_type="credit",
                        status="confirmed",
                        amount=completed_amount + bonus,
                        description=f"{target.name} Completed! ✅",
                        service_charge=0,
                        total_amount=completed_amount + bonus,
                        target_savings=target,
                        source="TARGET_COMPLETION",
                        transaction_id=f"[{target.id}]-{uuid.uuid4().hex[:12]}_COMPLETION",
                    )

                    # ✅ Record wallet credit transaction (separate, so user sees wallet inflow)
                    Transaction.objects.create(
                        user=user,
                        transaction_type="credit",
                        status="confirmed",
                        amount=completed_amount + bonus,
                        description=f"{target.name} Completed! ✅",
                        service_charge=0,
                        total_amount=completed_amount + bonus,
                        source="WALLET",
                        transaction_id=f"[{target.id}]-{uuid.uuid4().hex[:12]}_WALLET",
                    )

                    def _notify_completion():
                        try:
                            target.send_completion_email()
                        except Exception as e:
                            logger.exception(
                                f"Error sending completion email for target {target.id}: {e}"
                            )
                        try:
                            send_push_notification(
                                user,
                                title=f"🎉 {target.name} Target Completed!✅",
                                message=(
                                    f"Congratulations, your {target.name} Target Savings is completed! "
                                    f"₦{completed_amount + bonus:,.2f} credited to your wallet."
                                ),
                                data={
                                    "target_id": target.id,
                                    "type": "TARGET_COMPLETED",
                                    "amount": float(completed_amount + bonus),
                                },
                            )
                        except Exception as e:
                            logger.exception(
                                f"Error sending completion push for target {target.id}: {e}"
                            )

                    transaction.on_commit(_notify_completion)
                    return True

                # Otherwise persist next deduction and create auto transaction, then notify
                target.update_next_deduction_date()
                target.save()

                Transaction.objects.create(
                    user=user,
                    transaction_type="credit",
                    status="confirmed",
                    amount=amount,
                    description=f"{target.name}",
                    service_charge=0,
                    total_amount=amount,
                    target_savings=target,
                    source=source,
                    transaction_id=f"[{target.id}]-{uuid.uuid4().hex[:12]}_AUTO",
                )

                progress = round(
                    (target.current_amount / target.target_amount) * 100, 2
                )

                def _notify_success():
                    try:
                        subject = f"AutoSave for {target.name} Successful! 🎉"
                        message = (
                            f"Hi {user.first_name},\n\n"
                            f"₦{amount:,.2f} has been successfully autosaved for your {target.name} Target Savings plan.\n\n"
                            f"Your new balance in this plan is ₦{target.current_amount:,.2f}.\n\n"
                            f"You're now {progress}% closer to your goal! 🚀\n\n"
                            f"Next autosave: {target.next_deduction.strftime('%Y-%m-%d %H:%M') if target.next_deduction else 'scheduled soon'}"
                        )
                        send_generic_email(
                            subject, message, settings.DEFAULT_FROM_EMAIL, [user.email]
                        )
                    except Exception as e:
                        logger.exception(
                            f"Error sending success email for target {target.id}: {e}"
                        )
                    try:
                        send_push_notification(
                            user,
                            title=f"AutoSave for {target.name} Successful! 🎉",
                            message=(
                                f"{self.user.first_name}, ₦{amount:,.2f} has just been autosaved for your {target.name} goal. "
                                f"New balance: ₦{target.current_amount:,.2f}. You're now {progress}% closer to your goal! Well done! 🚀"
                            ),
                            data={"target_id": target.id, "type": "DEDUCTION_SUCCESS"},
                        )
                    except Exception as e:
                        logger.exception(
                            f"Error sending success push for target {target.id}: {e}"
                        )

                transaction.on_commit(_notify_success)
                return True

        except Exception as e:
            logger.error(
                f"Error processing autosave for target savings {self.id}: {str(e)}"
            )
            # If something unexpected fails, schedule a retry and persist state
            try:
                self.schedule_retry()
                self.save(update_fields=["next_retry"])
            except Exception:
                logger.exception("Failed to schedule retry after unexpected error")
            return False

    def send_failed_deduction_email(self, max_attempts=False):
        """Send formatted email notification about failed deduction using generic email helper"""
        from .utils import send_generic_email
        from django.conf import settings

        try:
            subject = f"{self.name} AutoSave Failed ❌"

            if max_attempts:
                message = (
                    f"Hi {self.user.first_name},<br><br>"
                    f"We've attempted to autosave ₦{self.monthly_payment:,.2f} for your {self.name} target savings multiple times but failed due to insufficient funds.<br><br>"
                    "Your target savings plan has been <strong>temporarily paused</strong> and your funds have been returned to the funding source.<br><br>"
                    "Please ensure you have sufficient funds and reactivate your plan to continue working towards your goal.<br><br>"
                    "<em>MyFund Team</em>"
                )
            else:
                retry_time = (
                    self.next_retry.strftime("%Y-%m-%d %H:%M")
                    if self.next_retry
                    else "soon"
                )

                message = (
                    f"Hi {self.user.first_name},<br><br>"
                    f"The autosave of ₦{self.monthly_payment:,.2f} for your {self.name} target savings failed due to insufficient funds.<br><br>"
                    "Kindly note that you'll forfeit the extra interest if you do not meet your target date.<br><br>"
                    f"To ensure you meet your target, add the required amount to your {self.funding_source} account.<br><br>"
                    f"We'll retry again at <strong>{retry_time}</strong>.<br><br>"
                    f"(PS: Your Target Savings plan will pause after 3 unsuccessful retries and the funds will be returned to your {self.funding_source} (1% charge). Kindly fund your {self.funding_source} to stay on track.)<br><br>"
                    "<em>MyFund Team</em>"
                )

            send_generic_email(
                subject, message, settings.DEFAULT_FROM_EMAIL, [self.user.email]
            )

        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception(
                f"Error sending failed deduction email for target {self.id}: {e}"
            )

    def send_completion_email(self):
        """Send formatted email notification about target completion using generic email helper"""
        from .utils import send_generic_email
        from .models import TargetSavingsCompletion

        try:
            completion = TargetSavingsCompletion.objects.filter(
                target_savings=self, user=self.user
            ).last()

            if not completion:
                logger.warning(
                    f"No completion record found for target {self.id} when sending email"
                )
                return

            subject = f"🎉 Congrats! {self.name} Plan Completed! ✅"
            message = (
                f"Hi {self.user.first_name},<br><br>"
                f"Congratulations! You've successfully completed your {self.name} Target Savings plan.<br><br>"
                f"<strong>Completed Amount:</strong> ₦{completion.completed_amount:,.2f}<br>"
                f"<strong>Bonus:</strong> ₦{completion.bonus_amount:,.2f}<br>"
                f"<strong>Total Credited:</strong> ₦{completion.total_amount:,.2f}<br><br>"
                "You can now use these funds for your intended goal or set up a new target savings plan.<br><br>"
                "Well done and keep up the great savings habit! 🚀<br><br>"
                "<em>MyFund Team</em>"
            )

            send_generic_email(
                subject, message, settings.DEFAULT_FROM_EMAIL, [self.user.email]
            )

        except Exception as e:
            logger.exception(
                f"Error sending completion email for target {self.id}: {e}"
            )

    def save(self, *args, **kwargs):
        """Ensure initial next_deduction is set when creating an active plan."""
        if not self.next_deduction and self.is_active and not self.is_cancelled:
            self.next_deduction = self.calculate_next_deduction_time()
        super().save(*args, **kwargs)


class TargetSavingsCompletion(models.Model):
    STATUS_CHOICES = [
        ("SUCCESS", "Success"),
        ("FAILED", "Failed"),
        ("CANCELLED", "Cancelled"),  # 🔴 Added new status option
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="completed_target_savings",
    )
    target_savings = models.OneToOneField(
        TargetSavings, on_delete=models.CASCADE, related_name="completion_record"
    )
    completed_amount = models.DecimalField(max_digits=12, decimal_places=2)
    bonus_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    completed_date = models.DateField()
    was_on_time = models.BooleanField(default=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="SUCCESS")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-completed_date"]

    def __str__(self):
        return (
            f"{self.user.email}'s {self.target_savings.name} Completion ({self.status})"
        )


# TRANSACTIONS MODEL # TRANSACTION MODEL
from decimal import Decimal, InvalidOperation, DecimalException
from django.utils import timezone
import uuid


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

    source = models.CharField(
        max_length=20,
        choices=[
            ("SAVINGS", "Savings"),
            ("INVESTMENT", "Investment"),
            ("CARD", "Card"),
            ("WALLET", "Wallet"),
        ],
        blank=True,
        null=True,
        help_text="Where the transaction funds came from",
    )

    source_channel = models.CharField(max_length=20, null=True, blank=True)

    credited_to = models.CharField(
        max_length=20,
        choices=[
            ("SAVINGS", "Savings"),
            ("INVESTMENT", "Investment"),
            ("WALLET", "Wallet"),
        ],
        blank=True,
        null=True,
        db_index=True,
        help_text="Where the transaction amount was credited to",
    )
    scheduled_date = models.DateField(
        null=True,
        blank=True,
        help_text="For scheduled withdrawals, the processing date.",
    )

    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    is_processed = models.BooleanField(
        default=False,
        help_text="For scheduled withdrawals - whether the scheduled withdrawal has been processed",
    )
    status = models.CharField(
        max_length=20, choices=STATUS_TYPES, default="pending", db_index=True
    )
    amount = models.DecimalField(max_digits=14, decimal_places=2)
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

    balance_before = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="User balance before this transaction",
    )

    balance_after = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="User balance after this transaction",
    )

    # ✅ FIXED: Remove duplicate paystack_auth_code and keep only one
    paystack_auth_code = models.CharField(
        max_length=255, null=True, blank=True, default="", editable=False
    )
    paystack_access_code = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        editable=False,
        db_index=True,
    )
    paystack_reference = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        db_index=True,
    )
    idempotency_key = models.CharField(
        max_length=64, unique=True, null=True, blank=True, db_index=True
    )

    service_charge = models.DecimalField(max_digits=14, decimal_places=2, default=0.0)
    total_amount = models.DecimalField(max_digits=14, decimal_places=2, default=0.0)
    referral_email = models.EmailField(
        max_length=255, blank=True, null=True, db_index=True
    )
    target_savings = models.ForeignKey(
        TargetSavings, on_delete=models.SET_NULL, null=True, blank=True
    )

    def save(self, *args, **kwargs):
        from decimal import Decimal

        if isinstance(self.amount, (int, float)):
            self.amount = Decimal(str(self.amount))

        if isinstance(self.service_charge, (int, float)):
            self.service_charge = Decimal(str(self.service_charge))

        if self.transaction_type == "debit":
            self.total_amount = self.amount + self.service_charge
        else:
            self.total_amount = self.amount

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} - {self.status} - {self.date}"

    class Meta:
        indexes = [
            models.Index(fields=["date", "status", "transaction_type"]),
            models.Index(fields=["user", "date", "status"]),
            models.Index(fields=["source", "transaction_type", "status", "date"]),
            models.Index(fields=["credited_to", "transaction_type", "status", "date"]),
        ]


# Push Notifications Model
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


# Metrics MODEL #Metric MODEL


class MetricSnapshot(models.Model):
    PERIOD_TYPES = (
        ("daily", "Daily"),
        ("weekly", "Weekly"),
        ("monthly", "Monthly"),
    )

    period_type = models.CharField(max_length=20, choices=PERIOD_TYPES)

    snapshot_date = models.DateField(db_index=True)

    total_users = models.PositiveIntegerField(default=0)

    new_users = models.PositiveIntegerField(default=0)

    active_users = models.PositiveIntegerField(default=0)

    retention_rate = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=0,
    )

    ltv = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=0,
    )

    cac_proxy = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        default=0,
    )

    float_balance = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=0,
    )

    estimated_float_revenue = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=0,
    )

    total_deposits = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=0,
    )

    total_withdrawals = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=0,
    )

    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-snapshot_date"]
        indexes = [
            models.Index(fields=["period_type", "snapshot_date"]),
        ]

    def __str__(self):
        return f"{self.period_type} metrics - {self.snapshot_date}"


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
    paystack_plan_code = models.CharField(max_length=255, null=True, blank=True)
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
                "paystack_plan_code": self.paystack_plan_code,
                "paystack_trans_ref": self.paystack_trans_ref,
            }
            if self.paystack_sub_id
            or self.paystack_sub_code
            or self.paystack_sub_token
            or self.paystack_plan_code
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
    paystack_plan_code = models.CharField(max_length=255, null=True, blank=True)
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
                "paystack_plan_code": self.paystack_plan_code,
                "paystack_trans_ref": self.paystack_trans_ref,
            }
            if self.paystack_sub_id
            or self.paystack_sub_code
            or self.paystack_sub_token
            or self.paystack_plan_code
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

    # ✅ IMPORTANT: This 'amount' field now stores NET AMOUNT (what to send)
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Net amount to send to user (after charges)",
    )

    total_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Original amount requested by user (including charges)",
    )

    charge_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        help_text="Percentage charge applied (e.g., 10.00 for 10%)",
    )

    charge_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Actual charge amount deducted",
    )

    transaction_id = models.CharField(max_length=50, unique=False, default="")
    is_approved = models.BooleanField(default=False)
    is_processed = models.BooleanField(
        default=False,
        help_text="Has scheduled withdrawal been credited to wallet?",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    source_account = models.CharField(max_length=255, default="savings")
    target_bank = models.CharField(max_length=100, default="")
    target_account_number = models.CharField(max_length=50, default="")
    target_account_name = models.CharField(max_length=255, blank=True, null=True)

    # Withdrawal type fields
    withdrawal_type = models.CharField(
        max_length=50,
        default="immediate",
        choices=[("immediate", "Immediate"), ("scheduled", "Scheduled")],
    )

    scheduled_processing_date = models.DateField(
        null=True,
        blank=True,
        help_text="Date when scheduled withdrawal should be processed",
    )

    # ✅ ADDED STATUS FIELD
    WITHDRAWAL_STATUS = (
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
        ("cancelled", "Cancelled"),
    )

    status = models.CharField(
        max_length=20,
        choices=WITHDRAWAL_STATUS,
        default="pending",
        blank=True,
        null=True,
        help_text="Current status of the withdrawal request",
    )

    # Add a method to calculate net amount if needed
    @property
    def net_amount(self):
        """Property to get net amount (same as amount field)"""
        return self.amount

    @property
    def display_total_amount(self):
        """Property to display total amount with currency"""
        return f"₦{self.total_amount:,.2f}"

    @property
    def display_charge_amount(self):
        """Property to display charge amount with currency"""
        return f"₦{self.charge_amount:,.2f}"

    @property
    def display_net_amount(self):
        """Property to display net amount with currency"""
        return f"₦{self.amount:,.2f}"

    def save(self, *args, **kwargs):
        """Ensure amounts are Decimal and calculate if needed"""
        try:
            # Convert to Decimal if needed
            if isinstance(self.amount, (int, float)):
                self.amount = Decimal(str(self.amount))
            if isinstance(self.total_amount, (int, float)):
                self.total_amount = Decimal(str(self.total_amount))
            if isinstance(self.charge_amount, (int, float)):
                self.charge_amount = Decimal(str(self.charge_amount))
            if isinstance(self.charge_percentage, (int, float)):
                self.charge_percentage = Decimal(str(self.charge_percentage))

        except (TypeError, InvalidOperation, DecimalException) as e:
            raise ValueError(f"Invalid amount format: {e}")

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.email} - ₦{self.total_amount:,.2f} -> ₦{self.amount:,.2f} ({self.get_withdrawal_type_display()})"

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Withdrawal Request"
        verbose_name_plural = "Withdrawal Requests"


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
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="device_tokens"
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


class GroupOwnership(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total_contributed = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    ownership_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, default=0
    )


class GroupDeparture(models.Model):
    REASON_CHOICES = [
        ("financial", "Financial constraints"),
        ("timeline", "Timeline doesn't work for me"),
        ("property", "Changed mind about the property"),
        ("group", "Issues with group members"),
        ("better_opportunity", "Found a better investment opportunity"),
        ("personal", "Personal reasons"),
        ("other", "Other"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(
        "Group", on_delete=models.CASCADE, related_name="departures"
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    additional_details = models.TextField(blank=True, null=True)  # Optional free text
    refunded_amount = models.DecimalField(max_digits=11, decimal_places=2, default=0)
    left_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-left_at"]

    def __str__(self):
        return f"{self.user.email} left {self.group.id} - {self.reason}"


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


from decimal import Decimal
from django.conf import settings
from django.db import models
from django.utils import timezone


class AmbassadorPointConfig(models.Model):
    """
    Central place to adjust ambassador points without touching code.
    Keep one active record.
    """

    name = models.CharField(max_length=100, default="Default Ambassador Config")
    is_active = models.BooleanField(default=True)

    signup_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("0.50")
    )
    signup_points_cap = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("10.00")
    )

    confirmed_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("10.00")
    )

    savings_points_per_10000 = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("0.40")
    )
    savings_points_cap = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("20.00")
    )

    attendance_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("0.50")
    )

    coursera_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("2.00")
    )
    social_media_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("2.00")
    )
    abroad_confirmed_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("10.00")
    )
    myfund_event_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("5.00")
    )
    reshares_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("0.05")
    )
    other_points = models.DecimalField(
        max_digits=6, decimal_places=2, default=Decimal("5.00")
    )

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Ambassador Point Config"
        verbose_name_plural = "Ambassador Point Config"

    def __str__(self):
        return f"{self.name} ({'Active' if self.is_active else 'Inactive'})"

    @classmethod
    def get_active(cls):
        config = cls.objects.filter(is_active=True).order_by("-updated_at").first()
        if config:
            return config
        return cls.objects.create()


class AmbassadorMonthlyReport(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ambassador_reports",
    )

    month = models.CharField(max_length=7, db_index=True)  # YYYY-MM

    # system / prefilled submitted values
    signups_submitted = models.PositiveIntegerField(default=0)
    confirmed_submitted = models.PositiveIntegerField(default=0)
    savings_submitted = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal("0.00")
    )
    attendance_submitted = models.PositiveIntegerField(default=0)
    others_submitted = models.PositiveIntegerField(default=0)

    # user-editable submitted values
    coursera_submitted = models.PositiveIntegerField(default=0)
    social_media_submitted = models.PositiveIntegerField(default=0)
    abroad_confirmed_submitted = models.PositiveIntegerField(default=0)
    events_submitted = models.PositiveIntegerField(default=0)
    reshares_submitted = models.PositiveIntegerField(default=0)
    notes = models.TextField(blank=True, null=True)

    # evidence
    coursera_certificate = models.ImageField(
        upload_to="ambassador_reports/", blank=True, null=True
    )
    social_media_evidence = models.ImageField(
        upload_to="ambassador_reports/", blank=True, null=True
    )
    abroad_signups_evidence = models.ImageField(
        upload_to="ambassador_reports/", blank=True, null=True
    )
    events_evidence = models.ImageField(
        upload_to="ambassador_reports/", blank=True, null=True
    )
    reshares_evidence = models.ImageField(
        upload_to="ambassador_reports/", blank=True, null=True
    )

    # admin-reviewed values
    signups_approved = models.PositiveIntegerField(default=0)
    confirmed_approved = models.PositiveIntegerField(default=0)
    savings_approved = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal("0.00")
    )
    attendance_approved = models.PositiveIntegerField(default=0)
    others_approved = models.PositiveIntegerField(default=0)

    coursera_approved = models.PositiveIntegerField(default=0)
    social_media_approved = models.PositiveIntegerField(default=0)
    abroad_confirmed_approved = models.PositiveIntegerField(default=0)
    events_approved = models.PositiveIntegerField(default=0)
    reshares_approved = models.PositiveIntegerField(default=0)

    # points breakdown
    signup_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    confirmed_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    savings_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    attendance_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    coursera_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    social_media_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    abroad_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    events_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    reshares_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    others_points_awarded = models.DecimalField(
        max_digits=8, decimal_places=2, default=Decimal("0.00")
    )
    total_points_awarded = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal("0.00")
    )

    # stipend
    stipend_amount = models.DecimalField(
        max_digits=12, decimal_places=2, default=Decimal("0.00")
    )
    stipend_paid = models.BooleanField(default=False)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    admin_note = models.TextField(blank=True, null=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="approved_ambassador_reports",
    )
    approved_at = models.DateTimeField(blank=True, null=True)

    submitted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ["user", "month"]
        ordering = ["-submitted_at"]

    def __str__(self):
        return f"{self.user.email} - {self.month} - {self.status}"

    def set_stipend_from_points(self):
        self.stipend_amount = (self.total_points_awarded or Decimal("0.00")) * Decimal(
            "100"
        )

    def recalculate_points(self):
        config = AmbassadorPointConfig.get_active()

        signup_points = Decimal(str(self.signups_approved or 0)) * Decimal(
            str(config.signup_points or 0)
        )
        if signup_points > Decimal(str(config.signup_points_cap or 0)):
            signup_points = Decimal(str(config.signup_points_cap or 0))

        confirmed_points = Decimal(str(self.confirmed_approved or 0)) * Decimal(
            str(config.confirmed_points or 0)
        )

        savings_units = Decimal(str(self.savings_approved or 0)) / Decimal("10000")
        savings_points = savings_units * Decimal(
            str(config.savings_points_per_10000 or 0)
        )
        if savings_points > Decimal(str(config.savings_points_cap or 0)):
            savings_points = Decimal(str(config.savings_points_cap or 0))

        attendance_points = Decimal(str(self.attendance_approved or 0)) * Decimal(
            str(config.attendance_points or 0)
        )
        coursera_points = Decimal(str(self.coursera_approved or 0)) * Decimal(
            str(config.coursera_points or 0)
        )
        social_media_points = Decimal(str(self.social_media_approved or 0)) * Decimal(
            str(config.social_media_points or 0)
        )
        abroad_points = Decimal(str(self.abroad_confirmed_approved or 0)) * Decimal(
            str(config.abroad_confirmed_points or 0)
        )
        events_points = Decimal(str(self.events_approved or 0)) * Decimal(
            str(config.myfund_event_points or 0)
        )
        reshares_points = Decimal(str(self.reshares_approved or 0)) * Decimal(
            str(config.reshares_points or 0)
        )
        others_points = Decimal(str(self.others_approved or 0)) * Decimal(
            str(config.other_points or 0)
        )

        self.signup_points_awarded = signup_points
        self.confirmed_points_awarded = confirmed_points
        self.savings_points_awarded = savings_points
        self.attendance_points_awarded = attendance_points
        self.coursera_points_awarded = coursera_points
        self.social_media_points_awarded = social_media_points
        self.abroad_points_awarded = abroad_points
        self.events_points_awarded = events_points
        self.reshares_points_awarded = reshares_points
        self.others_points_awarded = others_points

        self.total_points_awarded = (
            signup_points
            + confirmed_points
            + savings_points
            + attendance_points
            + coursera_points
            + social_media_points
            + abroad_points
            + events_points
            + reshares_points
            + others_points
        )

        # 1 point = ₦100
        self.stipend_amount = (self.total_points_awarded or Decimal("0.00")) * Decimal(
            "100"
        )

    def copy_submitted_to_approved_defaults(self):
        self.signups_approved = self.signups_submitted
        self.confirmed_approved = self.confirmed_submitted
        self.savings_approved = self.savings_submitted
        self.attendance_approved = self.attendance_submitted
        self.others_approved = self.others_submitted
        self.coursera_approved = self.coursera_submitted
        self.social_media_approved = self.social_media_submitted
        self.abroad_confirmed_approved = self.abroad_confirmed_submitted
        self.events_approved = self.events_submitted
        self.reshares_approved = self.reshares_submitted


class AmbassadorAttendanceSubmission(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ambassador_attendance_submissions",
    )
    email = models.EmailField()
    attendance_date = models.DateField(null=True, blank=True)
    takeaway = models.TextField()
    recommendation = models.TextField()

    month = models.CharField(max_length=7, db_index=True)  # YYYY-MM
    week_key = models.CharField(max_length=20, db_index=True)  # e.g. 2026-W13

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["user", "week_key"]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - {self.week_key} - {self.attendance_date}"


class FinanceMetricSnapshot(models.Model):
    PERIOD_CHOICES = (
        ("daily", "Daily"),
        ("monthly", "Monthly"),
        ("yearly", "Yearly"),
    )

    period_type = models.CharField(
        max_length=20, choices=PERIOD_CHOICES, default="monthly"
    )
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    abrupt_withdrawal_revenue = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )
    float_gross_revenue = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )
    roi_payable_to_users = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )
    float_net_profit = models.DecimalField(max_digits=14, decimal_places=2, default=0)

    property_sales_revenue = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )
    rent_commission_revenue = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )

    total_revenue = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    total_expenses = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    net_profit = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    profit_margin = models.DecimalField(max_digits=7, decimal_places=2, default=0)

    total_savings_balance = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )
    total_investment_balance = models.DecimalField(
        max_digits=14, decimal_places=2, default=0
    )

    notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("period_type", "period_start", "period_end")
        ordering = ["-period_start"]

    def __str__(self):
        return f"{self.period_type.title()} Finance Snapshot: {self.period_start} - {self.period_end}"


class Employee(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    monthly_amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.email})"


class PayrollRun(models.Model):
    month_label = models.CharField(max_length=50)
    reason = models.CharField(max_length=100, default="MyFund Allowance")
    is_test = models.BooleanField(default=False)
    test_email = models.EmailField(null=True, blank=True)
    executed_at = models.DateTimeField(auto_now_add=True)
    executed_by = models.CharField(max_length=150, blank=True)

    def __str__(self):
        return f"{self.month_label} {'(TEST)' if self.is_test else ''}"


class PayrollEntry(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending (Draft)"),
        ("credited", "Credited"),
        ("test_run", "Test Run"),
        ("user_not_found", "User Not Found"),
        ("failed", "Failed"),
    ]
    run = models.ForeignKey(
        PayrollRun, on_delete=models.CASCADE, related_name="entries"
    )
    employee = models.ForeignKey(Employee, on_delete=models.SET_NULL, null=True)
    email = models.EmailField()
    name = models.CharField(max_length=100, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.CharField(max_length=150, blank=True)
    balance_before = models.DecimalField(
        max_digits=11, decimal_places=2, null=True, blank=True
    )
    balance_after = models.DecimalField(
        max_digits=11, decimal_places=2, null=True, blank=True
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - ₦{self.amount} - {self.status}"
