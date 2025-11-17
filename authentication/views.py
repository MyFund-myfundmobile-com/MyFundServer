import os
from rest_framework import status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    api_view,
    parser_classes,
)
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import (
    SignupSerializer,
    ConfirmOTPSerializer,
    UserSerializer,
)
import random
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from rest_framework.views import APIView
from django.contrib.auth import logout
from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from authentication.models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserProfileUpdateSerializer
from rest_framework.permissions import IsAuthenticated
from .serializers import ProfilePictureUpdateSerializer
from rest_framework.parsers import FileUploadParser
from datetime import datetime
from django.utils.safestring import mark_safe
from django.db.models import F
import uuid
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password, check_password
import traceback
from utils.encryption import encrypt_data, decrypt_data
from utils.imageKit import imagekit
import hashlib
import json
import hmac
from dotenv import load_dotenv
import logging
from django.db.models import Min
from decimal import Decimal, ROUND_HALF_EVEN
from .utils import (
    generate_reference,
    get_user_balance,
    send_push_notification,
    set_user_balance,
)
from .utils import send_generic_email
from django.db import transaction
from .utils import send_sms_via_payless, validate_phone_number, send_bulk_sms
from rest_framework.exceptions import AuthenticationFailed


load_dotenv()

logger = logging.getLogger(__name__)


@api_view(["POST"])
@csrf_exempt
def signup(request):
    def handle_referral_rewards(user):
        try:
            transaction_id = str(uuid.uuid4())[:10]
            # Reward for referred user
            Transaction.objects.create(
                user=user,
                referral_email=user.referral.email,
                transaction_type="credit",
                status="pending",
                amount=500,
                description="Referral Reward . . .",
                transaction_id=transaction_id,
                total_amount=500,
            )

            user.pending_referral_reward = 500
            user.save(update_fields=["pending_referral_reward"])

            # Reward for referrer
            if not user.referral.is_hired_referrer:
                transaction_id = str(uuid.uuid4())[:10]
                Transaction.objects.create(
                    user=user.referral,
                    referral_email=user.email,
                    transaction_type="credit",
                    status="pending",
                    amount=500,
                    description="Referral Reward . . .",
                    transaction_id=transaction_id,
                    total_amount=500,
                )

                user.referral.pending_referral_reward = (
                    F("pending_referral_reward") + 500
                )
                user.referral.save()
                send_referrer_pending_reward_email(user.referral, user.email)

            if user.referral.is_hired_referrer:
                Referral.objects.create(user=user, referrer=user.referral)

            send_referred_pending_reward_email(user)
            logger.info("Referral rewards processed for user %s", user.email)
        except Exception as e:
            logger.error(
                f"Error processing referral rewards for user {user.email}: {str(e)}"
            )
            raise

    # ✅ Validate phone number before saving user
    phone_number = request.data.get("phone_number")
    if not phone_number:
        return Response(
            {"error": "Phone number is required"}, status=status.HTTP_400_BAD_REQUEST
        )

    phone_check = validate_phone_number(phone_number)
    if not phone_check.get("valid"):
        logger.warning(f"Invalid phone number: {phone_number}")
        return Response(
            {"error": phone_check.get("error")}, status=status.HTTP_400_BAD_REQUEST
        )

    validated_phone = phone_check.get("formatted")

    try:
        serializer = SignupSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            # ✅ Save user first
            user = serializer.save()
            user.phone_number = validated_phone
            user.how_did_you_hear = serializer.validated_data.get(
                "how_did_you_hear", "OTHER"
            )
            user.save(update_fields=["phone_number", "how_did_you_hear"])

            # ✅ Now generate OTP after saving phone number
            is_resend = request.data.get("resend", False)
            otp = generate_otp()
            user.otp = otp
            user.is_active = False if not is_resend else user.is_active
            user.last_otp_sent_at = timezone.now()
            user.save(
                update_fields=["otp", "is_active", "last_otp_sent_at", "updated_at"]
            )

            # Always send email OTP
            try:
                send_otp_email(user, otp)
            except Exception as e:
                logger.warning(f"⚠️ OTP email failed to send, continuing flow: {e}")

            # Only send SMS OTP on first signup (not resend)
            # Only send SMS OTP on first signup (not resend)
            if not is_resend:
                validated_phone = getattr(user, "phone_number", None)
                if validated_phone:
                    sms_sent = send_otp_sms(user, otp)  # <-- pass the user object
                    if sms_sent:
                        logger.info(f"📱 SMS OTP sent to {validated_phone}")
                    else:
                        logger.warning(
                            f"⚠️ SMS OTP failed to send for {validated_phone}"
                        )
                else:
                    logger.warning("⚠️ No valid phone number found for SMS OTP")

            # Handle referral rewards
            if user.referral:
                handle_referral_rewards(user)

            response_data = serializer.data
            response_data["referral_email"] = (
                user.referral.email if user.referral else None
            )
            return Response(response_data, status=status.HTTP_201_CREATED)

        else:
            logger.warning("Invalid signup data: %s", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.critical("Unexpected error in signup: %s", str(e))
        return Response(
            {"error": "Unexpected server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


def send_referrer_pending_reward_email(referrer, referred_email):
    subject = f"{referrer.first_name}, Your Referral Reward is Pending..."
    message = f"Hi {referrer.first_name},<br><br>Your referral reward of ₦500.00 is pending. When your friend ({referred_email}) becomes active by making their first savings/investment, your reward will be confirmed in your wallet.<br><br>Thank you for using MyFund!<br><br>Keep growing your funds.🥂<br><br>"

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [referrer.email]

    try:
        send_generic_email(subject, message, from_email, recipient_list)
    except Exception as e:
        logger.warning(f"⚠️ Referral email to referrer failed for {referrer.email}: {e}")


def send_referred_pending_reward_email(user):
    subject = f"{user.first_name}, Your N500 Referral Reward is Pending"
    message = f"Hi {user.first_name},<br><br>You have received a welcome referral reward bonus of ₦500.00 for signing up with a referral email. It will be confirmed in your Wallet when you make your first savings of up to ₦20,000.<br><br>Thank you for using MyFund!<br><br>Keep growing your funds.🥂<br><br>"

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]
    bcc_list = ["newusers@myfundmobile.com"]

    all_recipients = recipient_list + bcc_list

    try:
        send_generic_email(subject, message, from_email, all_recipients)
    except Exception as e:
        logger.warning(
            f"⚠️ Referral email to referred user failed for {user.email}: {e}"
        )


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_exempt
def confirm_otp(request):
    def activate_user_account(user):
        user.is_active = True
        user.save()
        logger.info("Account confirmed successfully for user %s", user.email)

        # Attempt to send welcome email, but don't break activation if mail fails.
        try:
            send_welcome_email(user)
        except Exception as e:
            logger.exception(
                "Failed to send welcome email to %s after activation: %s",
                user.email,
                str(e),
            )

    serializer = ConfirmOTPSerializer(data=request.data)
    if serializer.is_valid():
        otp = serializer.validated_data["otp"]

        try:
            user = CustomUser.objects.get(otp=otp)
            if user.is_active:
                logger.info(
                    "Attempted to confirm an already active account for user %s",
                    user.email,
                )
                return Response(
                    {"message": "Account already confirmed."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            activate_user_account(user)
            return Response(
                {"message": "Account confirmed successfully."},
                status=status.HTTP_200_OK,
            )
        except CustomUser.DoesNotExist:
            logger.warning("Invalid OTP provided: %s", otp)
            return Response(
                {"message": "Invalid OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    logger.warning("Invalid data submitted for OTP confirmation: %s", serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def generate_otp():
    return "".join(random.choices("0123456789", k=6))


def send_otp_email(user, otp):
    """
    Sends the OTP email using Django's send_mail with a proper recipient_list.
    Now always wrapped in MyFund's email/email.html template.
    Raises on failure so callers can handle/log it.
    """
    subject = f"[OTP-{otp}] Did You Just Signup?"

    # Inner content (can be plain text or HTML)
    inner_html = f"""
    <p>Hi {user.first_name}, </p>

    <p>We heard you'd like a shiny new MyFund account. Use the One-Time-Password (OTP) below to complete your signup. This code is valid only for 20 minutes, so chop-chop!</p>

    <h1 style="text-align: center; font-size: 36px;">{otp}</h1>

    <p>If you did not request to create a MyFund account, kindly ignore this email. Otherwise, buckle up, you're in for a treat!</p>

    <p>Cheers! 🥂</p>
    """

    # Wrap in MyFund template
    context = {
        "subject": subject,
        "message": inner_html,  # template should render {{ message|safe }}
        "user": user,  # optional if your template uses it
    }
    html_message = render_to_string("email/email.html", context=context)
    message_text = strip_tags(html_message)

    from_email = getattr(
        settings, "DEFAULT_FROM_EMAIL", "MyFund <info@myfundmobile.com>"
    )
    recipient_list = [user.email]

    try:
        send_mail(
            subject,
            message_text,
            from_email,
            recipient_list,
            html_message=html_message,
            fail_silently=False,
        )
        logger.info("OTP email sent to %s", user.email)
    except Exception as exc:
        logger.exception("Failed to send OTP email to %s: %s", user.email, str(exc))
        try:
            user.otp = None
            user.save(update_fields=["otp"])
        except Exception:
            user.save()
        raise


def send_otp_sms(user, otp):
    from authentication.utils import send_sms_via_payless

    phone_number = getattr(user, "phone_number", None)  # should already be +234...
    first_name = getattr(user, "first_name", "") or "there"

    if not phone_number or len(phone_number) < 10:
        logger.warning(f"Invalid phone number: {phone_number}")
        return False

    message = (
        f"Hi {first_name}, please use {otp} to complete your signup on MyFund. "
        f"It expires in 20 minutes. Please keep it safe."
    )

    try:
        success = send_sms_via_payless(phone_number, message)
        if success:
            logger.info(f"📱 SMS OTP sent to {phone_number}")
        else:
            logger.warning(f"⚠️ SMS OTP failed to send for {phone_number}")
        return success
    except Exception as e:
        logger.exception(f"❌ SMS sending failed for {phone_number}: {e}")
        return False


def send_otp_for_user(user):
    """
    Helper: generate OTP, persist it (and last_otp_sent_at if available),
    attempt to send the OTP email, and return True on success or raise on failure.
    """
    otp = generate_otp()
    user.otp = otp

    # update last_otp_sent_at if you added the field previously
    if hasattr(user, "last_otp_sent_at"):
        user.last_otp_sent_at = timezone.now()

    # Save fields atomically when possible
    try:
        update_fields = ["otp", "updated_at"]
        if hasattr(user, "last_otp_sent_at"):
            update_fields.append("last_otp_sent_at")
        user.save(update_fields=update_fields)
    except Exception:
        user.save()

    # Try to send the email and raise if it fails so caller can handle it
    try:
        send_otp_email(user, otp)
        logger.info("send_otp_for_user: OTP sent to %s", user.email)
        return True
    except Exception as e:
        logger.exception(
            "send_otp_for_user: Failed to send OTP to %s: %s", user.email, str(e)
        )
        # Clear the OTP (avoid leaving an unused OTP in DB)
        try:
            user.otp = None
            user.save(update_fields=["otp"])
        except Exception:
            user.save()
        # raise to inform the caller
        raise


@api_view(["POST"])
@csrf_exempt
@permission_classes([AllowAny])
def resend_otp(request):
    """
    Resend OTP for an existing, inactive user.
    Payload: { "email": "user@example.com" }
    """
    email = (request.data.get("email") or "").strip().lower()
    if not email:
        logger.warning("Resend OTP called without email.")
        return Response(
            {"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = CustomUser.objects.get(email__iexact=email)
    except CustomUser.DoesNotExist:
        logger.warning("Resend OTP requested for non-existent user: %s", email)
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    if user.is_active:
        logger.info("Resend OTP requested for already active user: %s", user.email)
        return Response(
            {"detail": "Account already verified."}, status=status.HTTP_400_BAD_REQUEST
        )

    # Optional server-side cooldown using last_otp_sent_at if available
    COOLDOWN_SECONDS = 60
    last_sent = getattr(user, "last_otp_sent_at", None)
    if last_sent and timezone.now() - last_sent < timedelta(seconds=COOLDOWN_SECONDS):
        logger.info("OTP resend cooldown in effect for %s", user.email)
        return Response(
            {"detail": "Please wait before requesting another code."}, status=429
        )

    try:
        send_otp_for_user(user)
        return Response(
            {"detail": "OTP resent successfully.", "email": user.email},
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        logger.exception("Error resending OTP to %s: %s", email, str(e))
        return Response(
            {"detail": "Failed to resend OTP. Try again later."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


from django.core.mail import send_mail
from django.utils.html import format_html

logo_url = (
    "https://drive.google.com/uc?export=view&id=1MorbW_xLg4k2txNQdhUnBVxad8xeni-N"
)
image_url = (
    "https://drive.google.com/uc?export=view&id=1K7sBCm3mgW5jQ1Cfh73LQDZuvGuNFTKw"
)


def send_welcome_email(user):
    subject = f"{user.first_name}, WELCOME TO MyFund! 🥂🎊🔥"

    image_url = (
        "https://drive.google.com/uc?export=view&id=1K7sBCm3mgW5jQ1Cfh73LQDZuvGuNFTKw"
    )
    savings_image_url = (
        "https://drive.google.com/uc?export=view&id=1bOVTTicGZJgUKX2aTm2SAqyX-8qfH41Q"
    )

    message_html = f"""
    <p>Hi {user.first_name},</p>
    <p>I'm personally welcoming you to the MyFund family.</p>
    <p>By signing up, you've entered the 4th step toward financial freedom,
       <strong>SAVINGS</strong> (click WealthMap on the app for details).</p>
    <p><img src="{savings_image_url}" alt="Savings Step Image" style="display: block; margin: 10px auto; max-width: 100%; height: auto;"></p>
    <p>The app tracks your progress as you save towards buying properties for a lifetime rental (passive) income.</p>
    <p>In the last few years, thousands have saved to sort their rents, started a business, saved their first million, earned their first passive income, traveled abroad, got married... it's amazing.</p>
    <p>I can't wait to hear your financial success story in the shortest time possible here at MyFund.</p>
    <p>Once again, you're welcome!</p>
    <br>
   <p style="display: inline-flex; align-items: center; margin: 0;">
    <img src="{image_url}" alt="Dr Tee"
        style="width: 50px; height: 50px; border-radius: 50%; margin-right: 10px;">
    <span>
        <strong style="font-size: 16px;">Tolulope Ahmed (Dr Tee)</strong><br>
        <span style="font-size: 12px; font-style: italic; color: #555;">
        CEO/Co-founder, MyFund
        </span>
    </span>
    </p>
    """

    # Just call the generic helper
    send_generic_email(
        subject=subject,
        message=message_html,
        recipient_list=[user.email],
    )


def send_otp_reset_email(user, otp):
    subject = f"[OTP] Password Reset - {otp}"
    current_year = datetime.now().year

    message = f"""
    <p><img src="{logo_url}" alt="MyFund Logo" style="display: block; margin: 0 auto; max-width: 100px; height: auto;"></p>

    <p>Hi {user.first_name}, </p>

    <p>You have requested to reset your password. Use the One-Time-Password (OTP) below to complete the password reset. This code is valid only for a short time, so act quickly!</p>

    If you did not request a password reset, please ignore this email.

    Thank you,
    
    MyFund
    """

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_generic_email(subject, message, from_email, recipient_list)


def test_email(request):
    subject = f"Test Email"
    message = f"""
    This is a test email body.

    Thank you,
    
    MyFund
    """

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = ["sammy@myfundmobile.com"]

    send_generic_email(subject, message, from_email, recipient_list)

    return HttpResponse("Test email sent. This shows the email system is working")


from rest_framework.test import force_authenticate
from rest_framework.request import Request
from rest_framework.parsers import JSONParser
from django.http import JsonResponse

from rest_framework.test import APIRequestFactory, force_authenticate


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def delete_my_account(request):
    user = request.user
    print(f"⚠️ Deletion request for: {user.email}")

    total_funds = user.savings + user.investment + user.wallet

    # Case 1: No funds — delete immediately
    if total_funds == 0:
        user.delete()
        print("✅ User deleted immediately. No funds.")
        return Response({"message": "Account deleted successfully."})

    # Case 2: Has funds — require a bank account
    target_bank_account = user.bank_accounts.first()
    if not target_bank_account:
        print("❌ No bank account found. Cannot proceed with withdrawal.")
        return Response(
            {"error": "No bank account available for withdrawal."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        factory = APIRequestFactory()

        for source, balance in [
            ("savings", user.savings),
            ("investment", user.investment),
            ("wallet", user.wallet),
        ]:
            if balance > 0:
                print(f"💸 Withdrawing ₦{balance} from {source}")
                data = {
                    "source_account": source,
                    "amount": str(balance),
                    "withdrawal_type": "immediate",
                    "target_bank_account_id": target_bank_account.id,
                }
                mock_request = factory.post("/api/withdraw/", data, format="json")
                force_authenticate(mock_request, user=user)

                # ✅ Call the actual decorated view function
                response = process_withdrawal_to_local_bank(mock_request)
                if response.status_code not in (200, 201):
                    raise Exception(f"Failed withdrawal from {source}: {response.data}")

        user.delete()
        print("✅ User account deleted after triggering withdrawals.")
        return Response({"message": "Account deleted and withdrawals triggered."})

    except Exception as e:
        print("❌ Failed to process withdrawal before deletion.")
        import traceback

        traceback.print_exc()
        return Response(
            {"error": "Failed to process withdrawal before account deletion."},
            status=status.HTTP_400_BAD_REQUEST,
        )


from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import authenticate_user_by_email_or_phone  # <- import
from authentication.models import CustomUser
import logging

logger = logging.getLogger(__name__)


class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        try:
            username = request.data.get("username", "").strip().lower()
            password = request.data.get("password", "")

            # DRY authentication
            user = authenticate_user_by_email_or_phone(username, password)

            # 🚫 Block banned users first
            if getattr(user, "is_banned", False):
                return Response(
                    {
                        "status": "banned",
                        "message": (
                            "Your account has been disabled due to some suspicious activities detected.\n\n"
                            "Contact support at care@myfundmobile.com for review."
                        ),
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # If user is inactive: send OTP
            if not user.is_active:
                from authentication.views import send_otp_for_user

                try:
                    send_otp_for_user(user)
                except Exception as e:
                    logger.exception(
                        "Failed to send OTP during login for %s: %s", user.email, str(e)
                    )
                    return Response(
                        {"detail": "Failed to send OTP. Try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

                return Response(
                    {
                        "status": "inactive",
                        "message": "Account not verified. A new OTP has been sent to your email.",
                        "next_step": "enter_otp",
                        "email": user.email,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # ✅ Active user: generate tokens
            tokens = self.get_tokens_for_user(user)
            return Response(tokens)

        except AuthenticationFailed as auth_exc:
            return Response(
                {"error": str(auth_exc)}, status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            logger.error(f"Login error for {request.data.get('username')}: {str(e)}")
            return Response(
                {"error": "Invalid credentials or account issue"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    @staticmethod
    def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_id": user.id,
        }


from rest_framework.permissions import AllowAny


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Restrict access to authenticated users

    def post(self, request):
        try:
            logout(request)
            logger.info("User logged out successfully: %s", request.user)
            return Response(
                {"detail": "Logged out successfully."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error("Error during logout: %s", str(e))
            return Response(
                {"detail": "An error occurred during logout."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class OTPVerificationView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def post(self, request, *args, **kwargs):
        received_otp = request.data.get("otp")
        user = request.user  # Authenticated user

        if not received_otp:
            logger.warning("No OTP provided by user: %s", user.email)
            return Response(
                {"success": False, "message": "OTP is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.otp == received_otp:
            if user.otp_verified:
                logger.info(
                    "User %s attempted to verify an already verified OTP.", user.email
                )
                return Response(
                    {"success": False, "message": "OTP already verified."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # OTP matches and not yet verified
            user.otp_verified = True
            user.save()
            logger.info("User %s successfully verified OTP.", user.email)
            return Response(
                {"success": True, "message": "OTP verified successfully."},
                status=status.HTTP_200_OK,
            )
        else:
            logger.warning("Invalid OTP provided by user: %s", user.email)
            return Response(
                {"success": False, "message": "Invalid OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )


from .models import CustomUser, GroupOwnership, PasswordReset, UserPassword


@api_view(["POST"])
@csrf_exempt
def request_password_reset(request):
    """
    Handles password reset requests by sending an OTP to the user's email.
    """
    email = request.data.get("email").strip().lower()

    if not email:
        logger.warning("Password reset request received without an email.")
        return Response(
            {"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = CustomUser.objects.get(email=email)
        logger.info("Password reset request for user: %s", user.email)

        # Generate and store OTP
        otp = generate_otp()
        PasswordReset.objects.create(user=user, otp=otp)

        # Send OTP reset email
        send_otp_reset_email(user, otp)
        logger.info("Password reset OTP sent successfully to user: %s", user.email)

        return Response(
            {"detail": "Password reset OTP sent successfully."},
            status=status.HTTP_200_OK,
        )

    except CustomUser.DoesNotExist:
        logger.warning("Password reset requested for non-existent user: %s", email)
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        logger.error("Error handling password reset request: %s", str(e))
        return Response(
            {"detail": "An error occurred while processing the request."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@csrf_exempt
def reset_password(request):
    """
    Handles password reset using an email, OTP, and new password.
    """
    required_fields = ["email", "otp", "password", "confirm_password"]
    for field in required_fields:
        if field not in request.data:
            logger.warning("Password reset request missing required field: %s", field)
            return Response(
                {"error": f"'{field}' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    email = request.data.get("email").strip().lower()
    otp = request.data.get("otp")
    password = request.data.get("password")
    confirm_password = request.data.get("confirm_password")

    if password != confirm_password:
        logger.warning("Password mismatch for user email: %s", email)
        return Response(
            {"error": "Passwords do not match."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        user = CustomUser.objects.get(email=email)
        password_reset = PasswordReset.objects.get(user=user, otp=otp)
    except CustomUser.DoesNotExist:
        logger.warning("Password reset attempted with non-existent email: %s", email)
        return Response(
            {"error": "Invalid email."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    except PasswordReset.DoesNotExist:
        logger.warning("Invalid OTP for email: %s", email)
        return Response(
            {"error": "Invalid OTP."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        # Reset the password
        user.set_password(password)
        user.save()
        password_reset.delete()  # Delete the used OTP entry
        logger.info("Password reset successful for user: %s", user.email)
        return Response(
            {"message": "Password reset successful."},
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        logger.error("Error during password reset for user %s: %s", email, str(e))
        return Response(
            {"error": "An error occurred while resetting the password."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    """
    Retrieve and return the authenticated user's profile information.
    """
    try:
        user = request.user

        if not user.is_authenticated:
            logger.warning("Unauthenticated request attempted for user profile.")
            return Response(
                {"error": "User is not authenticated."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        logger.info("Fetching profile data for user: %s", user.email)

        profile_data = {
            "firstName": user.first_name,
            "lastName": user.last_name,
            "mobileNumber": user.phone_number,
            "email": user.email,
            "profile_picture": (
                user.profile_picture.url
                if hasattr(user.profile_picture, "url")
                else user.profile_picture if user.profile_picture else None
            ),
            "preferred_asset": user.preferred_asset,
            "savings_goal_amount": user.savings_goal_amount,
            "time_period": user.time_period,
        }
        return Response(profile_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(
            "Error fetching user profile for user %s: %s", request.user, str(e)
        )
        return Response(
            {"error": "An error occurred while fetching user profile."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["PATCH"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    """
    Updates the authenticated user's profile with provided data.
    """
    user = request.user
    allowed_fields = ["first_name", "last_name", "phone_number"]

    try:
        updated_fields = {}

        for field in allowed_fields:
            if field in request.data:
                setattr(user, field, request.data[field])
                updated_fields[field] = request.data[field]

        if updated_fields:
            user.save()
            logger.info(
                "User profile updated for user: %s with fields: %s",
                user.email,
                updated_fields,
            )
            return Response(
                {
                    "message": "Profile updated successfully.",
                    "updated_fields": updated_fields,
                },
                status=status.HTTP_200_OK,
            )
        else:
            logger.warning(
                "No valid fields provided for user profile update: %s", user.email
            )
            return Response(
                {"error": "No valid fields provided for update."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    except Exception as e:
        logger.error("Error updating profile for user %s: %s", user.email, str(e))
        return Response(
            {"error": "An error occurred while updating the profile."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


import time
import logging
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from imagekitio import ImageKit
from django.conf import settings

logger = logging.getLogger(__name__)

imagekit = ImageKit(
    private_key=settings.IMAGEKIT_PRIVATE_KEY,
    public_key=settings.IMAGEKIT_PUBLIC_KEY,
    url_endpoint=settings.IMAGEKIT_URL_ENDPOINT,
)


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def profile_picture_update(request):
    user = request.user
    pic = request.FILES.get("profile_picture")
    if not pic:
        return Response(
            {"error": "No image file provided"}, status=status.HTTP_400_BAD_REQUEST
        )

    # optional: enforce size/type here…

    ext = pic.name.rsplit(".", 1)[-1]
    filename = f"profile_{user.id}_{int(time.time())}.{ext}"

    try:
        # upload to ImageKit
        result = imagekit.upload_file(
            file=pic,
            file_name=filename,
            options={
                "folder": "/profile_pictures/",
                "tags": [f"user_{user.id}"],
            },
        )
        url = result["response"]["url"]

        user.profile_picture = url
        user.save()

        return Response(
            {
                "message": "Profile picture updated successfully",
                "profile_picture": url,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error("ImageKit upload failed: %s", e)
        # fallback to local
        from django.core.files.storage import FileSystemStorage

        fs = FileSystemStorage()
        local_name = fs.save(filename, pic)
        local_url = request.build_absolute_uri(fs.url(local_name))
        user.profile_picture = local_url
        user.save()

        return Response(
            {
                "message": "Profile picture saved locally",
                "profile_picture": local_url,
                "warning": "Cloud upload failed, using local storage",
            },
            status=status.HTTP_200_OK,
        )


from .serializers import SavingsGoalUpdateSerializer


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def update_savings_goal(request):
    """
    Updates the user's savings goal and handles the first-time signup flag.
    """
    user = request.user

    try:
        serializer = SavingsGoalUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()

            # Update is_first_time_signup flag
            if user.is_first_time_signup:
                user.is_first_time_signup = False
                user.save()
                logger.info("First-time signup flag updated for user: %s", user.email)

            logger.info("Savings goal updated for user: %s", user.email)
            return Response(serializer.data, status=status.HTTP_200_OK)

        logger.warning("Invalid data for savings goal update: %s", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error("Error updating savings goal for user %s: %s", user.email, str(e))
        return Response(
            {"error": "An error occurred while updating the savings goal."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


from .serializers import (
    MessageSerializer,
)  # Create a serializer for AdminMessage if needed
from .models import AutoSave, Message
from django.contrib.auth import get_user_model
from channels.layers import get_channel_layer
from rest_framework.parsers import MultiPartParser


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
def send_message(request, recipient_id):
    """
    Sends a message with optional content or image to a specified recipient.
    """
    user = request.user
    content = request.data.get("content")
    image = request.data.get("image")

    # Validate input
    if not content and not image:
        logger.warning("Message content or image is required. User: %s", user.email)
        return Response(
            {"error": "Message content or image is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate recipient
    try:
        recipient = get_user_model().objects.get(id=recipient_id)
    except get_user_model().DoesNotExist:
        logger.warning(
            "Recipient not found for id: %s by user: %s", recipient_id, user.email
        )
        return Response(
            {"error": "Recipient not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    try:
        # Create the message
        message = Message.objects.create(
            sender=user,
            recipient=recipient,
            content=content,
            image=image,
        )

        logger.info(
            "Message sent from user %s to recipient %s", user.email, recipient.email
        )

        # Prepare response data
        message_data = {
            "content": message.content,
            "image": message.image.url if message.image else None,
            "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "sender_id": message.sender.id,
            "recipient_id": message.recipient.id,
        }

        return Response(
            {"success": True, "message": message_data},
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        logger.error("Error while sending message from user %s: %s", user.email, str(e))
        return Response(
            {"error": "An error occurred while sending the message."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_messages(request, recipient_id):
    """
    Retrieves all messages exchanged between the authenticated user and the specified recipient.
    """
    user = request.user

    try:
        # Validate recipient existence
        recipient = get_user_model().objects.get(id=recipient_id)
    except get_user_model().DoesNotExist:
        logger.warning(
            "Recipient with id %s not found. User: %s", recipient_id, user.email
        )
        return Response(
            {"error": "Recipient not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    try:
        # Retrieve and order messages
        messages = Message.objects.filter(
            sender__in=[user, recipient], recipient__in=[user, recipient]
        ).order_by("timestamp")

        # Serialize messages
        message_data_list = [
            {
                "content": message.content,
                "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "sender_id": message.sender.id,
                "recipient_id": message.recipient.id,
                "image": message.image.url if message.image else None,
            }
            for message in messages
        ]

        logger.info(
            "Messages retrieved successfully between %s and %s",
            user.email,
            recipient.email,
        )
        return Response(message_data_list, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(
            "Error retrieving messages for user %s with recipient %s: %s",
            user.email,
            recipient_id,
            str(e),
        )
        return Response(
            {"error": "An error occurred while retrieving messages."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_admin_reply(request, message_id):
    admin_user = request.user
    content = request.data.get("content")

    try:
        message = Message.objects.get(id=message_id)
        if message.recipient != admin_user:
            return Response(
                {"error": "You are not authorized to reply to this message"},
                status=status.HTTP_403_FORBIDDEN,
            )

    except Message.DoesNotExist:
        return Response(
            {"error": "Message not found"}, status=status.HTTP_404_NOT_FOUND
        )

    if not content:
        return Response(
            {"error": "Message content is required"}, status=status.HTTP_400_BAD_REQUEST
        )

    # Create a new message from admin to user
    reply_message = Message.objects.create(
        sender=admin_user, recipient=message.sender, content=content
    )

    return Response({"success": True})


from django.contrib import messages
from django.urls import reverse


def reply_to_message(request, message_id):
    # Logic to handle replying to a message
    if request.method == "POST":
        # Process the reply message and save it to the database
        reply_content = request.POST.get(
            "content"
        )  # Get the reply content from the form
        if reply_content:
            # Process the reply content and save it to the database
            # For example, you can create a new message instance and save it

            messages.success(request, "Reply message sent successfully.")
            return redirect(reverse("admin:authentication_message_changelist"))
        else:
            messages.error(request, "Reply content cannot be empty.")
            return redirect(reverse("admin:authentication_message_changelist"))

    # Render a form to reply to the message
    context = {
        "message_id": message_id,
    }
    return render(request, "admin/message/reply_message.html", context)


from .serializers import BankAccountSerializer
from .models import BankAccount
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from .serializers import BankAccountSerializer
import requests


class BankAccountViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing bank accounts.
    """

    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=["get"])
    def get_user_banks(self, request):
        """
        Retrieve all bank accounts associated with the authenticated user.
        """
        user_banks = BankAccount.objects.filter(user=request.user)
        serializer = self.get_serializer(user_banks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def resolve_account(self, account_number, bank_code):
        """
        Resolve account details using Paystack's API.
        """
        secret_key = os.environ.get(
            "PAYSTACK_KEY_LIVE",
            default="  ",
        )
        url = f"https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={bank_code}"
        headers = {"Authorization": f"Bearer {secret_key}"}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            response_data = response.json()
            account_name = response_data.get("data", {}).get("account_name", "")
            if account_name:
                logger.info("Account resolved successfully: %s", account_name)
            return account_name
        except requests.exceptions.RequestException as e:
            logger.error("Failed to resolve account: %s", str(e))
            return None

    def perform_create(self, serializer):
        """
        Create a bank account, resolving account details if possible.
        """
        account_number = self.request.data.get("accountNumber")
        bank_code = self.request.data.get("bankCode")

        if account_number and bank_code:
            account_name = self.resolve_account(account_number, bank_code)

            if account_name:
                # Create the recipient code through Paystack
                paystack_recipient_code = create_paystack_recipient(
                    account_name, account_number, bank_code
                )

                serializer.save(
                    user=self.request.user,
                    account_number=account_number,
                    bank_code=bank_code,
                    account_name=account_name,
                    paystack_recipient_code=paystack_recipient_code,
                )
                logger.info(
                    "Bank account added successfully for user: %s",
                    self.request.user.email,
                )
                return Response(
                    {"message": "Bank account added successfully."},
                    status=status.HTTP_201_CREATED,
                )
            else:
                logger.warning(
                    "Failed to resolve account details for user: %s",
                    self.request.user.email,
                )
                return Response(
                    {"error": "Failed to resolve account details."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            serializer.save(user=self.request.user)
            logger.info(
                "Bank account added without resolution for user: %s",
                self.request.user.email,
            )
            return Response(
                {"message": "Bank account added without account details resolution."},
                status=status.HTTP_201_CREATED,
            )


from django.db import IntegrityError


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_bank_account(request):
    """
    Adds a bank account for the authenticated user.
    """
    bank_name = request.data.get("bankName")
    account_number = request.data.get("accountNumber")
    account_name = request.data.get("accountName")
    bank_code = request.data.get("bankCode")

    # Validate required fields
    if not all([bank_name, account_number, account_name, bank_code]):
        error_message = (
            "All fields (bankName, accountNumber, accountName, bankCode) are required."
        )
        logger.error(error_message)
        return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Create Paystack recipient
        paystack_recipient_code = create_paystack_recipient(
            account_name, account_number, bank_code
        )

        if not paystack_recipient_code:
            error_message = "Failed to create Paystack recipient."
            logger.error(error_message)
            return Response(
                {"error": error_message}, status=status.HTTP_400_BAD_REQUEST
            )

        # Save bank account
        # Save bank account
        bank_account = BankAccount.objects.create(
            user=request.user,
            bank_name=bank_name,
            account_number=account_number,
            account_name=account_name,
            bank_code=bank_code,
            is_default=False,
            paystack_recipient_code=paystack_recipient_code,
        )

        # 🔥 Link the bank account to the user's ManyToMany field
        request.user.bank_accounts.add(bank_account)

        logger.info("Bank account added successfully for user: %s", request.user.email)

        # Serialize and return response
        serializer = BankAccountSerializer(bank_account)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    except IntegrityError:
        error_message = "This bank account is already associated with another user."
        logger.error("IntegrityError: %s", error_message)
        return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        error_message = f"An unexpected error occurred: {str(e)}"
        logger.error("Unexpected error: %s", error_message)
        return Response(
            {"error": error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


from django.db.models import Count
from django.db import transaction


@api_view(["DELETE"])
def delete_bank_account(request, account_number):
    """
    Deletes a bank account identified by the account number.
    """
    try:
        # Attempt to retrieve the bank account
        bank_account = BankAccount.objects.get(account_number=account_number)
    except BankAccount.DoesNotExist:
        logger.warning("Bank account with account number %s not found.", account_number)
        return Response(
            {"error": "Bank account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    try:
        # Identify duplicate accounts with the same account number
        duplicates = (
            BankAccount.objects.filter(account_number=account_number)
            .annotate(count=Count("id"))
            .filter(count__gt=1)
        )

        with transaction.atomic():
            # Delete duplicates (if any)
            for duplicate in duplicates:
                if duplicate.id != bank_account.id:
                    logger.info(
                        "Deleting duplicate bank account with ID %s", duplicate.id
                    )
                    duplicate.delete()

            # Delete the primary bank account
            bank_account.delete()
            logger.info(
                "Bank account with account number %s deleted successfully.",
                account_number,
            )

        return Response(
            {"message": "Bank account deleted successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )

    except Exception as e:
        logger.error("Error deleting bank account %s: %s", account_number, str(e))
        return Response(
            {"error": "An error occurred while deleting the bank account."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_banks(request):
    try:
        user_banks = BankAccount.objects.filter(user=request.user)
        serializer = BankAccountSerializer(user_banks, many=True)
        logger.info(
            "Retrieved %d bank accounts for user: %s",
            user_banks.count(),
            request.user.email,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(
            "Error retrieving bank accounts for user %s: %s", request.user.email, str(e)
        )
        return Response(
            {"error": "An error occurred while retrieving bank accounts."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


from .models import Card
from .serializers import CardSerializer, TransactionSerializer
from rest_framework import generics


class BankAccountListCreateView(generics.ListCreateAPIView):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class BankAccountDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def perform_destroy(self, instance):
        instance.delete()


class UserBankAccountListView(generics.ListAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return BankAccount.objects.filter(user=self.request.user)


class CardListCreateView(generics.ListCreateAPIView):
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CardDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]


class UserCardListView(generics.ListAPIView):
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Card.objects.filter(user=self.request.user)


class DeleteCardView(generics.DestroyAPIView):
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        card = self.get_object()
        card.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TransactionCreateView(generics.CreateAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(
            user=self.request.user,  # Set the user field to the authenticated user
            description="Add Card Transaction",  # Provide a transaction description
        )


from .models import Transaction

channel_layer = get_channel_layer()


# Modify UserTransactionListView to use the Transaction model
class UserTransactionListView(generics.ListAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        transactions = Transaction.objects.filter(user=user).order_by("-date", "-time")
        return transactions


from .serializers import AccountBalancesSerializer


class AccountBalancesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = AccountBalancesSerializer(user)
        return Response(serializer.data)


from graphene_django.views import GraphQLView
from graphql_jwt.decorators import jwt_cookie
from django.utils.decorators import method_decorator


class CustomGraphQLView(GraphQLView):
    @method_decorator(jwt_cookie)
    def dispatch(self, request, *args, **kwargs):
        # Your existing authentication logic
        if request.user.is_authenticated:
            print("User is authenticated:", request.user)
            return super().dispatch(request, *args, **kwargs)
        else:
            print("User is not authenticated. Sending 401 response.")
            return JsonResponse(
                {"error": "Authentication required. Login first"}, status=401
            )


paystack_secret_key = os.environ.get(
    "PAYSTACK_KEY_LIVE",
    default="  ",
)

# views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
import requests
from django.conf import settings


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def quicksave(request):
    amount = request.data.get("amount")
    payment_channels = request.data.get("channels", ["card"])

    if amount is None:
        return Response({"error": "amount required"}, status=400)

    if int(amount) < 100:
        return Response({"error": "Amount cannot be less than #100"}, status=400)

    # Convert amount to kobo and to int (Paystack requires integer amount in kobo)
    amount_kobo = int(amount * 100)

    payload = {
        "email": request.user.email,
        "amount": amount_kobo,
        "channels": payment_channels,
    }

    # Make request to Paystack
    resp = requests.post(
        "https://api.paystack.co/transaction/initialize",
        json=payload,
        headers={
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        },
        timeout=30,  # 30 seconds timeout
    )

    # Check if request to Paystack was successful
    if resp.status_code != 200:
        error_message = resp.json().get("message", "Payment initialization failed")
        return Response({"error": error_message}, status=400)

    data = resp.json()

    if not data.get("status"):
        return Response(
            {
                "error": f"Payment initialization failed: {data.get('message', 'Unknown error')}"
            },
            status=400,
        )

    reference = data["data"]["reference"]
    access_code = data["data"]["access_code"]

    # ✅ NEW: Capture authorization data for reusable payments
    authorization_data = data["data"].get("authorization", {})
    authorization_code = authorization_data.get("authorization_code")
    reusable = authorization_data.get("reusable", False)
    # You can also capture card details if you want to show them to users
    card_brand = authorization_data.get("brand", "")
    card_last4 = authorization_data.get("last4", "")

    Transaction.objects.create(
        user=request.user,
        transaction_type="credit",
        status="pending",
        amount=Decimal(amount),
        description="QuickSave",
        transaction_id=reference,
        paystack_access_code=access_code,
        # ✅ NEW: Store authorization code if available
        authorization_code=authorization_code,
    )

    return Response(
        {
            "status": "transaction_initiated",
            "message": "Authorization of QuickSave transaction on Paystack required",
            "authorization_url": data["data"]["authorization_url"],
            "access_code": access_code,
            # ✅ NEW: Return authorization info to frontend
            "authorization_code": authorization_code,
            "reusable": reusable,
            "card_brand": card_brand,
            "card_last4": card_last4,
        }
    )


import time
import threading
import logging


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def autosave(request):
    user = request.user
    amount = request.data.get("amount")
    frequency = request.data.get("frequency")

    # Validate request data
    if not amount or not frequency:
        return Response(
            {"error": "Missing required fields: card_id, amount, and frequency."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = int(amount)
        if amount < 100:
            return Response(
                {"error": "Amount cannot be less that N100"},
                status=status.HTTP_400_BAD_REQUEST,
            )
    except ValueError:
        return Response(
            {"error": "Invalid amount. Amount should be a number."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    valid_frequencies = ["hourly", "daily", "weekly", "monthly"]
    if frequency not in valid_frequencies:
        return Response(
            {
                "error": "Invalid frequency. Choose 'hourly', 'daily', 'weekly', or 'monthly'."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Check for existing AutoSave records for the user
    try:
        existing_autosave = AutoSave.objects.filter(
            user=user, frequency=frequency, active=True
        )

        if existing_autosave.exists():
            return Response(
                {
                    "error": f"An active AutoSave record already exists for frequency: {frequency}."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
    except ObjectDoesNotExist:
        pass

    # Check if user has a transaction with a paystack_auth_code
    has_paystack_auth = (
        Transaction.objects.filter(user=user, paystack_auth_code__isnull=False)
        .exclude(paystack_auth_code="")
        .exists()
    )

    # print(f"has_paystack_auth:  {has_paystack_auth}")

    if not has_paystack_auth:
        return Response(
            {
                "error": "You need to do a QuickSave/QuickInvest before you can activate AutoSave"
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Prepare Paystack plan creation request
    paystack_frequency = frequency
    plan_payload = {
        "name": f"{frequency.capitalize()} AutoSave Plan for {user.email}",
        "interval": paystack_frequency,
        "amount": amount * 100,  # Convert amount to kobo
    }

    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }

    # Step 1: Create subscription plan on Paystack
    try:
        plan_response = requests.post(
            "https://api.paystack.co/plan", json=plan_payload, headers=headers
        )
        plan_response.raise_for_status()
        plan_data = plan_response.json()

        if not plan_data.get("status"):
            return Response(
                {"error": "Failed to create plan on Paystack."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        plan_code = plan_data.get("data", {}).get("plan_code")
    except requests.RequestException as e:
        return Response(
            {"error": f"Paystack plan creation failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 2: Subscribe user to the plan
    subscription_payload = {"customer": user.email, "plan": plan_code}

    try:
        subscription_response = requests.post(
            "https://api.paystack.co/subscription",
            json=subscription_payload,
            headers=headers,
        )
        subscription_response.raise_for_status()
        subscription_data = subscription_response.json()

        if not subscription_data.get("status"):
            return Response(
                {"error": "Subscription failed."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        subscription_id = subscription_data.get("data", {}).get("id")
        subscription_code = subscription_data.get("data", {}).get("subscription_code")
        subscription_token = subscription_data.get("data", {}).get("email_token")
        transaction_reference = subscription_data.get("data", {}).get("reference")

    except requests.RequestException as e:
        return Response(
            {"error": f"Subscription failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 3: Save AutoSave record to the database
    autosave_record = AutoSave.objects.create(
        user=user,
        frequency=frequency,
        amount=amount,
        paystack_sub_id=subscription_id,
        paystack_sub_code=subscription_code,
        paystack_sub_token=subscription_token,
        paystack_plan_code=plan_code,
        paystack_trans_ref=transaction_reference,
        active=True,
    )

    # Send success notification email
    subject = "AutoSave Activated!"
    message = f"Hi {user.first_name},<br><br>Your AutoSave have been activated. You are now saving ₦{amount} {frequency}.<br><br>Keep growing your funds.🥂"
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_generic_email(subject, message, from_email, recipient_list)

    # Mark user as having autosave enabled
    user.autosave_enabled = True
    user.save()

    # After user.autosave_enabled = True and user.save()
    send_push_notification(
        user=user,
        title="AutoSave Activated! ✅",
        message=f"Well done {user.first_name}! You're now saving ₦{amount} {frequency}. Keep growing your funds.",
        data={
            "amount": str(amount),
            "frequency": frequency,
            "type": "AutoSave",
            "status": "activated",
        },
        notif_type="SYSTEM",
    )

    return Response({"message": "AutoSave activated"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def deactivate_autosave(request):
    user = request.user
    frequency = request.data.get("frequency")

    if not frequency:
        return Response(
            {
                "error": "Frequency Missing: Please, provide the frequency of the autosave."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        # Find all active AutoSaves for the user with the given frequency
        active_autosaves = AutoSave.objects.filter(
            user=user, frequency=frequency, active=True
        )

        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }

        for autosave in active_autosaves:

            # print(f"autosave: {autosave}")

            if autosave.paystack_sub_id and autosave.paystack_sub_token:
                # Prepare the data for the request
                data = {
                    "code": autosave.paystack_sub_code,
                    "token": autosave.paystack_sub_token,
                }

                # Log the data being sent
                # print("Disabling subscription with data:", autosave.paystack_trans_ref)

                # Make the API request
                deactivate_response = requests.post(
                    "https://api.paystack.co/subscription/disable",
                    json=data,
                    headers=headers,
                )

                # Check for successful response
                deactivate_response.raise_for_status()  # Raises an HTTPError for bad responses

                # Deactivate the AutoSave
                autosave.active = False
                autosave.save()
                autosave.delete()
            else:
                autosave.delete()
                return Response(
                    {
                        "error": "Paystack subscription details are missing for one or more AutoSaves"
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        user.autosave_enabled = False
        user.save()

        # Send a confirmation email
        subject = "AutoSave Deactivated!"
        message = f"Hi {user.first_name},<br><br>Your {frequency} AutoSave(s) have been deactivated. <br><br>Keep growing your funds.🥂"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_generic_email(subject, message, from_email, recipient_list)

        # Return a success response indicating that AutoSave has been deactivated
        return Response({"message": "AutoSave deactivated"}, status=status.HTTP_200_OK)

    except requests.RequestException as e:
        return Response(
            {"error": f"Failed to deactivate subscription on Paystack: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_autosave_status(request):
    user = request.user
    autosave_enabled = user.autosave_enabled

    # Retrieve the user's active auto-save settings
    try:
        autosave = AutoSave.objects.get(user=user, active=True)
        autoSaveSettings = {
            "active": autosave_enabled,
            "amount": autosave.amount,
            "frequency": autosave.frequency,
        }

        # Fetch subscription status from Paystack
        subscription_id = autosave.paystack_sub_id
        paystack_url = f"https://api.paystack.co/subscription/{subscription_id}"

        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }

        response = requests.get(paystack_url, headers=headers)
        if response.status_code == 200:
            subscription_data = response.json()
            subscription_status = subscription_data.get("data", {}).get("status")
            autoSaveSettings["subscription_status"] = subscription_status
            autosave_enabled = (
                True if autoSaveSettings["subscription_status"] == "active" else False
            )
        else:
            autoSaveSettings = {"active": False, "amount": 0, "frequency": ""}

    except AutoSave.DoesNotExist:
        autoSaveSettings = {"active": False, "amount": 0, "frequency": ""}

    except Exception as e:
        # Handle any other exceptions that might occur
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response(
        {"autosave_enabled": autosave_enabled, "autoSaveSettings": autoSaveSettings},
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def quickinvest(request):
    amount = request.data.get("amount")
    payment_channels = request.data.get("channels", ["card"])

    if amount is None:
        return Response({"error": "amount required"}, status=400)

    if int(amount) < 100000:
        return Response({"error": "Amount cannot be less than #100,000"}, status=400)

    # Convert amount to kobo and to int (Paystack requires integer amount in kobo)
    amount_kobo = int(amount * 100)

    # Paystack charge request
    payload = {
        "email": request.user.email,
        "amount": amount_kobo,
        "channels": payment_channels,
    }

    resp = requests.post(
        "https://api.paystack.co/transaction/initialize",
        json=payload,
        headers={
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        },
    )

    data = resp.json()

    # print(f"<br><br>paystack response:\n {data}<br><br>")

    if not data.get("status"):
        return Response({"error": f"Charge Failed: {data}"}, status=400)

    reference = data["data"]["reference"]
    access_code = data["data"]["access_code"]

    # Create pending transaction
    Transaction.objects.create(
        user=request.user,
        transaction_type="credit",
        status="pending",
        amount=Decimal(amount),
        description="QuickInvest",
        transaction_id=reference,
        paystack_access_code=access_code,
    )

    return Response(
        {
            "status": "transaction_initiated",
            "message": "Authorization of QickInvest transaction on Paystack required",
            "authorization_url": f'{data["data"]["authorization_url"]}',
            "access_code": f"{access_code}",
        }
    )


from .models import AutoInvest


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def autoinvest(request):
    user = request.user
    amount = request.data.get("amount")
    frequency = request.data.get("frequency")

    # Validate request data
    if not all([amount, frequency]):
        return Response(
            {"error": "Missing required fields: card_id, amount, and frequency."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = int(amount)
        if amount < 100000:
            return Response(
                {"error": "Amount cannot be less than N100,000."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    except ValueError:
        return Response(
            {"error": "Invalid amount. Amount should be a number."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    valid_frequencies = ["hourly", "daily", "weekly", "monthly"]
    if frequency not in valid_frequencies:
        return Response(
            {"error": "Invalid frequency. Choose 'daily', 'weekly', or 'monthly'."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Check for existing AutoInvest records for the user
    if AutoInvest.objects.filter(user=user, frequency=frequency, active=True).exists():
        return Response(
            {
                "error": f"An active AutoInvest record already exists for frequency: {frequency}."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Check if user has a transaction with a paystack_auth_code
    has_paystack_auth = (
        Transaction.objects.filter(user=user, paystack_auth_code__isnull=False)
        .exclude(paystack_auth_code="")
        .exists()
    )

    if not has_paystack_auth:
        return Response(
            {
                "error": "You need to do a QuickSave/QuickInvest before you can activate AutoInvest"
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Prepare Paystack plan creation request
    plan_payload = {
        "name": f"{frequency.capitalize()} AutoInvest Plan for {user.email}",
        "interval": frequency,
        "amount": amount * 100,  # Convert amount to kobo
    }

    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }

    # Step 1: Create subscription plan on Paystack
    try:
        plan_response = requests.post(
            "https://api.paystack.co/plan", json=plan_payload, headers=headers
        )
        plan_response.raise_for_status()
        plan_data = plan_response.json()
        plan_code = plan_data["data"]["plan_code"]
    except requests.RequestException as e:
        logger.error(f"Paystack plan creation failed: {e}")
        return Response(
            {"error": "Failed to create plan on Paystack."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 2: Subscribe user to the plan
    subscription_payload = {"customer": user.email, "plan": plan_code}

    try:
        subscription_response = requests.post(
            "https://api.paystack.co/subscription",
            json=subscription_payload,
            headers=headers,
        )
        subscription_response.raise_for_status()
        subscription_data = subscription_response.json()
        subscription_id = subscription_data.get("data", {}).get("id")
        subscription_code = subscription_data.get("data", {}).get("subscription_code")
        subscription_token = subscription_data.get("data", {}).get("email_token")
        transaction_reference = subscription_data.get("data", {}).get("reference")
    except requests.RequestException as e:
        logger.error(f"Subscription failed: {e}")
        return Response(
            {"error": "Subscription failed."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 3: Save AutoInvest record to the database
    with transaction.atomic():
        AutoInvest.objects.create(
            user=user,
            frequency=frequency,
            amount=amount,
            paystack_sub_id=subscription_id,
            paystack_sub_code=subscription_code,
            paystack_sub_token=subscription_token,
            paystack_plan_code=plan_code,
            paystack_trans_ref=transaction_reference,
            active=True,
        )

    # Send success notification email
    subject = "AutoInvest Activated!"
    message = f"Hi {user.first_name},<br><br>Your AutoInvest have been activated. You are now saving ₦{amount} {frequency}.<br><br>Keep growing your funds.🥂"
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_generic_email(subject, message, from_email, recipient_list)

    return Response({"message": "AutoInvest activated"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def deactivate_autoinvest(request):
    user = request.user
    frequency = request.data.get("frequency")

    if not frequency:
        return Response(
            {
                "error": "Frequency Missing: Please, provide the frequency of the autoinvest."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        # Find all active AutoInvest for the user with the given frequency
        active_autoinvest = AutoInvest.objects.filter(
            user=user, frequency=frequency, active=True
        )

        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }

        for autoinvest in active_autoinvest:

            # print(f"autoinvest: {autoinvest}")

            if autoinvest.paystack_sub_id and autoinvest.paystack_sub_token:
                # Prepare the data for the request
                data = {
                    "code": autoinvest.paystack_sub_code,
                    "token": autoinvest.paystack_sub_token,
                }

                # Log the data being sent
                # print("Disabling AutoInvest subscription with data:", data)

                # Make the API request
                deactivate_response = requests.post(
                    "https://api.paystack.co/subscription/disable",
                    json=data,
                    headers=headers,
                )

                # Check for successful response
                deactivate_response.raise_for_status()  # Raises an HTTPError for bad responses

                # Deactivate the AutoInvest
                autoinvest.active = False
                autoinvest.save()
                autoinvest.delete()
            else:
                autoinvest.delete()
                return Response(
                    {
                        "error": "Paystack subscription details are missing for one or more AutoInvest"
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        user.autoinvest_enabled = False
        user.save()

        # Send a confirmation email
        subject = "AutoInvest Deactivated!"
        message = f"Hi {user.first_name},<br><br>Your {frequency} AutoInvest subscription have been deactivated. <br><br>Keep growing your funds.🥂"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_generic_email(subject, message, from_email, recipient_list)

        # Return a success response indicating that AutoInvest has been deactivated
        return Response(
            {"message": "AutoInvest deactivated"}, status=status.HTTP_200_OK
        )

    except requests.RequestException as e:
        return Response(
            {
                "error": f"Failed to deactivate AutoInvest subscription on Paystack: {str(e)}"
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_autoinvest_status(request):
    user = request.user
    autoinvest_enabled = user.autoinvest_enabled

    # Retrieve the user's active auto-invest settings
    try:
        active_autoinvest = AutoInvest.objects.get(user=user, active=True)
        autoInvestSettings = {
            "active": True,
            "amount": active_autoinvest.amount,
            "frequency": active_autoinvest.frequency,
        }

        # Fetch subscription status from Paystack
        subscription_id = active_autoinvest.paystack_sub_id
        paystack_url = f"https://api.paystack.co/subscription/{subscription_id}"

        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",  # Ensure secure handling of secret keys
            "Content-Type": "application/json",
        }

        response = requests.get(paystack_url, headers=headers)

        if response.status_code == 200:
            subscription_data = response.json()
            subscription_status = subscription_data.get("data", {}).get("status")
            autoInvestSettings["subscription_status"] = subscription_status
        else:
            autoInvestSettings = {
                "active": False,
                "amount": 0,
                "frequency": "",
                "subscription_status": None,
            }

    except AutoInvest.DoesNotExist:
        autoInvestSettings = {
            "active": False,
            "amount": 0,
            "frequency": "",
            "subscription_status": None,
        }

    except requests.RequestException as e:
        return Response(
            {"error": f"Request to Paystack failed: {str(e)}"},
            status=status.HTTP_502_BAD_GATEWAY,
        )

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response(
        {
            "autoinvest_enabled": autoinvest_enabled,
            "autoInvestSettings": autoInvestSettings,
        },
        status=status.HTTP_200_OK,
    )


from decimal import Decimal
import uuid  # Import the uuid library

random_uuid = uuid.uuid4()


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def savings_to_investment(request):
    user = request.user

    # Ensure user is authenticated
    if not user or not user.is_authenticated:
        return Response(
            {"error": "Authentication credentials were not provided."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Validate and parse amount
    amount_raw = request.data.get("amount", None)
    if amount_raw is None:
        return Response(
            {"error": "Amount is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = Decimal(amount_raw)
    except (InvalidOperation, TypeError):
        return Response(
            {"error": "Invalid amount format."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        return Response(
            {"error": "Amount must be greater than zero."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
            # Refresh user to get latest balance and lock row for update
            user = user.__class__.objects.select_for_update().get(pk=user.pk)

            if user.savings < amount:
                return Response(
                    {"error": "Insufficient savings balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use full UUID for transaction IDs (no truncation)
            debit_transaction_id = str(uuid.uuid4())[:16]
            credit_transaction_id = str(uuid.uuid4())[:16]

            # Create debit transaction
            debit_transaction = Transaction(
                user=user,
                transaction_type="debit",
                status="confirmed",
                amount=amount,
                description="Savings > Investment",
                transaction_id=debit_transaction_id,
                service_charge=0.0,
                total_amount=amount,
            )
            debit_transaction.save()

            # Create credit transaction
            credit_transaction = Transaction(
                user=user,
                transaction_type="credit",
                status="confirmed",
                amount=amount,
                description="QuickInvest",
                transaction_id=credit_transaction_id,
                service_charge=0.0,
                total_amount=amount,
            )
            credit_transaction.save()

            # Update user balances
            user.savings -= amount
            user.investment += amount
            user.save()

    except Transaction.DoesNotExist:
        return Response(
            {"error": "User account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except IntegrityError:
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {
            "message": "Savings to investment transfer successful.",
            "debit_transaction_id": debit_transaction_id,
            "credit_transaction_id": credit_transaction_id,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_to_savings(request):
    user = request.user

    # Ensure user is authenticated
    if not user or not user.is_authenticated:
        return Response(
            {"error": "Authentication credentials were not provided."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Validate and parse amount
    amount_raw = request.data.get("amount", None)
    if amount_raw is None:
        return Response(
            {"error": "Amount is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = Decimal(amount_raw)
    except (InvalidOperation, TypeError):
        return Response(
            {"error": "Invalid amount format."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        return Response(
            {"error": "Amount must be greater than zero."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
            # Lock user record to prevent race conditions
            user = user.__class__.objects.select_for_update().get(pk=user.pk)

            if user.wallet < amount:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use full UUID for transaction IDs with clear suffixes
            base_transaction_id = str(uuid.uuid4())[:16]

            debit_transaction = Transaction(
                user=user,
                transaction_type="debit",
                status="confirmed",
                amount=amount,
                total_amount=amount,
                description="Wallet > Savings",
                transaction_id=base_transaction_id + "-D",
            )
            debit_transaction.save()

            credit_transaction = Transaction(
                user=user,
                transaction_type="credit",
                status="confirmed",
                amount=amount,
                total_amount=amount,
                description="QuickSave (Transfer)",
                transaction_id=base_transaction_id + "-C",
            )
            credit_transaction.save()

            # Update balances
            user.wallet -= amount
            user.savings += amount
            user.save()

    except user.DoesNotExist:
        return Response(
            {"error": "User account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except IntegrityError:
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {
            "message": "Wallet to savings transfer successful.",
            "transaction_id": base_transaction_id,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_to_investment(request):
    user = request.user

    # Ensure user is authenticated
    if not user or not user.is_authenticated:
        return Response(
            {"error": "Authentication credentials were not provided."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Validate and parse amount
    amount_raw = request.data.get("amount", None)
    if amount_raw is None:
        return Response(
            {"error": "Amount is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = Decimal(amount_raw)
    except (InvalidOperation, TypeError):
        return Response(
            {"error": "Invalid amount format."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        return Response(
            {"error": "Amount must be greater than zero."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
            # Lock user record to prevent race conditions
            user = user.__class__.objects.select_for_update().get(pk=user.pk)

            if user.wallet < amount:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use full UUID as base transaction ID
            base_transaction_id = str(uuid.uuid4())[:16]

            debit_transaction = Transaction(
                user=user,
                transaction_type="debit",
                status="confirmed",
                amount=amount,
                total_amount=amount,
                description="Wallet > Investment",
                transaction_id=base_transaction_id + "-D",
            )
            debit_transaction.save()

            credit_transaction = Transaction(
                user=user,
                transaction_type="credit",
                status="confirmed",
                amount=amount,
                total_amount=amount,
                description="QuickInvest (Transfer)",
                transaction_id=base_transaction_id + "-C",
            )
            credit_transaction.save()

            # Update user balances
            user.wallet -= amount
            user.investment += amount
            user.save()

    except user.DoesNotExist:
        return Response(
            {"error": "User account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except IntegrityError:
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {
            "message": "Wallet to investment transfer successful.",
            "transaction_id": base_transaction_id,
        },
        status=status.HTTP_200_OK,
    )


import uuid
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db import IntegrityError
from django.core.mail import send_mail
from authentication.models import BankAccount, Transaction, WithdrawalsRequestToAdmin


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def withdraw_to_local_bank(request):
    User = get_user_model()
    user = request.user
    source_account = request.data.get("source_account", "").strip().lower()
    target_bank_account_id = request.data.get("target_bank_account_id", "")
    amount_raw = request.data.get("amount", 0)

    # 1️⃣ Validate inputs
    if not source_account:
        return Response({"error": '"source_account" was NOT provided.'}, status=400)
    if not target_bank_account_id:
        return Response(
            {"error": '"target_bank_account_id" was NOT provided.'}, status=400
        )
    # when amount is not provided
    if not request.data.get("amount", 0):
        return Response(
            {"error": '"amount" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    amount = Decimal(request.data.get("amount", 0)).quantize(
        Decimal("0.00"), rounding=ROUND_HALF_EVEN
    )

    VALID_SOURCES = ["savings", "investment", "wallet"]

    if source_account not in VALID_SOURCES:
        return Response({"error": "Invalid source account."}, status=400)

    try:
        if amount <= 0:
            return Response({"error": "Amount must be greater than zero."}, status=400)
    except:
        return Response({"error": "Invalid amount format."}, status=400)

    # 2️⃣ Check user balance (do NOT debit yet)
    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=request.user.pk)
        if source_account == "savings" and user.savings < amount:
            return Response({"error": "Insufficient savings balance."}, status=400)
        if source_account == "investment" and user.investment < amount:
            return Response({"error": "Insufficient investment balance."}, status=400)
        if source_account == "wallet" and user.wallet < amount:
            return Response({"error": "Insufficient wallet balance."}, status=400)

        # 3️⃣ Verify bank account ownership
        try:
            target_bank_account = BankAccount.objects.get(
                id=target_bank_account_id, user=user
            )
        except BankAccount.DoesNotExist:
            return Response({"error": "Target bank account not found."}, status=400)

        # 4️⃣ Compute service charge & net amount
        pct = (
            10
            if source_account == "savings"
            else 15 if source_account == "investment" else 0
        )
        service_charge = (pct / Decimal(100)) * amount
        withdrawal_amount = amount - service_charge
        reference_code = generate_reference()
        transaction_id = f"withdrawal-{reference_code}"

        try:
            # 5️⃣ Create pending transaction
            transaction_details = Transaction.objects.create(
                user=user,
                transaction_type="debit",
                status="pending",
                amount=withdrawal_amount,
                service_charge=service_charge,
                total_amount=amount,
                description=f"{source_account.capitalize()} > Bank . . .",
                transaction_id=transaction_id,
            )

            # 6️⃣ Hit Paystack first
            paystack_response = make_withdrawal_through_paystack(
                user, target_bank_account, withdrawal_amount, transaction_id
            )
            print("Paystack API Response:", paystack_response)

            if paystack_response.get("status"):
                # 7️⃣ On success, debit user
                if source_account == "savings":
                    user.savings -= amount
                elif source_account == "investment":
                    user.investment -= amount
                else:
                    user.wallet -= amount
                user.save()

                transaction_details.status = "confirmed"
                transaction_details.save()

                # 8️⃣ Email user
                subject = f"Withdrawal Successful: ₦{amount}"
                message = (
                    f"Hi {user.first_name},<br><br>"
                    f"Your withdrawal of ₦{amount} from your {source_account} account has been sent to {target_bank_account.bank_name}.<br><br>"
                    "Thank you for using MyFund! 🥂<br><br>"
                )

                send_generic_email(
                    subject, message, "MyFund <info@myfundmobile.com>", [user.email]
                )

                return Response(
                    {
                        "success": True,
                        "message": paystack_response.get("message"),
                        "transaction_id": transaction_id,
                        "updated_balance": {
                            "savings": user.savings,
                            "investment": user.investment,
                            "wallet": user.wallet,
                        },
                    },
                    status=200,
                )

            # 9️⃣ On PAYSTACK FAILURE → **manual fallback**:
            # — first, **debit** the user so their balance reflects the pending withdrawal
            if source_account == "savings":
                user.savings -= amount
            elif source_account == "investment":
                user.investment -= amount
            else:
                user.wallet -= amount
            user.save()

            # — record the admin‐processed request
            WithdrawalsRequestToAdmin.objects.create(
                user=user,
                amount=amount,
                transaction_id=transaction_id,
                source_account=source_account,
                target_bank=target_bank_account.bank_name,
                target_account_number=target_bank_account.account_number,
                withdrawal_type="immediate",
                is_approved=False,
            )

            # 🔔 Send push notification on Paystack failure (manual processing fallback)
            send_push_notification(
                user=user,
                title="Withdrawal Processing... ⏳",
                message="Your withdrawal request has been received and will be processed shortly. You'll get a confirmation by mail once it's completed.",
                data={
                    "amount": str(amount),
                    "transaction_id": transaction_id,
                    "source_account": source_account,
                    "type": "Withdrawal",
                    "status": "pending_manual",
                },
                notif_type="PENDING",  # Suitable here since it's in progress
            )

            # — notify the user
            subject = f"Withdrawal of ₦{amount} Processing..."
            message = (
                f"Hi {user.first_name},<br><br>"
                f"We've received your request to withdraw ₦{amount}. It'll be processed within the hour.<br><br>"
                "Thank you for using MyFund!<br><br>"
            )

            send_generic_email(
                subject, message, "MyFund <info@myfundmobile.com>", [user.email]
            )

            # — notify admin
            subj_admin = f"[CHECK] {user.first_name} Wants to Withdraw ₦{amount}"
            msg_admin = (
                f"User: {user.first_name} {user.last_name}<br>"
                f"Amount: ₦{amount}<br>"
                f"Bank: {target_bank_account.bank_name} ({target_bank_account.account_number})<br>"
                f"Transaction ID: {transaction_id}<br>"
                "Reason: automatic Paystack withdrawal failed; manual processing required."
            )

            send_generic_email(
                subj_admin,
                msg_admin,
                "MyFund <info@myfundmobile.com>",
                ["admin@myfundmobile.com"],
            )

            # 0️⃣ Return 200 with success:false so front end enters “processing” flow
            return Response(
                {
                    "success": False,
                    "message": "Automatic withdrawal failed. We’re processing it manually.",
                    "transaction_id": transaction_id,
                },
                status=200,
            )

        except IntegrityError:
            return Response(
                {"error": "Transaction conflict, please retry."}, status=400
            )

        except Exception as e:
            print("Error in withdraw_to_local_bank:", e)
            return Response(
                {"error": "Server error, please try again later."}, status=500
            )


import string
import random
import string
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta  # Import these


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def process_withdrawal_to_local_bank(request):
    user = request.user
    data = request.data

    print("✅ STEP 1: Received withdrawal request:", data)

    source_account = data.get("source_account", "").strip().lower()
    target_bank_account_id = data.get("target_bank_account_id")
    amount = data.get("amount")
    withdrawal_type = (
        data.get("withdrawal_type", "immediate").strip().lower()
    )  # Capture withdrawal type

    if not source_account:
        print("❌ source_account not provided.")
        return Response(
            {"error": '"source_account" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    VALID_SOURCES = ["savings", "investment", "wallet"]

    if source_account not in VALID_SOURCES:
        return Response({"error": "Invalid source account."}, status=400)

    if not target_bank_account_id:
        print("❌ target_bank_account_id not provided.")
        return Response(
            {"error": '"target_bank_account_id" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        target_bank_account_id = int(target_bank_account_id)
        amount = Decimal(amount)
        print("✅ STEP 2: Parsed target_bank_account_id and amount.")
    except (ValueError, TypeError, InvalidOperation) as e:
        print(f"❌ STEP 2 ERROR: Invalid input for amount or bank_account_id: {e}")
        return Response(
            {"error": '"amount" or "target_bank_account_id" is invalid.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        print("❌ STEP 3: Invalid amount <= 0.")
        return Response(
            {"error": "Invalid withdrawal amount."}, status=status.HTTP_400_BAD_REQUEST
        )

    # Check user balance (ensure these attributes exist on your User model or a related profile)
    # The deduction will now happen within the atomic block, but this initial check is still crucial.
    if source_account == "savings":
        if not hasattr(user, "savings") or user.savings < amount:
            print("❌ STEP 4: Insufficient savings balance or attribute missing.")
            return Response(
                {"error": "Insufficient savings balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    elif source_account == "investment":
        if not hasattr(user, "investment") or user.investment < amount:
            print("❌ STEP 4: Insufficient investment balance or attribute missing.")
            return Response(
                {"error": "Insufficient investment balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    elif source_account == "wallet":
        if not hasattr(user, "wallet") or user.wallet < amount:
            print("❌ STEP 4: Insufficient wallet balance or attribute missing.")
            return Response(
                {"error": "Insufficient wallet balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        print("❌ STEP 4: Invalid source account specified.")
        return Response(
            {"error": "Invalid source account."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        target_bank_account = BankAccount.objects.get(
            id=target_bank_account_id, user=user
        )
        print("✅ STEP 5: Target bank account validated.")
    except BankAccount.DoesNotExist:
        print("❌ STEP 5: Target bank account not found.")
        return Response(
            {"error": "Target bank account not found."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    transaction_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=20)
    )
    print(f"✅ STEP 6: Generated transaction_id")
    current_datetime = datetime.now()
    processing_date = None
    if withdrawal_type == "scheduled":
        if source_account == "savings":
            processing_date = current_datetime + timedelta(days=30)
        elif source_account == "investment":
            processing_date = current_datetime + timedelta(days=90)
        # Wallet is always immediate, so no scheduled date calculation needed here

    try:
        with transaction.atomic():
            User = get_user_model()

            # Lock user row for update to prevent concurrent modifications
            user_locked = User.objects.select_for_update().get(id=user.id)

            # Re-check balance inside transaction after locking
            if source_account == "savings":
                if not hasattr(user_locked, "savings") or user_locked.savings < amount:
                    return Response(
                        {"error": "Insufficient savings balance."}, status=400
                    )
                user_locked.savings -= amount

            elif source_account == "investment":
                if (
                    not hasattr(user_locked, "investment")
                    or user_locked.investment < amount
                ):
                    return Response(
                        {"error": "Insufficient investment balance."}, status=400
                    )
                user_locked.investment -= amount

            elif source_account == "wallet":
                if not hasattr(user_locked, "wallet") or user_locked.wallet < amount:
                    return Response(
                        {"error": "Insufficient wallet balance."}, status=400
                    )
                user_locked.wallet -= amount

            else:
                return Response({"error": "Invalid source account."}, status=400)

            # Save updated balances
            user_locked.save()

            print(
                f"✅ STEP 7: Amount {amount} deducted from user's {source_account} balance."
            )

            # Withdrawal record
            withdrawal = WithdrawalsRequestToAdmin.objects.create(
                user=user_locked,
                amount=amount,
                transaction_id=transaction_id,
                source_account=source_account,
                target_bank=target_bank_account.bank_name,
                target_account_number=target_bank_account.account_number,
                withdrawal_type=withdrawal_type,  # Save the withdrawal type
                scheduled_processing_date=(
                    processing_date.date() if processing_date else None
                ),  # Save the date part only
                is_approved=False,  # Remains False until admin action
            )
            print("✅ STEP 8: Withdrawal record created.")

            # Transaction record - Status is "pending" because it's waiting for admin approval,
            # but the amount is already "debited" from the user's perspective.
            Transaction.objects.create(
                user=user_locked,
                transaction_id=transaction_id,
                transaction_type="debit",
                status="pending",
                amount=amount,
                description=f"{source_account.capitalize()} > Bank . . .",
                scheduled_date=processing_date.date() if processing_date else None,
            )
            print("✅ STEP 9: Transaction record created.")

            # --- Send email to user (dynamically based on withdrawal_type) ---
            subject = "Withdrawal Request Received"
            user_message_body = ""
            if withdrawal_type == "immediate":
                user_message_body = (
                    f"Your immediate withdrawal request of ₦{amount:,.2f} from your {source_account.capitalize()} account to "
                    f"{target_bank_account.bank_name} ({target_bank_account.account_name} - {target_bank_account.account_number}) "
                    "has been successfully submitted. The amount has been deducted and is pending approval. You will be notified once it is completed."
                )
            elif withdrawal_type == "scheduled" and processing_date:
                user_message_body = (
                    f"Your scheduled withdrawal request of ₦{amount:,.2f} from your {source_account.capitalize()} account to "
                    f"{target_bank_account.bank_name} ({target_bank_account.account_name} - {target_bank_account.account_number}) "
                    f"has been successfully submitted. The amount has been deducted and it is scheduled to be processed into your account on {processing_date.strftime('%A, %B %d, %Y')}."
                )
            else:  # Fallback for unexpected withdrawal type or missing date
                user_message_body = (
                    f"Your withdrawal request of ₦{amount:,.2f} from your {source_account.capitalize()} account to "
                    f"{target_bank_account.bank_name} ({target_bank_account.account_name} - {target_bank_account.account_number}) "
                    "has been successfully submitted. The amount has been deducted and is pending approval. You will be notified once it is processed."
                )

            user_message = (
                f"Hi {user_locked.first_name},<br><br>"
                f"{user_message_body}<br><br>"
                "Thank you for using MyFund.<br><br>"
            )
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user_locked.email]

            send_generic_email(subject, user_message, from_email, recipient_list)

            # ✅ STEP 10.1: Send push notification to user
            if withdrawal_type == "scheduled" and processing_date:
                push_message = (
                    f"Your scheduled withdrawal of ₦{int(amount):,} from your {source_account.capitalize()} account "
                    f"will be processed on {processing_date.strftime('%A, %B %d, %Y')}. You'll be notified once it's completed."
                )
                push_title = "Withdrawal Scheduled 📅"
            else:
                push_message = (
                    f"Your withdrawal of ₦{int(amount):,} from your {source_account.capitalize()} account "
                    "is pending approval. We'll notify you once it’s processed."
                )
                push_title = "Withdrawal Request Pending ⏳"

            send_push_notification(
                user=user_locked,
                title=push_title,
                message=push_message,
                data={
                    "amount": str(amount),
                    "transaction_id": transaction_id,
                    "source_account": source_account,
                    "type": "Withdrawal",
                    "status": (
                        "pending" if withdrawal_type == "immediate" else "scheduled"
                    ),
                    "processing_date": (
                        processing_date.strftime("%Y-%m-%d")
                        if processing_date
                        else None
                    ),
                },
                notif_type="SCHEDULED" if withdrawal_type == "scheduled" else "PENDING",
            )
            print("✅ STEP 10.2: Dynamic push notification sent to user.")

            # --- Send email to admin (with more details and correct recipients) ---
            admin_subject = (
                f"[CHECK] {user_locked.first_name} Wants to Withdraw ₦{amount:,.2f}"
            )
            admin_message = f"""
            Hi Admin,

            A new withdrawal request has been submitted. The user's account has already been debited.
            Please review this request and process the payment manually.

            User: {user_locked.first_name} {user_locked.last_name}
            Email: {user_locked.email}
            Transaction ID: {transaction_id}
            Amount: ₦{amount:,.2f}
            Source Account: {source_account.capitalize()}
            Withdrawal Type: {withdrawal_type.capitalize()}
            Target Bank: {target_bank_account.bank_name}
            Target Account Name: {target_bank_account.account_name}
            Target Account Number: {target_bank_account.account_number}
            Request Date: {withdrawal.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            """
            if withdrawal_type == "scheduled" and processing_date:
                admin_message += f"Scheduled Processing Date: {processing_date.strftime('%A, %B %d, %Y')}<br>"

            admin_message += f"""
            
            Please log in to the admin panel to mark this request as 'Approved' once payment has been made.

            Best regards!
            """
            admin_recipient_list = [
                "company@myfundmobile.com"
            ]  # Changed to the specified admin email

            send_generic_email(
                admin_subject, admin_message, from_email, admin_recipient_list
            )

        return Response(
            {
                "message": "Withdrawal request created and pending approval. Amount deducted from your account.",
                "transaction_id": transaction_id,
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        print("❌ STEP 12: Exception occurred during transaction block.")
        print(f"❌ ERROR: {str(e)}")
        import traceback

        traceback.print_exc()
        return Response(
            {
                "error": "An error occurred while processing your request. Please try again."
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def cancel_scheduled_withdrawal(request):
    user = request.user
    data = request.data

    print("✅ STEP 1: Received cancel scheduled withdrawal request:", data)

    transaction_id = data.get("transaction_id")

    if not transaction_id:
        print("❌ transaction_id not provided.")
        return Response(
            {"error": "Transaction ID is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
            # Lock the withdrawal request and user for update
            withdrawal_request = WithdrawalsRequestToAdmin.objects.select_for_update().get(
                transaction_id=transaction_id,
                user=user,
                withdrawal_type="scheduled",  # Only allow canceling scheduled withdrawals
                is_approved=False,  # Only allow canceling pending withdrawals
            )

            # Lock the user row
            user_locked = User.objects.select_for_update().get(id=user.id)

            print(
                f"✅ STEP 2: Found scheduled withdrawal request for transaction {transaction_id}"
            )

            # Calculate refund amount (99% of original amount)
            refund_amount = withdrawal_request.amount * Decimal("0.99")
            service_charge = withdrawal_request.amount * Decimal("0.01")

            print(
                f"✅ STEP 3: Refund amount: {refund_amount}, Service charge: {service_charge}"
            )

            # Credit the user's savings account with 99% of the amount
            if hasattr(user_locked, "savings"):
                user_locked.savings += refund_amount
                user_locked.save()
                print(f"✅ STEP 4: Credited {refund_amount} to user's savings account")
            else:
                return Response(
                    {"error": "User savings account not found."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Update the withdrawal request to mark it as cancelled
            withdrawal_request.is_approved = (
                True  # Mark as "processed" but in cancelled state
            )
            withdrawal_request.save()
            print("✅ STEP 5: Updated withdrawal request status")

            # ✅ STEP 6: DELETE the original pending transaction instead of updating it
            try:
                original_transaction = Transaction.objects.get(
                    transaction_id=transaction_id, user=user, status="pending"
                )
                original_transaction.delete()  # Remove the pending transaction
                print("✅ STEP 6: Deleted original pending transaction")
            except Transaction.DoesNotExist:
                print("⚠️ Original transaction not found, continuing...")

            # ✅ STEP 7: Create a new credit transaction for the 99% refund to savings
            refund_transaction_id = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )

            Transaction.objects.create(
                user=user_locked,
                transaction_id=refund_transaction_id,
                transaction_type="credit",
                status="confirmed",
                amount=refund_amount,
                description=f"[Refund] Cancelled Withdrawal",
                source="SAVINGS",
            )
            print("✅ STEP 7: Created refund transaction record")

            # ✅ STEP 8: Create a debit transaction for the 1% service charge
            if service_charge > 0:
                service_charge_transaction_id = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=20)
                )

                Transaction.objects.create(
                    user=user_locked,
                    transaction_id=service_charge_transaction_id,
                    transaction_type="debit",
                    status="confirmed",
                    amount=service_charge,
                    description=f"[Charge] Cancelled Withdrawal",
                    source="SAVINGS",
                )
                print("✅ STEP 8: Created service charge transaction record")

            # --- Send email to user ---
            subject = "Scheduled Withdrawal Cancelled"
            user_message = (
                f"Hi {user_locked.first_name},<br><br>"
                f"Your scheduled withdrawal of ₦{withdrawal_request.amount:,.2f} has been successfully cancelled. "
                f"₦{refund_amount:,.2f} has been refunded to your Savings account (1% service charge of ₦{service_charge:,.2f} applied).<br><br>"
                "Thank you for using MyFund.<br><br>"
            )
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user_locked.email]

            send_generic_email(subject, user_message, from_email, recipient_list)
            print("✅ STEP 9: Sent cancellation email to user")

            # --- Send push notification to user ---
            send_push_notification(
                user=user_locked,
                title="Withdrawal Cancelled ✅",
                message="Your scheduled withdrawal has been cancelled. ₦{:,.2f} has been refunded to your Savings account.".format(
                    float(refund_amount)
                ),
                data={
                    "refund_amount": str(refund_amount),
                    "original_amount": str(withdrawal_request.amount),
                    "service_charge": str(service_charge),
                    "transaction_id": transaction_id,
                    "type": "Withdrawal_Cancellation",
                    "status": "completed",
                },
                notif_type="SUCCESS",
            )
            print("✅ STEP 10: Sent push notification to user")

        return Response(
            {
                "message": "Scheduled withdrawal cancelled successfully.",
                "refund_amount": float(refund_amount),
                "service_charge": float(service_charge),
                "original_amount": float(withdrawal_request.amount),
                "new_savings_balance": float(user_locked.savings),
            },
            status=status.HTTP_200_OK,
        )

    except WithdrawalsRequestToAdmin.DoesNotExist:
        print("❌ Withdrawal request not found or already processed")
        return Response(
            {"error": "Scheduled withdrawal not found or already processed."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except Exception as e:
        print("❌ Exception occurred during cancellation:")
        print(f"❌ ERROR: {str(e)}")
        import traceback

        traceback.print_exc()
        return Response(
            {
                "error": "An error occurred while cancelling the scheduled withdrawal. Please try again."
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


import logging


def create_paystack_recipient(bank_name, account_number, bank_code):
    try:
        # Make a request to the Paystack API to create a recipient
        url = "https://api.paystack.co/transferrecipient"
        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }
        data = {
            "type": "nuban",
            "name": bank_name,
            "account_number": account_number,
            "bank_code": bank_code,  # Use the actual bank code
            "currency": "NGN",
        }

        response = requests.post(url, headers=headers, json=data)

        if response.status_code == status.HTTP_201_CREATED:
            recipient_data = response.json().get("data", {})
            return recipient_data.get("recipient_code")
        else:
            error_message = f"Failed to create Paystack recipient. Paystack API Response: {response.status_code}, {response.text}"
            logger.error(error_message)
            return None
    except Exception as e:
        error_message = f"An error occurred while creating Paystack recipient: {str(e)}"
        logger.error(error_message)
        return None


def make_withdrawal_through_paystack(user, target_bank_account, amount, reference):
    """
    Makes a withdrawal request to Paystack API.
    Generates a valid reference string automatically with prefix.

    Reference string format:
    - Prefix: 'withdrawal-'
    - Suffix: 16-50 characters of lowercase letters, digits, dash, underscore (default 20 chars)
    - Total length will be prefix length + suffix length.
    """

    url = "https://api.paystack.co/transfer"
    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }
    data = {
        "source": "balance",
        "amount": int(amount * 100),  # Amount in kobo (100 kobo = 1 Naira)
        "recipient": target_bank_account.paystack_recipient_code,
        "reference": reference,
    }

    response = requests.post(url, headers=headers, json=data)

    return response.json()


def make_withdrawal_through_admin(user, amount, transaction_id):

    try:

        # Create a WithdrawalsRequestToAdmin record
        request = WithdrawalsRequestToAdmin(
            user=user, amount=amount, transaction_id=transaction_id
        )
        request.save()

        # Send an email to admin
        subject = f"[CHECK] {user.first_name} Made A Withdrawal Request"
        message = f"Hi Admin, <br><br>A withdrawal request of ₦{amount} has just been initiated by {user.first_name} {user.last_name} ({user.email}).<br><br>Please log in to the admin panel for review: https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@myfundmobile.com",
            "cto@myfundmobile.com",
        ]

        send_generic_email(subject, message, from_email, recipient_list)

        # Send a pending quicksave email to the user
        user_subject = "Withdrawal Pending..."
        user_message = f"Hi {user.first_name},<br><br>Your withdrawal of ₦{amount} is pending approval. We will notify you once it's processed. <br><br>Thank you for using MyFund."
        user_email = [user.email]

        send_generic_email(user_subject, user_message, from_email, user_email)

        return {"message": "Withdrawal request created and pending admin approval"}

    except Exception as e:
        # print error
        print(f"\n(Error) make_withdrawal_through_admin():  {e}\n")


from decimal import Decimal

from decimal import Decimal, InvalidOperation
from django.core.mail import send_mail
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import uuid


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_transfer_view(request):  # ✅ NEW NAME
    sender = request.user
    data = request.data
    target_email = data.get("recipient_email")

    try:
        amount = Decimal(str(data.get("amount")))
    except (InvalidOperation, TypeError, ValueError):
        return Response(
            {"error": "Invalid amount format."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        return Response(
            {"error": "Amount must be greater than 0."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Check sender balance
    if sender.wallet < amount:
        return Response(
            {"error": "Insufficient balance in the wallet."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Find recipient
    try:
        target_user = CustomUser.objects.get(email=target_email)
    except CustomUser.DoesNotExist:
        return Response(
            {"error": "Target user not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # Perform transfer
    sender.wallet -= amount
    target_user.wallet += amount
    sender.save()
    target_user.save()

    # Push notification to recipient
    send_push_notification(
        user=target_user,
        title="You've Received ₦{:,.2f} from {}".format(amount, sender.first_name),
        message=f"{sender.first_name} just sent you ₦{amount}. Check your Wallet.",
        data={"amount": str(amount), "from": sender.email},
        notif_type="CREDIT",
    )

    send_push_notification(
        user=sender,
        title="You sent ₦{:,.2f} to {}".format(amount, target_user.first_name),
        message=f"You successfully sent ₦{amount} to {target_user.first_name}.",
        data={"amount": str(amount), "to": target_user.email},
        notif_type="DEBIT",
    )

    # Create transactions
    sender_transaction = Transaction.objects.create(
        user=sender,
        transaction_type="debit",
        status="confirmed",
        amount=amount,
        total_amount=amount,
        transaction_id=str(uuid.uuid4().hex)[:10],
        description=f"Sent to {target_user.first_name}",
    )

    target_transaction = Transaction.objects.create(
        user=target_user,
        transaction_type="credit",
        status="confirmed",
        amount=amount,
        total_amount=amount,
        transaction_id=str(uuid.uuid4().hex)[:10],
        description=f"Received from {sender.first_name}",
    )

    # Send confirmation emails

    subject = f"You Sent ₦{amount} to {target_user.first_name}"
    message = f"Hi {sender.first_name},<br><br>You have successfully transferred ₦{amount} to {target_user.first_name} ({target_user.email}).<br><br>Thank you for using MyFund!"
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [sender.email]

    send_generic_email(subject, message, from_email, recipient_list)

    subject = f"You Received ₦{amount} from {sender.first_name}"
    message = f"Hi {target_user.first_name},<br><br>You have received ₦{amount} from {sender.first_name} ({sender.email}).<br><br>Thank you for using MyFund!"
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [target_user.email]

    send_generic_email(subject, message, from_email, recipient_list)

    return Response({"success": True})


from rest_framework import generics, status
from rest_framework.response import Response
from .models import Property, Transaction
from .serializers import BuyPropertySerializer
from .serializers import PropertySerializer
from datetime import datetime, timedelta
from django.utils import timezone
import uuid


def schedule_rent_reward(user_id, rent_reward, transaction_id, property_name):
    # Calculate the next payment date (365 days from now)
    next_payment_date = timezone.now() + timedelta(days=1)

    # Create a transaction for the rent reward with the unique transaction_id
    transaction = Transaction(
        user_id=user_id,
        transaction_type="credit",
        status="pending",
        amount=rent_reward,
        description="Rent Reward",
        transaction_id=str(uuid.uuid4())[:10],  # 10-character ID
    )

    transaction.save()

    # # Update the user's wallet with the rent reward
    # user = transaction.user
    # user.wallet += Decimal(rent_reward)  # Convert rent_reward to Decimal
    # user.save()

    # # Send an email to the user for the rental income
    # subject = "You've Earned a Rental Income!"
    # message = f"Hi {user.first_name},<br><br>You've received an annual rental income of ₦{rent_reward} from your {property_name} property. Keep growing your portfolio to enjoy more returns on your investment.🥂 <br><br>Thank you for using MyFund!"
    # from_email = "MyFund <info@myfundmobile.com>"
    # recipient_list = [user.email]

    # send_generic_email(subject, message, from_email, recipient_list)


class BuyPropertyView(generics.CreateAPIView):
    queryset = Property.objects.all()
    serializer_class = BuyPropertySerializer
    permission_classes = [IsAuthenticated]  # Make sure the user is authenticated

    def create(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        property = serializer.validated_data["property"]
        num_units = serializer.validated_data["num_units"]
        payment_source = serializer.validated_data.get("payment_source")
        card_id = request.data.get("card_id")

        if property.units_available < num_units:
            return Response(
                {"detail": "Not enough units available for purchase."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        total_price = float(property.price) * num_units

        if payment_source == "savings" and float(user.savings) < total_price:
            return Response(
                {"detail": "Insufficient funds in savings account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        elif payment_source == "investment" and float(user.investment) < total_price:
            return Response(
                {"detail": "Insufficient funds in investment account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        elif payment_source == "wallet" and float(user.wallet) < total_price:
            return Response(
                {"detail": "Insufficient funds in wallet."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if payment_source in ["savings", "investment", "wallet"]:
            if payment_source == "savings":
                user.savings = float(user.savings) - total_price
            elif payment_source == "investment":
                user.investment = float(user.investment) - total_price
            else:  # 'wallet'
                user.wallet = float(user.wallet) - total_price
            user.save()

            property.units_available -= num_units
            property.owner = user
            property.save()

            user.properties += num_units
            user.save()

            rent_reward = float(total_price) * 0.075
            transaction_id = uuid.uuid4()

            # Generate a unique ID with 15 characters
            def generate_short_id():
                unique_id = str(uuid.uuid4().int)
                return unique_id[:10]

            transaction = Transaction(
                user=user,
                transaction_type="debit",
                status="confirmed",
                amount=total_price,
                description=f"Purchase of {property.name}",
                transaction_id=str(uuid.uuid4())[:10],  # 10-character ID
            )

            transaction.save()

            subject = f"Congratulations {user.first_name} on Your Property Purchase!"
            num_units_text = "unit" if num_units == 1 else "units"
            message = f"Hi {user.first_name},<br><br>You've successfully purchased {num_units} {num_units_text} of {property.name} property valued at {property.price}.<br><br>You will earn an annual rental income of ₦{rent_reward} on this property.<br><br>Congratulations on being a landlord!"
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user.email]

            send_generic_email(subject, message, from_email, recipient_list)

            schedule_rent_reward(user.id, rent_reward, uuid.uuid4(), property.name)

            total_price = float(property.price) * num_units

        if payment_source == "saved_cards":
            try:
                # Retrieve the card information
                card = Card.objects.get(id=card_id)
            except Card.DoesNotExist:
                return Response(
                    {"detail": "Selected card not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            card_number = card.card_number
            cvv = card.cvv
            expiry_month = card.expiry_date.split("/")[0]
            expiry_year = card.expiry_date.split("/")[1]

            # Define your payment gateway credentials and headers
            paystack_secret_key = os.environ.get(
                "PAYSTACK_KEY_LIVE",
                default="  ",
            )
            headers = {
                "Authorization": f"Bearer {paystack_secret_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "email": user.email,
                "amount": total_price * 100,  # Amount in kobo
                "card": {
                    "number": card_number,
                    "cvv": cvv,
                    "expiry_month": expiry_month,
                    "expiry_year": expiry_year,
                },
            }

            try:
                # Make a payment request to the payment gateway
                response = requests.post(
                    "https://api.paystack.co/charge", json=payload, headers=headers
                )
                response_data = response.json()
                print(
                    "Payment gateway response:", response_data
                )  # Log the response for debugging

                if response.status_code == 200 and response_data.get("status") is True:
                    # Payment successful, update property ownership and user's properties
                    property.units_available -= num_units
                    property.owner = user
                    property.save()

                    user.properties += num_units
                    user.save()

                    rent_reward = total_price * 0.075

                    transaction = Transaction(
                        user=user,
                        transaction_type="debit",
                        status="confirmed",
                        amount=total_price,
                        description=f"Property purchase: {property.name}",
                        transaction_id=str(uuid.uuid4())[:10],  # 10-character ID
                    )

                    transaction.save()

                    subject = (
                        f"Congratulations {user.first_name} on Your Property Purchase!"
                    )
                    num_units_text = "unit" if num_units == 1 else "units"
                    message = f"Hi {user.first_name},<br><br>You've successfully purchased {num_units} {num_units_text} of {property.name} property valued at {property.price}.<br><br>You will earn an annual rental income of ₦{rent_reward} on this property.<br><br>Congratulations on being a landlord!"
                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = [user.email]

                    send_generic_email(subject, message, from_email, recipient_list)

                    return Response(
                        {"detail": "Property purchased successfully."},
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {"detail": "Payment failed. Please check your card details."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Exception as e:
                print("Payment processing error:", str(e))
                return Response(
                    {"detail": "Payment processing error."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        elif payment_source == "bank_transfer":
            # Implement bank transfer payment confirmation logic here
            pass  # Add your implementation here

        return Response(
            {"detail": "Property purchased successfully."}, status=status.HTTP_200_OK
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_property_details(request):
    try:
        # Get all properties
        properties = Property.objects.all()
        print(f"properties {properties}")

        if properties.exists():
            # Serialize the properties data
            serializer = PropertySerializer(properties, many=True)
            return Response(serializer.data)

        # If no properties are found
        return Response(
            {"message": "No property found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    except Property.DoesNotExist:
        return Response(
            {"message": "Error fetching properties."},
            status=status.HTTP_404_NOT_FOUND,
        )


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
from django.db.models import Q, OuterRef, Subquery, Sum, DecimalField
from django.db.models.functions import Coalesce
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser, Transaction, TopSaverHistory
from .utils import send_push_notification, send_generic_email
import traceback

from datetime import datetime


def get_ordinal_suffix(position):
    """Returns the ordinal suffix for a given position number"""
    if 10 <= position % 100 <= 20:
        return "th"
    else:
        return {1: "st", 2: "nd", 3: "rd"}.get(position % 10, "th")


def send_top_saver_notification(user, old_rank, new_rank):
    """
    Sends tailored push and (optionally) email notifications when a user's Top Saver position changes.
    Rules:
      1. Email notifications only for users in the top 10.
      2. Personalized body (calls user by first name).
      3. Congratulates when moving up or maintaining top position.
      4. Encourages when dropping position.
      5. Includes current month in the message.
    """
    month_name = datetime.now().strftime("%B")  # e.g. "October"
    in_top_3_now = new_rank <= 3

    # Get ordinal suffixes
    new_rank_str = f"{new_rank}{get_ordinal_suffix(new_rank)}"
    old_rank_str = f"{old_rank}{get_ordinal_suffix(old_rank)}" if old_rank else None

    # Build dynamic messages
    if old_rank == 0:
        # first time getting a position
        subject = f"Congratulations, You're Now the {new_rank_str} Top Saver! 🎉"
        push_title = f"You're Now the {new_rank_str} Top Saver! 🎉"
        push_message = (
            f"🎉 Congrats {user.first_name}, You're now the {new_rank_str} Top Saver for {month_name} (was {old_rank_str})! "
            f"Keep growing your funds to move up and earn more as a top saver this {month_name}. Well done! 🚀"
        )
        email_message = (
            f"Hi {user.first_name},<br><br>"
            f"You're now the {new_rank_str} Top Saver for {month_name} (was {old_rank_str})!<br>"
            f"Keep growing your funds to move up and earn more as a top saver this {month_name}. Well done!<br><br>"
            "— The MyFund Team"
        )

    elif new_rank < old_rank:
        # Improved position - Always congratulate for moving up
        subject = f"🎉 Congratulations, You're Now the {new_rank_str} Top Saver! 🎉"
        push_title = f"You're Now the {new_rank_str} Top Saver! 🎉"
        push_message = (
            f"🎉 Congrats {user.first_name}, You're now the {new_rank_str} Top Saver for {month_name} (was {old_rank_str})! "
            f"Keep growing your funds to move up and earn more as a top saver this {month_name}. Well done! 🚀"
        )
        email_message = (
            f"Hi {user.first_name},<br><br>"
            f"You're now the {new_rank_str} Top Saver for {month_name} (was {old_rank_str})!<br>"
            f"Keep growing your funds to move up and earn more as a top saver this {month_name}. Well done! 💫<br><br>"
            "— The MyFund Team"
        )

    elif new_rank > old_rank:
        # Dropped position - No congrats, just notification
        subject = f"You're Now the {new_rank_str} Top Saver"
        push_title = f"You're Now the {new_rank_str} Top Saver"
        push_message = (
            f"Hi {user.first_name}, You're now the {new_rank_str} Top Saver for {month_name} (was {old_rank_str}). "
            f"Keep saving to earn more as a top saver this {month_name}. Well done! 💫"
        )
        email_message = (
            f"Hi {user.first_name},<br><br>"
            f"You're now the {new_rank_str} Top Saver for {month_name} (was {old_rank_str}).<br>"
            f"Keep saving to earn more as a top saver this {month_name}. Well done! 💫<br><br>"
            "— The MyFund Team"
        )

    else:
        # same rank, no change
        return

    # Send push notification to everyone whose position changed
    send_push_notification(
        user=user,
        title=push_title,
        message=push_message,
        data={"old_position": old_rank, "new_position": new_rank, "type": "TopSaver"},
        notif_type="SYSTEM",
    )

    # Only email if user is currently in Top 10
    if in_top_3_now:
        send_generic_email(
            subject,
            email_message,
            "MyFund <info@myfundmobile.com>",
            [user.email],
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_top_savers(request):
    try:
        now = timezone.now()
        current_month = now.month
        current_year = now.year

        with transaction.atomic():
            TopSaverHistory.objects.filter(
                month=current_month, year=current_year
            ).delete()

            CustomUser.objects.all().update(
                total_savings_and_investments_this_month=Coalesce(
                    Subquery(
                        Transaction.objects.filter(
                            user=OuterRef("pk"),
                            date__month=current_month,
                            date__year=current_year,
                        )
                        .filter(
                            Q(status="confirmed", transaction_type="credit")
                            | Q(
                                description__in=[
                                    "AutoSave (Confirmed)",
                                    "AutoInvest (Confirmed)",
                                ]
                            )
                        )
                        .values("user")
                        .annotate(total=Sum("amount"))
                        .values("total"),
                        output_field=DecimalField(),
                    ),
                    0,
                )
            )

            users = CustomUser.objects.filter(
                total_savings_and_investments_this_month__gt=0
            ).order_by("-total_savings_and_investments_this_month")

            top_amount = (
                users.first().total_savings_and_investments_this_month
                if users.exists()
                else 1
            )

            top_savers, top_history_entries, rank_changes = [], [], {}
            rank = 1

            for user in users:
                amount = user.total_savings_and_investments_this_month or 0
                percentage = (
                    round((amount / top_amount) * 100, 1) if top_amount > 0 else 0
                )
                old_rank = getattr(user, "last_top_saver_rank", 0) or 0

                if old_rank != rank:
                    rank_changes[user] = (old_rank, rank)
                    user.last_top_saver_rank = rank
                    user.save(update_fields=["last_top_saver_rank"])

                top_history_entries.append(
                    TopSaverHistory(
                        month=current_month,
                        year=current_year,
                        user=user,
                        total_savings=amount,
                        rank=rank,
                    )
                )

                top_savers.append(
                    {
                        "id": user.id,
                        "first_name": user.first_name or "",
                        "email": user.email or "",
                        "profile_picture": getattr(user.profile_picture, "url", None)
                        or "",
                        "amount": float(amount),
                        "percentage": percentage,
                    }
                )

                rank += 1

            if top_history_entries:
                TopSaverHistory.objects.bulk_create(top_history_entries)

            for user_obj, (old_rank, new_rank) in rank_changes.items():
                send_top_saver_notification(user_obj, old_rank, new_rank)

        current_user = request.user
        current_user_amount = (
            getattr(current_user, "total_savings_and_investments_this_month", 0) or 0
        )
        current_user_percentage = (
            round((current_user_amount / top_amount) * 100, 1) if top_amount > 0 else 0
        )

        return Response(
            {
                "top_savers": top_savers[:50],
                "current_user": {
                    "id": current_user.id,
                    "first_name": current_user.first_name or "",
                    "last_name": current_user.last_name or "",
                    "email": current_user.email or "",
                    "profile_picture": getattr(
                        current_user.profile_picture, "url", None
                    )
                    or "",
                    "percentage": current_user_percentage,
                    "individual_percentage": current_user_percentage,
                },
            }
        )

    except Exception as e:
        traceback.print_exc()
        return Response(
            {"error": str(e), "trace": traceback.format_exc()},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_past_top_savers(request, month, year):
    top_savers = TopSaverHistory.objects.filter(month=month, year=year).order_by("rank")

    if not top_savers.exists():
        return Response(
            {"detail": f"No top savers found for {month}/{year}."},
            status=status.HTTP_404_NOT_FOUND,
        )

    past_top_savers = [
        {
            "id": saver.user.id,
            "first_name": saver.user.first_name,
            "profile_picture": saver.user.profile_picture,
            "total_savings": float(saver.total_savings),
            "rank": saver.rank,
        }
        for saver in top_savers
    ]

    return Response({"past_top_savers": past_top_savers})


from .serializers import KYCUpdateSerializer


class KYCUpdateView(generics.UpdateAPIView):
    serializer_class = KYCUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # If not yet approved, mark as pending and notify user by email
        if user.kyc_status != "Updated!":
            user.kyc_status = "Pending..."
            user.save()

            # 1️⃣ Email to user
            user_subject = "KYC Update Received... 🕒"
            user_message = (
                f"Hi {user.first_name},<br><br>"
                "We’ve received your updated KYC details. "
                "Our team will review them shortly, and we’ll let you know once it’s approved.<br><br>"
                "Thank you for using MyFund.<br><br>"
            )
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user.email]

            send_generic_email(user_subject, user_message, from_email, recipient_list)

        # 2️⃣ Push notification to user
        send_push_notification(
            user=user,
            title="KYC Update Submitted... 🕒",
            message="Thanks for updating your KYC details. We’ll notify you once it’s approved. Thank you for using MyFund.",
            data={"kyc_status": user.kyc_status},
            notif_type="SYSTEM",
        )

        # 3️⃣ Notify admin
        admin_email = ["info@myfundmobile.com", "company@myfundmobile.com"]
        admin_subject = f"KYC Update for {user.first_name} Pending Approval"
        admin_message = (
            f"Hello Admin,<br><br>"
            f"{user.first_name} {user.last_name} ({user.email}) has submitted a KYC update. "
            "Please review it in the admin panel:<br>"
            "https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/.<br><br>"
        )
        send_generic_email(
            admin_subject, admin_message, "MyFund <info@myfundmobile.com>", admin_email
        )

        return Response(serializer.data)


view = KYCUpdateView.as_view()


class GetKYCStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        kyc_status = user.kyc_status
        message = ""

        if kyc_status is None:
            message = "You haven't started your KYC process."
        elif kyc_status == "Pending...":
            message = "KYC status is pending approval."
        elif kyc_status == "Updated!":
            message = "KYC status has been updated."
        elif kyc_status == "Failed":
            message = "KYC update has been rejected."

        return Response(
            {"kycStatus": kyc_status, "message": message}, status=status.HTTP_200_OK
        )


class KYCApprovalViewSet(viewsets.ViewSet):
    def approve_kyc(self, request, pk=None):
        user = CustomUser.objects.get(pk=pk)
        user.kyc_updated = True  # Mark KYC as updated
        user.save()
        # Send an email notification here
        return Response({"message": "KYC Approved"})

    def reject_kyc(self, request, pk=None):
        user = CustomUser.objects.get(pk=pk)
        user.kyc_updated = False  # Mark KYC as not updated
        user.save()
        # Send an email notification here
        return Response({"message": "KYC Rejected"})


from .serializers import (
    AlertMessageSerializer,
)  # Create a serializer for AlertMessage if needed
from .models import AlertMessage


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_alert_message(request):
    user = request.user
    text = request.data.get("text")
    date = request.data.get(
        "date"
    )  # You can set this in your frontend or use server time

    alert_message = AlertMessage(user=user, text=text, date=date)
    alert_message.save()

    return Response(status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_alert_messages(request):
    user = request.user
    alert_messages = AlertMessage.objects.filter(user=user)
    serializer = AlertMessageSerializer(
        alert_messages, many=True
    )  # Use your serializer to format the data

    return Response(serializer.data, status=status.HTTP_200_OK)


from .models import BankTransferRequest, InvestTransferRequest


from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from .models import Notification, User  # Changed from relative import to direct import
from .serializers import NotificationSerializer
from django.shortcuts import get_object_or_404


class NotificationListCreateView(generics.ListCreateAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by(
            "-created_at"
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def mark_notification_as_read(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.is_read = True
    notification.save()
    return Response(status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_all_notifications_as_read(request):
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    return Response(status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_admin_notification(request):
    if not request.user.is_staff:
        return Response(
            {"detail": "Permission denied"}, status=status.HTTP_403_FORBIDDEN
        )

    user_id = request.data.get("user_id")
    title = request.data.get("title")
    message = request.data.get("message")

    if not all([user_id, title, message]):
        return Response(
            {"detail": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    notification = Notification.objects.create(
        user=user, notification_type="ADMIN", title=title, message=message
    )

    return Response(
        NotificationSerializer(notification).data, status=status.HTTP_201_CREATED
    )


# Add this utility function to your views.py or create a separate utils.py
def create_notification(user, notification_type, title, message, data=None):
    notification = Notification.objects.create(
        user=user,
        notification_type=notification_type,
        title=title,
        message=message,
        data=data or {},
    )
    return notification


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_bank_transfer(request):
    try:
        user = request.user
        amount = request.data.get("amount")

        # ✅ Generate a unique transaction ID
        transaction_id = str(uuid.uuid4())[:10]

        # ✅ Create a BankTransferRequest record with transaction_id
        bank_transfer_request = BankTransferRequest(
            user=user, amount=amount, transaction_id=transaction_id
        )
        bank_transfer_request.save()

        # ✅ Create a pending transaction for the user
        current_datetime = timezone.now()
        referral_email = user.referral.email if user.referral else None

        transaction = Transaction.objects.create(
            user=user,
            referral_email=referral_email,
            transaction_type="credit",  # Mark as credit since it's a deposit
            status="pending",
            amount=amount,
            date=current_datetime.date(),
            time=current_datetime.time(),
            description="QuickSave . . .",
            transaction_id=transaction_id,  # ✅ Ensure both records share the same transaction_id
        )
        transaction.save()

        send_push_notification(
            user=user,
            title="QuickSave Pending ⏳",
            message="Your transfer of ₦{:,.2f} is pending approval. We'll notify you once it’s confirmed. Thank you for using MyFund.".format(
                int(amount)
            ),
            data={
                "amount": str(amount),
                "transaction_id": transaction_id,
                "type": "QuickSave",
                "status": "pending",
            },
            notif_type="PENDING",
        )

        # ✅ Notify Admin
        subject = f"[CHECK] {user.first_name} Made A QuickSave Request"
        message = f"Hi Admin,<br><br>A bank transfer request of ₦{amount} has been initiated by {user.first_name} {user.last_name} ({user.email}).<br><br>Review here: https://myfundapi-myfund-07ce351a.koyeb.app/admin/<br><br>MyFund Team"

        send_generic_email(
            subject,
            message,
            "MyFund <info@myfundmobile.com>",
            ["company@myfundmobile.com", "info@myfundmobile.com"],
        )

        # ✅ Notify User
        user_subject = "QuickSave Pending..."
        user_message = f"Hi {user.first_name},<br><br>Your bank transfer request of ₦{amount} is pending approval. We'll notify you once it's processed.<br><br>Thank you for using MyFund. <br><br>"
        send_generic_email(
            user_subject, user_message, "MyFund <info@myfundmobile.com>", [user.email]
        )

        return Response(
            {"message": "Bank transfer request created and pending admin approval"},
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_invest_transfer(request):
    try:
        user = request.user
        amount = request.data.get("amount")

        # Send an email to admin
        subject = f"[CHECK] {user.first_name} Made A QuickInvest Request"
        message = f"Hi Admin, <br><br>An investment transfer request of ₦{amount} has just been initiated by {user.first_name} ({user.email}).<br><br>Please log in to the admin panel for review.<br><br>"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@myfundmobile.com",
        ]  # Replace with the admin's email address

        send_generic_email(subject, message, from_email, recipient_list)

        # Send a pending invest email to the user
        user_subject = "QuickInvest Pending..."
        user_message = f"Hi {user.first_name},<br><br>Your investment transfer request of ₦{amount} is pending approval. We will notify you once it's processed. <br><br>Thank you for using MyFund. <br><br>"
        user_email = user.email

        send_generic_email(user_subject, user_message, from_email, [user_email])

        send_push_notification(
            user=user,
            title="QuickInvest Pending ⏳",
            message="Your transfer of ₦{:,.2f} is pending approval. We'll notify you once it’s confirmed.".format(
                int(amount)
            ),
            data={
                "amount": str(amount),
                "transaction_id": transaction_id,
                "type": "QuickInvest",
                "status": "pending",
            },
            notif_type="PENDING",
        )

        # Create a pending transaction for the user with date and time
        current_datetime = timezone.now()
        referral_email = user.referral.email if user.referral else None

        # ✅ Generate a unique transaction ID
        transaction_id = str(uuid.uuid4())[:10]

        # ✅ Create an InvestTransferRequest record with transaction_id
        invest_transfer_request = InvestTransferRequest(
            user=user, amount=amount, transaction_id=transaction_id
        )
        invest_transfer_request.save()

        # ✅ Create a pending transaction for the user
        current_datetime = timezone.now()
        referral_email = user.referral.email if user.referral else None

        transaction = Transaction.objects.create(
            user=user,
            referral_email=referral_email,
            transaction_type="credit",
            status="pending",
            amount=amount,
            date=current_datetime.date(),
            time=current_datetime.time(),
            description="QuickInvest . . .",
            transaction_id=transaction_id,  # ✅ Ensure both records share the same transaction_id
        )
        transaction.save()

        return Response(
            {
                "message": "Investment transfer request created and pending admin approval"
            },
            status=status.HTTP_201_CREATED,
        )
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_by_email(request):
    email = request.query_params.get("email", "")
    try:
        user = CustomUser.objects.get(email=email)
        user_data = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            # Add any other user details you want to include
        }
        return Response(user_data, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def message_admin(request):
    try:
        email = request.user.email
        first_name = request.user.first_name
        last_name = request.user.last_name
        message = request.data.get("message")
        recipient_email = "care@myfundmobile.com"
        from_email = "info@myfundmobile.com"

        if not message:
            return JsonResponse(
                {"error": "Message is required."},
                status=status.HTTP_200_OK,
            )

        subject = f"Message from {first_name} {last_name}"
        message = f"From: {first_name} {last_name} ({email})<br><br>{message}"

        send_generic_email(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=[recipient_email],
        )

        return JsonResponse({"success": True}, status=status.HTTP_200_OK)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_myfund_pin(request):
    try:
        user = request.user
        myfund_pin = request.data.get("myfund_pin")

        if not myfund_pin:
            return Response(
                {"error": "myfund_pin is required"}, status=status.HTTP_200_OK
            )

        user.myfund_pin = encrypt_data(myfund_pin)
        user.save()

        return JsonResponse(
            {"success": "myfund_pin updated successfully"}, status=status.HTTP_200_OK
        )

    except Exception as e:
        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def has_myfund_pin(request):
    try:
        user = request.user
        has_pin = user.myfund_pin is not None
        return JsonResponse({"has_pin": has_pin}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def validate_myfund_pin(request):
    try:
        user = request.user
        entered_pin = request.data.get("entered_pin")
        myfund_pin = user.myfund_pin.tobytes()

        myfund_pin = decrypt_data(myfund_pin)

        if not entered_pin:
            return JsonResponse(
                {"error": "entered_pin is not set"}, status=status.HTTP_200_OK
            )

        if entered_pin == myfund_pin:
            return JsonResponse({"success": True})

        return JsonResponse({"error": "Incorrect Pin"}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

        # Add to your views.py


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_pin_reset_otp(request):
    """Send OTP via email + push"""
    try:
        user = request.user
        if not user.myfund_pin:
            return JsonResponse({"error": "No PIN set for this account"}, status=400)

        otp = "".join(random.choices(string.digits, k=6))
        user.pin_reset_otp = otp
        user.pin_reset_otp_expiry = timezone.now() + timezone.timedelta(minutes=10)
        user.save()

        subject = f"[{otp}] PIN Reset OTP - MyFund"
        message = f"""
        Hi {user.first_name},<br><br>
        Your PIN reset OTP is:<br><br>
        <div style="font-size: 28px; font-weight: bold; text-align: center; color: #2c3e50;">
            {otp}
        </div><br>
        This OTP expires in 10 minutes.<br><br>
        If you didn't request this PIN reset, please contact support immediately.<br><br>
        Best regards,<br>
        MyFund Team
        """
        send_generic_email(
            subject, message, "MyFund <info@myfundmobile.com>", [user.email]
        )

        send_push_notification(
            user,
            title="PIN Reset OTP",
            message="Your MyFund PIN reset OTP has been sent to your registered email. Kindly use it to complete your PIN reset.",
            data={"type": "PIN_RESET"},
            notif_type="SECURITY",
        )
        return JsonResponse({"success": "OTP sent successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": "Failed to send OTP"}, status=500)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_otp_and_reset_pin(request):
    """Verify OTP and reset PIN in one go"""
    try:
        user = request.user
        otp = request.data.get("otp")
        new_pin = request.data.get("new_pin")

        if (
            not user.pin_reset_otp
            or user.pin_reset_otp != otp
            or not user.pin_reset_otp_expiry
            or user.pin_reset_otp_expiry < timezone.now()
        ):
            return JsonResponse({"error": "Invalid or expired OTP"}, status=400)

        if not new_pin or len(new_pin) != 4 or not new_pin.isdigit():
            return JsonResponse({"error": "PIN must be exactly 4 digits"}, status=400)

        user.myfund_pin = encrypt_data(new_pin)
        user.pin_reset_otp = None
        user.pin_reset_otp_expiry = None
        user.save()

        subject = "PIN Reset Successful - MyFund"
        message = f"""
        Hi {user.first_name},<br><br>
        ✅ Your transaction PIN has been successfully reset.<br><br>
        If this wasn't you, please contact support immediately.<br><br>
        Best regards,<br>
        MyFund Team
        """
        send_generic_email(
            subject, message, "MyFund <info@myfundmobile.com>", [user.email]
        )

        send_push_notification(
            user,
            title="PIN Reset Successful",
            message="Your MyFund transaction PIN has been successfully reset.",
            data={"type": "PIN_RESET_SUCCESS"},
            notif_type="SECURITY",
        )
        return JsonResponse({"success": "PIN reset successful"}, status=200)

    except Exception as e:
        return JsonResponse({"error": "Failed to reset PIN"}, status=500)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def paystack_submit_otp(request):
    try:
        entered_otp = request.data.get("entered_otp")
        reference = request.data.get("reference")

        paystack_url = "https://api.paystack.co/charge/submit_otp"

        payload = {"otp": entered_otp, "reference": reference}

        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }

        response = requests.post(paystack_url, json=payload, headers=headers)
        paystack_response = response.json()
        print(paystack_response)

        transaction = Transaction.objects.get(transaction_id=reference)
        description = transaction.description
        description = description.split(" ")

        if paystack_response["data"]["status"] == "failed":
            transaction.transaction_type = "failed"
            transaction.description = description[0] + " (Failed)"
            transaction.save()

        if paystack_response["data"]["status"] == "success":
            user = transaction.user

            transaction.transaction_type = "credit"
            transaction.description = description[0] + " (Card)"
            transaction.save()

            amount = transaction.amount

            if description[0] == "QuickInvest":
                user.investment += int(amount)

                subject = "QuickInvest Successful!"
                message = f"Well done {user.first_name},<br><br>Your QuickInvest was successful and ₦{amount} has been successfully added to your INVESTMENTS account. <br><br>Keep growing your funds.🥂"
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_generic_email(subject, message, from_email, recipient_list)

            if description[0] == "QuickSave":
                user.savings += int(amount)

                # Send a confirmation email
                subject = "QuickSave Successful!"
                message = f"Well done {user.first_name},<br><br>Your QwickSave was successful and ₦{amount} has been successfully added to your SAVINGS account. <br><br>Keep growing your funds.🥂"
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_generic_email(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                )

            user.confirm_referral_rewards(is_referrer=True)
            user.update_total_savings_and_investment_this_month()
            user.save()

        return JsonResponse(paystack_response, status=status.HTTP_200_OK)

    except Exception as e:
        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


import threading
import time

paystack_ips = ["52.31.139.75", "52.49.173.169", "52.214.14.220"]


@api_view(["POST"])
def paystack_webhook(request):
    try:
        event = request.data

        header_data = request.headers

        ip_address = request.headers.get("Cf-Connecting-Ip") or request.get(
            "ip_address"
        )

        ip_is_paystack = ip_address in paystack_ips

        event_status = event["event"]

        # print(str(event))
        print(f"paystack event status: {event_status}")

        if not ip_is_paystack:
            return JsonResponse(
                {
                    "status": False,
                    "message": "Request not from paystack",
                    "ip": ip_address,
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            # Create and Start a thread that process the event in the background
            threading.Thread(
                target=paystack_webhook_processing,
                args=(
                    event,
                    ip_address,
                    ip_is_paystack,
                    header_data,
                ),
            ).start()

            return JsonResponse({"status": True}, status=status.HTTP_200_OK)

    except Exception as e:
        # print error
        print(f"\nPaystack Webhook(Internal Server Error):  {e}\n")

        # Send an email of the error that ocurred
        subject = "Paystack Webhook Error!"
        message = f"Paystack Webhook Internal Server Error:  {e}"

        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]

        send_generic_email(subject, message, from_email, recipient_list)

        return JsonResponse({"error": str(e)}, status=status.HTTP_200_OK)


from .models import WithdrawalsRequestToAdmin


def paystack_webhook_processing(event, ip_address, ip_is_paystack, header_data):
    try:
        # Send a email of the webhook payload
        subject = "Paystack Webhook Received!"
        message = (
            str(event)
            + " ip Address:"
            + str(ip_address)
            + "  verified:"
            + str(ip_is_paystack)
            + " headers:"
            + str(header_data)
        )

        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = ["webhook@myfundmobile.com", "sammy@myfundmobile.com"]

        send_generic_email(subject, message, from_email, recipient_list)

        match event["event"]:
            case "charge.success":
                reference = event["data"]["reference"]
                payment_channel = event["data"]["channel"]
                email = event["data"]["customer"]["email"]
                amount = Decimal(event["data"]["amount"]) / 100
                paystack_auth_code = event["data"]["authorization"][
                    "authorization_code"
                ]
                plan_code = (
                    event["data"]["plan"]["plan_code"]
                    if event["data"]["plan"]
                    else None
                )

                try:
                    user = CustomUser.objects.get(email=email)
                except CustomUser.DoesNotExist:
                    user = None

                    # Send an email of the error that ocurred
                    subject = "[Webhook Error] User NOT Found in DB"
                    message = f"No user found with email {email}."

                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]

                    send_generic_email(subject, message, from_email, recipient_list)

                    return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                try:
                    transaction = Transaction.objects.get(
                        transaction_id=reference, amount=amount
                    )
                except Transaction.DoesNotExist:
                    transaction = None

                    # Send an email of the error that ocurred
                    subject = "[Webhook Error] Referrence ID NOT Found in DB"
                    message = f"No Transaction found with reference {reference} and amount {amount}."

                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]

                    pass

                # Determine if this is an AutoSave/AutoInvest (has plan_code) or QuickSave/QuickInvest (no plan_code)
                if plan_code:
                    # AutoSave or AutoInvest flow
                    autosave = AutoSave.objects.filter(
                        user=user, paystack_plan_code=plan_code, active=True
                    ).first()
                    autoinvest = None
                    if not autosave:
                        autoinvest = AutoInvest.objects.filter(
                            user=user, paystack_plan_code=plan_code, active=True
                        ).first()

                    target = autosave if autosave else autoinvest

                    if not target:
                        # Send an email of the error that ocurred
                        subject = "[Webhook Error] Referrence ID NOT Found in DB"
                        message = f"No Transaction found with reference {reference} and amount {amount}."

                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [
                            "info@myfundmobile.com",
                            "sammy@myfundmobile.com",
                        ]

                        return

                    # Create a new confirmed Transaction for this autosave/autoinvest payment
                    if autosave:
                        # Create transaction if it doesn't exist
                        if not transaction:
                            transaction = Transaction.objects.create(
                                user=user,
                                transaction_type="credit",
                                status="confirmed",
                                amount=Decimal(amount),
                                description=f"AutoSave ({autosave.frequency.capitalize()})",
                                transaction_id=reference,
                                paystack_auth_code=paystack_auth_code,
                            )

                        # Atomically update user's savings
                        transaction.status = "confirmed"
                        transaction.paystack_auth_code = paystack_auth_code
                        transaction.save()

                        user.savings += int(amount)
                        user.update_total_savings_and_investment_this_month()
                        user.save()

                        # Send success email
                        subject = f"AutoSave ({autosave.frequency.capitalize()}) Successful! ✅"
                        message = (
                            f"Well done {user.first_name},<br><br>"
                            f"Your AutoSave was successful and ₦{Decimal(amount):,.2f} has been added to your SAVINGS account."
                        )
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]
                        send_generic_email(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                        )

                        # Send push notification
                        send_push_notification(
                            user=user,
                            title="AutoSave Successful! ✅",
                            message=(
                                f"Your scheduled AutoSave of ₦{Decimal(amount):,.2f} "
                                f"({autosave.frequency.capitalize()}) has just been deposited into your savings."
                            ),
                            data={
                                "amount": str(amount),
                                "frequency": autosave.frequency,
                                "transaction_id": reference,
                                "type": "AutoSave",
                                "status": "confirmed",
                            },
                            notif_type="CREDIT",
                        )

                        print("AutoSave Successfully Credited your Account.")

                        return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                    elif autoinvest:
                        # Create transaction if it doesn't exist
                        if not transaction:
                            transaction = Transaction.objects.create(
                                user=user,
                                transaction_type="credit",
                                status="confirmed",
                                amount=Decimal(amount),
                                description=f"AutoInvest ({autoinvest.frequency.capitalize()})",
                                transaction_id=reference,
                                paystack_auth_code=paystack_auth_code,
                            )

                        transaction.status = "confirmed"
                        transaction.paystack_auth_code = paystack_auth_code
                        transaction.save()

                        user.investment += int(amount)
                        user.update_total_savings_and_investment_this_month()
                        user.save()

                        # Send success email
                        subject = f"AutoInvest ({autoinvest.frequency.capitalize()}) Successful! 🎉"
                        message = (
                            f"Well done {user.first_name},<br><br>"
                            f"Your AutoInvest was successful and ₦{Decimal(amount):,.2f} "
                            f"has been added to your INVESTMENT account."
                        )
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]
                        send_generic_email(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                        )

                        # Send push notification
                        send_push_notification(
                            user=user,
                            title="AutoInvest Successful! 🎉",
                            message=(
                                f"Your scheduled AutoInvest of ₦{Decimal(amount):,.2f} "
                                f"({autoinvest.frequency.capitalize()}) has just been deposited into your investments."
                            ),
                            data={
                                "amount": str(amount),
                                "frequency": autoinvest.frequency,
                                "transaction_id": reference,
                                "type": "AutoInvest",
                                "status": "confirmed",
                            },
                            notif_type="CREDIT",
                        )

                        print("AutoInvest Successfully Credited your Account.")

                        return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                elif transaction and transaction.description.lower().startswith(
                    "quicksave"
                ):

                    # print("\n====QuickSave Webhook Processing ====\n")
                    transaction.description = f"QuickSave ({payment_channel})"
                    transaction.status = "confirmed"
                    transaction.paystack_auth_code = paystack_auth_code
                    transaction.save()

                    user.savings += int(amount)
                    # user.confirm_referral_rewards(is_referrer=True)
                    user.update_total_savings_and_investment_this_month()
                    user.save()

                    subject = "QuickSave Successful!"
                    message = f"Well done {user.first_name},<br><br>Your <b>QuickSave</b> was successful and <b>₦{amount}</b> has been successfully added to your SAVINGS account. <br><br>Keep growing your funds.🥂<br><br>"
                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = [user.email]

                    send_generic_email(
                        subject,
                        message,
                        from_email,
                        recipient_list,
                    )

                    return JsonResponse(
                        {"status": True}, status=status.HTTP_200_OK
                    )  # Prevent double processing

                elif transaction and transaction.description.lower().startswith(
                    "quickinvest"
                ):
                    transaction.description = f"QuickInvest ({payment_channel})"
                    transaction.status = "confirmed"
                    transaction.paystack_auth_code = paystack_auth_code
                    transaction.save()

                    user.investment += int(amount)
                    # user.confirm_referral_rewards(is_referrer=True)
                    user.update_total_savings_and_investment_this_month()
                    user.save()

                    subject = "QuickInvest Successful!"
                    message = f"Well done {user.first_name},<br><br>Your QuickInvest was successful and ₦{amount} has been successfully added to your INVESTMENTS account. <br><br>Keep growing your funds.🥂<br><br>"
                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = [user.email]

                    send_generic_email(
                        subject,
                        message,
                        from_email,
                        recipient_list,
                    )

                    print("QuickInvest Successfully Credited your Account.")

                    return JsonResponse(
                        {"status": True}, status=status.HTTP_200_OK
                    )  # Prevent double processing

                else:
                    # Handle regular transactions
                    trans_description = []  # <-- Initialize with a default value

                    if transaction is None:
                        trans_description = event["data"]["plan"]["name"].split(" ")
                        amount = event["data"]["amount"] / 100

                        Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status="confirmed",
                            amount=int(amount),
                            description=f"{trans_description[1]}",
                            transaction_id=reference,
                        )

                    # Handle AutoInvest case
                    # Safely access trans_description[1] if it's defined and has enough elements
                    trans_type = (
                        trans_description[1] if len(trans_description) > 1 else ""
                    )

                    if (
                        trans_type == "AutoInvest"
                        or AutoInvest.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                    ):
                        transaction = Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status=(
                                "confirmed"
                                if event["data"]["status"] == "success"
                                else "confirmed"
                            ),
                            amount=int(amount),
                            description=f"{trans_type}",
                            transaction_id=event["data"]["reference"],
                        )

                        user.investment += int(amount)
                        # user.confirm_referral_rewards(is_referrer=True)
                        user.update_total_savings_and_investment_this_month()
                        user.save()

                print(f"transaction before update: {transaction}")

                # Only update AutoSave transactions if they are not already confirmed
                if transaction and transaction.description.lower().startswith(
                    "autosave"
                ):
                    # If already confirmed, do nothing.
                    if transaction.status != "confirmed":
                        autosave_rec = AutoSave.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                        # Use the frequency from autosave_rec; if not available, fall back to the frequency sent in the event
                        freq = (
                            autosave_rec.frequency.capitalize()
                            if autosave_rec and autosave_rec.frequency
                            else event["data"].get("frequency", "").capitalize()
                        )
                        transaction.transaction_type = "credit"
                        transaction.status = "confirmed"
                        transaction.description = f"AutoSave ({freq})"
                        transaction.save(
                            update_fields=["transaction_type", "status", "description"]
                        )

                        user.savings += int(amount)
                        # user.confirm_referral_rewards(is_referrer=True)
                        user.update_total_savings_and_investment_this_month()
                        user.save()
                    else:
                        # Already confirmed: ensure description includes the frequency.
                        autosave_rec = AutoSave.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                        freq = (
                            autosave_rec.frequency.capitalize()
                            if autosave_rec and autosave_rec.frequency
                            else "Confirmed"
                        )
                        # Force-update description even if status is already confirmed
                        transaction.description = f"AutoSave ({freq})"
                        transaction.save(update_fields=["description"])
                else:
                    # For non-AutoSave transactions, follow your existing logic:
                    if event["data"]["status"] != "success":
                        base_desc = transaction.description.split(" ")[0]
                        transaction.status = "failed"
                        transaction.description = f"{base_desc} (Failed)"
                        transaction.save(update_fields=["status", "description"])
                    elif event["data"]["status"] == "success":
                        base_desc = transaction.description.split(" ")[0]
                        transaction.transaction_type = "credit"
                        transaction.status = "confirmed"
                        transaction.description = f"{base_desc} (Card)"
                        transaction.save(
                            update_fields=["transaction_type", "status", "description"]
                        )

                    amount = transaction.amount
                    description = transaction.description

                    if description[0] == "AutoSave":
                        user.savings += int(amount)

                        subject = f"{description[0]} Successful!"
                        message = f"Well done {user.first_name},<br><br>Your {description[0]} was successful and ₦{amount} has been successfully added to your SAVINGS account. <br><br>Keep growing your funds.🥂"
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]

                        send_generic_email(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                        )

                    if description[0] == "AutoInvest":
                        user.investment += int(amount)

                        subject = f"{description[0]} Successful!"
                        message = f"Well done {user.first_name},<br><br>Your {description[0]} was successful and ₦{amount} has been successfully added to your INVESTMENT account. <br><br>Keep growing your funds.🥂<br><br>"
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]

                        send_generic_email(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                        )

                    user.confirm_referral_rewards(is_referrer=True)
                    user.update_total_savings_and_investment_this_month()
                    user.save()

                print(f"transaction after update: {transaction}")

                return
            case "invoice.create":
                # sub_code = event["data"]["subscription"]["subscription_code"]
                # sub_token = event["data"]["subscription"]["email_token"]
                # email = event["data"]["customer"]["email"]
                # trans_ref = event["data"]["transaction"]["reference"]
                # user = CustomUser.objects.get(email=email)

                # print(f"sub_code: {sub_code}, sub_token: {sub_token}")

                # if AutoSave.objects.get(
                #     paystack_sub_code=sub_code,
                #     paystack_sub_token=sub_token,
                # ):
                #     # print(f"AutoSave has a record with the sub_code: {sub_code} and sub_token: {sub_token}")

                #     amount = event["data"]["amount"] / 100  # convert amount to naira

                #     # Check if a transaction with the same transaction_id already exists
                #     existing_transaction = Transaction.objects.filter(
                #         transaction_id=trans_ref
                #     ).first()

                #     if not existing_transaction:
                #         # Create a new transaction if not found
                #         Transaction.objects.create(
                #             user=user,
                #             transaction_type="credit",
                #             status="pending",
                #             amount=int(amount),
                #             description="AutoSave",
                #             transaction_id=trans_ref,
                #         )

                #     return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                # elif AutoInvest.objects.get(
                #     paystack_sub_code=sub_code,
                #     paystack_sub_token=sub_token,
                # ):
                #     # print(f"AutoInvest has a record with the sub_code: {sub_code} and sub_token: {sub_token}")

                #     amount = event["data"]["amount"] / 100  # convert amount to naira

                #     # Check if a transaction with the same transaction_id already exists
                #     existing_transaction = Transaction.objects.filter(
                #         transaction_id=trans_ref
                #     ).first()

                #     if not existing_transaction:
                #         # Create a new transaction if not found
                #         Transaction.objects.create(
                #             user=user,
                #             transaction_type="credit",
                #             status="pending",
                #             amount=int(amount),
                #             description="AutoInvest",
                #             transaction_id=trans_ref,
                #         )

                #     return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                # else:
                #     print(
                #         f'\n"invoice.create" details does not exist in MyFund database\n'
                #     )
                return

            case "invoice.payment_failed":

                event_data = event["data"]

                # Send an email of the data of the failed payment
                subject = "Paystack Webhook(Payment Failed)"
                message = f"Invoice Data:  <br><br>{event_data}"

                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]

                return JsonResponse({"status": True}, status=status.HTTP_200_OK)

            case "transfer.failed":
                amount = event["data"]["amount"]
                amount = int(amount / 100)  # convert to naira
                reason = event["data"]["reason"]
                transaction_id = event["data"]["transfer_code"]
                bank_name = event["data"]["recipient"]["details"]["bank_name"]
                account_number = event["data"]["recipient"]["details"]["account_number"]
                # print(f"bank_name: {bank_name}")
                # print(f"account_number: {account_number}")

                # Get the user of the failed withdrawal
                user = None
                try:
                    user = BankAccount.objects.get(
                        account_number=account_number,
                    ).user
                except CustomUser.DoesNotExist:
                    print("User does not exist")

                # Create a WithdrawalsRequestToAdmin record
                request = WithdrawalsRequestToAdmin(
                    user=user, amount=amount, transaction_id=transaction_id
                )
                request.save()

                # Send a Withdrawal Request to Admin
                subject = f"[CHECK] {user.first_name} Withdrawal Request FAILED!"
                message = f"Hi Admin, <br><br>A withdrawal request of ₦{amount} that was initiated by {user.first_name} {user.last_name} ({user.email}) has just FAILED!<br><br>Reason for failure: {reason}<br><br>Please log in to the admin panel for review: https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/<br><br>"
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [
                    "company@myfundmobile.com",
                    "info@myfundmobile.com",
                    "sammy@myfundmobile.com",
                ]

                send_generic_email(subject, message, from_email, recipient_list)

                return JsonResponse({"status": True}, status=status.HTTP_200_OK)

    except Exception as e:
        # print error
        print(f"\nPaystack Webhook(Internal Server Error):  {e}\n")

        # Send an email of the error that ocurred
        subject = "Paystack Webhook Error!"
        message = f"Paystack Webhook Internal Server Error:  {e}"

        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]

        send_generic_email(subject, message, from_email, recipient_list)

        return JsonResponse({"error": str(e)}, status=status.HTTP_200_OK)


# ------------------------------ ADMIN SECTION FUNCTIONS

from datetime import timedelta
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from django.shortcuts import get_object_or_404
from django.db import connection  # Add this import at the top
import time


@api_view(["GET"])
def get_all_users(request):
    start = time.time()

    date_range = request.query_params.get("date_range", None)
    now = timezone.now()
    start_date = None

    # Determine date range
    if date_range == "daily":
        start_date = now - timedelta(days=1)
    elif date_range == "weekly":
        start_date = now - timedelta(weeks=1)
    elif date_range == "monthly":
        start_date = now - timedelta(weeks=4)
    elif date_range == "quarterly":
        start_date = now - timedelta(weeks=13)
    elif date_range == "6months":
        start_date = now - timedelta(days=182)
    elif date_range == "yearly":
        start_date = now - timedelta(days=365)

    # Base queryset
    users = CustomUser.objects.filter(is_subscribed=True)

    # Apply date filtering if needed
    if start_date:
        users = users.filter(date_joined__gte=start_date)

    # Annotate counts - MATCHING THE ADMIN IMPLEMENTATION
    users = users.annotate(
        total_referrals=Count(
            "user_transactions",  # Changed from referral_transactions to match your Transaction model
            filter=Q(user_transactions__description__icontains="referral reward"),
            distinct=True,
        ),
        confirmed_referrals=Count(
            "user_transactions",  # Changed from referral_transactions to match your Transaction model
            filter=Q(user_transactions__description__icontains="referral reward")
            & Q(user_transactions__status="confirmed"),
            distinct=True,
        ),
    ).select_related("referral")

    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(["POST"])
def unsubscribe_user(request):
    user_email = request.data.get("email", None)
    if user_email:
        user = get_object_or_404(CustomUser, email=user_email)
        user.is_subscribed = False
        user.save()
        return Response(
            {"message": "You have been unsubscribed."}, status=status.HTTP_200_OK
        )
    return Response({"error": "Email not provided"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def resubscribe_user(request):
    print("Resubscribe endpoint hit")  # Add this for debugging
    user_email = request.data.get("email", None)
    if user_email:
        user = get_object_or_404(CustomUser, email=user_email)
        if not user.is_subscribed:
            user.is_subscribed = True
            user.save()
            return Response(
                {"message": "You have been resubscribed."}, status=status.HTTP_200_OK
            )
        return Response(
            {"message": "You are already subscribed."}, status=status.HTTP_200_OK
        )
    return Response({"error": "Email not provided"}, status=status.HTTP_400_BAD_REQUEST)


import logging
import time
from smtplib import SMTPException
from django.core.mail import EmailMultiAlternatives, get_connection
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import CustomUser  # Adjust import based on your project structure

# Email batching settings
BATCH_SIZE = 15  # Lower batch size for stability
EMAILS_PER_HOUR_LIMIT = 200  # Adjust based on SMTP limits
TIME_BETWEEN_BATCHES = 3600 / EMAILS_PER_HOUR_LIMIT  # Approx. 18s per batch

logger = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_email(request):
    sender = settings.DEFAULT_FROM_EMAIL
    subject = request.data.get("subject")
    body = request.data.get("body")
    recipients = request.data.get("recipients", [])

    if not all([sender, subject, body, recipients]):
        return Response(
            {"message": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST
        )

    failed_recipients = []
    total_recipients = len(recipients)
    logger.info(f"Total recipients: {total_recipients}")

    # Reuse SMTP connection for performance
    connection = get_connection()
    connection.open()

    for i in range(0, total_recipients, BATCH_SIZE):
        batch_recipients = recipients[i : i + BATCH_SIZE]
        logger.info(
            f"Processing batch {i // BATCH_SIZE + 1} with {len(batch_recipients)} recipients"
        )

        email_objects = []
        for recipient_email in batch_recipients:
            try:
                recipient_user = CustomUser.objects.filter(
                    email=recipient_email
                ).first()

                # Personalization placeholders
                placeholder_map = {
                    "{first_name}": (
                        recipient_user.first_name if recipient_user else "User"
                    ),
                    "{last_name}": recipient_user.last_name if recipient_user else "",
                    "{email}": recipient_email,
                    "{wallet}": str(recipient_user.wallet) if recipient_user else "0",
                    "{savings}": str(recipient_user.savings) if recipient_user else "0",
                    "{investment}": (
                        str(recipient_user.investment) if recipient_user else "0"
                    ),
                    "{properties}": (
                        str(recipient_user.properties) if recipient_user else "0"
                    ),
                    "{full_name}": (
                        recipient_user.full_name if recipient_user else "User"
                    ),
                    "{total_savings_and_investments_this_month}": (
                        str(recipient_user.total_savings_and_investments_this_month)
                        if recipient_user
                        else "0"
                    ),
                    "{top_saver_percentage}": (
                        str(recipient_user.top_saver_percentage)
                        if recipient_user
                        else "0"
                    ),
                }

                personalized_subject = subject
                personalized_body = body
                for placeholder, value in placeholder_map.items():
                    personalized_subject = personalized_subject.replace(
                        placeholder, value
                    )
                    personalized_body = personalized_body.replace(placeholder, value)

                # Create Email Object (Batched BCC Sending)
                email = EmailMultiAlternatives(
                    subject=personalized_subject,
                    body=personalized_body,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    bcc=[recipient_email],  # Use BCC to reduce load
                    connection=connection,  # Use the same connection for all emails
                )
                email.attach_alternative(personalized_body, "text/html")
                email_objects.append(email)

            except Exception as e:
                logger.error(f"Error preparing email for {recipient_email}: {str(e)}")
                failed_recipients.append(recipient_email)

        # Send batched emails together
        try:
            if email_objects:
                connection.send_messages(email_objects)
                logger.info(f"Batch {i // BATCH_SIZE + 1} sent successfully")
        except SMTPException as e:
            logger.error(f"SMTP error sending batch {i // BATCH_SIZE + 1}: {str(e)}")
            failed_recipients.extend(batch_recipients)

        time.sleep(TIME_BETWEEN_BATCHES)  # Controlled delay between batches

    connection.close()  # Close SMTP connection

    if failed_recipients:
        return Response(
            {
                "message": "Emails sent with some failures.",
                "failed_recipients": failed_recipients,
            },
            status=status.HTTP_207_MULTI_STATUS,
        )
    else:
        return Response(
            {"message": "All emails sent successfully!"}, status=status.HTTP_200_OK
        )


from .models import EmailTemplate
from .serializers import EmailTemplateSerializer
from django.views.decorators.http import require_http_methods

import logging


@api_view(["POST"])
def save_template(request):
    try:
        data = request.data
        title = data.get("title")
        design_body = data.get("designBody")
        design_html = data.get("designHTML")
        last_update = data.get("lastUpdate")

        # Create or update template
        template, created = EmailTemplate.objects.update_or_create(
            title=title,
            defaults={
                "design_body": design_body,
                "design_html": design_html,
                "last_update": last_update,
            },
        )

        serializer = EmailTemplateSerializer(template)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error saving template: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def get_templates(request):
    try:
        templates = EmailTemplate.objects.all()
        serializer = EmailTemplateSerializer(templates, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching templates: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["DELETE"])
def delete_template(request, template_id):
    try:
        logger.info(
            f"Attempting to delete template with ID: {template_id}"
        )  # Add logging
        template = EmailTemplate.objects.get(id=template_id)
        template.delete()
        return Response(
            {"message": "Template deleted successfully"}, status=status.HTTP_200_OK
        )
    except EmailTemplate.DoesNotExist:
        logger.warning(
            f"Template with ID {template_id} does not exist."
        )  # Log if template doesn't exist
        return Response(
            {"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error deleting template: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@require_http_methods(["GET"])
def get_template(request, template_id):
    try:
        template = EmailTemplate.objects.get(id=template_id)
        return JsonResponse(
            {
                "id": template.id,
                "title": template.title,
                "design": template.design_body,  # JSON version
                "design_html": template.design_html,  # HTML version
            },
            safe=False,
        )
    except EmailTemplate.DoesNotExist:
        return JsonResponse({"error": "Template not found"}, status=404)


@csrf_exempt
@require_http_methods(["POST"])
def update_template(request, template_id):
    try:
        template = EmailTemplate.objects.get(id=template_id)
        data = json.loads(request.body)
        template.title = data.get("title", template.title)
        template.design_body = data.get(
            "design", template.design_body
        )  # Update this field
        template.save()
        return JsonResponse({"message": "Template updated successfully"})
    except EmailTemplate.DoesNotExist:
        return JsonResponse({"error": "Template not found"}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def first_ever_transaction_in_month(request):
    current_date = timezone.now()
    current_month = current_date.month
    current_year = current_date.year
    User = get_user_model()

    # Get users with their first-ever transaction excluding referral-related ones
    first_transactions = (
        Transaction.objects.exclude(description__icontains="referral")
        .values("user")
        .annotate(first_transaction_date=Min("date"))
        .filter(
            first_transaction_date__year=current_year,
            first_transaction_date__month=current_month,
        )
    )

    # Extract user IDs from the filtered transactions
    user_ids = list(first_transactions.values_list("user", flat=True))

    # Fetch user details based on the filtered user IDs
    users = User.objects.filter(id__in=user_ids).values(
        "id", "first_name", "last_name", "email"
    )

    return Response({"users": list(users)})


"""Group Contribution APIs"""
from .models import Contribution
from .models import Group
from .serializers import GroupSerializer
from .serializers import ContributionSerializer
from django.utils import timezone
from django.core.exceptions import ValidationError

# Group Related APIs


# POST /groups/create - Create a new group buy for a property
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_groupbuy(request):
    if request.method == "POST":
        data = request.data

        # Step 1: Check for required fields (excluding deadline, now optional)
        required_fields = ["property_id", "minimum_contribution", "group_type"]
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            return JsonResponse(
                {"error": f'Missing required fields: {", ".join(missing_fields)}'},
                status=400,
            )

        # Step 2: Validate groupType
        allowed_group_types = ["public", "private"]
        group_type = data["group_type"].lower()
        if group_type not in allowed_group_types:
            return JsonResponse(
                {
                    "error": f'Invalid groupType. Must be one of: {", ".join(allowed_group_types)}'
                },
                status=400,
            )

        # Step 3: Ensure the property exists
        try:
            property_obj = Property.objects.get(id=data["property_id"])
        except Property.DoesNotExist:
            return JsonResponse({"error": "Invalid Property ID"}, status=400)

        # Step 4: Check property availability
        if property_obj.units_available < 1:
            return JsonResponse(
                {"error": "The group limit for this property has already been reached"},
                status=400,
            )

        # Step 5: Handle deadline logic
        now = timezone.now()
        max_deadline = now + timedelta(days=90)

        if "deadline" in data and data["deadline"]:
            try:
                deadline = datetime.strptime(data["deadline"], "%Y-%m-%d")
                deadline = timezone.make_aware(deadline)
            except ValueError:
                return JsonResponse(
                    {"error": "Invalid deadline format. Use YYYY-MM-DD."}, status=400
                )

            if deadline < now:
                return JsonResponse(
                    {"error": "Deadline cannot be in the past."}, status=400
                )

            if deadline > max_deadline:
                return JsonResponse(
                    {"error": "Deadline cannot be more than 3 months from today."},
                    status=400,
                )
        else:
            deadline = max_deadline  # Default deadline to 3 months from now

        # Step 6: Create the group
        group = Group.objects.create(
            property_id=data["property_id"],
            created_by=request.user,
            goal_amount=property_obj.price,
            minimum_contribution=data["minimum_contribution"],
            total_raised=0,
            status="active",
            group_type=group_type,
            deadline=deadline,
        )

        # Reserve a unit
        property_obj.units_available -= 1
        property_obj.save()

        # Step 7: Handle invited users (if group is private)
        warning_message = None
        if group_type == "private":
            invited_emails = data.get("invited_users", [])

            if invited_emails:
                # Validate all emails
                cleaned_emails = set()
                invalid_emails = []

                for email in invited_emails:
                    email = email.strip().lower()
                    try:
                        validate_email(email)
                        cleaned_emails.add(email)
                    except ValidationError:
                        invalid_emails.append(email)

                if cleaned_emails:
                    invited_users = get_user_model().objects.filter(
                        email__in=cleaned_emails
                    )

                    if invited_users.exists():
                        # Add users to group
                        group.invited_users.add(*invited_users)

                        # Send invitation emails
                        subject = (
                            "You're Invited to Join a GroupBuy Investment Opportunity"
                        )
                        join_link = (
                            f"https://myfundmobile.com/groupbuy-invite/{group.id}"
                        )

                        message = (
                            f"Hello,<br><br>"
                            f"You've been invited by <strong>{request.user.first_name} {request.user.last_name}</strong> to join a private property GroupBuy on MyFund.<br><br>"
                            f"GroupBuys allow members to pool funds together and invest in real estate opportunities collaboratively. "
                            f"This is a great way to build wealth with like-minded investors.<br><br>"
                            f"<a href='{join_link}' style='display:inline-block; padding:10px 20px; background-color:#2c7be5; color:#ffffff; "
                            f"text-decoration:none; border-radius:5px;'>Click here to Join the GroupBuy</a><br><br>"
                            f"If the button doesn't work, copy and paste this link into your browser:<br>"
                            f"{join_link}<br><br>"
                            f"Keep growing your funds 🥂<br><br>"
                            f"— The MyFund Team"
                        )

                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email for user in invited_users]

                        try:
                            send_generic_email(
                                subject, message, from_email, recipient_list
                            )
                        except Exception as e:
                            return Response(
                                {"error": f"Failed to send email: {str(e)}"},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            )

                    else:
                        warning_message = (
                            "No registered users found for the provided emails."
                        )

                if invalid_emails:
                    warning_message = f"Some emails were invalid and skipped: {', '.join(invalid_emails)}"

        # Step 8: Return the serialized group
        serializer = GroupSerializer(group)
        response_data = serializer.data
        response_data = dict(serializer.data)
        if warning_message:
            response_data["warning"] = warning_message
        return Response(response_data, status=status.HTTP_201_CREATED)


# GET /groups/:propertyId - Retrieve group buy details for a specific property
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_groupbuy_by_property(request, property_id):
    try:
        group = Group.objects.filter(property_id=property_id)
        if group.exists():
            serializer = GroupSerializer(group, many=True)
            return Response(serializer.data)
        return Response(
            {"message": "No group found for this property."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# GET /groupbuys/ - Retrieve group buy details for a specific property
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_active_public_groupbuys(request):
    try:
        groups = Group.objects.filter(
            status__in=["Active", "active"], group_type="public"
        )
        if groups.exists():
            serializer = GroupSerializer(groups, many=True)
            return Response(serializer.data)
        return Response(
            {"message": "No active public GroupBuy available"},
            status=status.HTTP_404_NOT_FOUND,
        )
    except Exception as e:
        return Response(
            {"message": f"An error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# POST /groups/:groupId/join - Allow a user to join a group
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def join_groupbuy(request, group_id):
    try:
        user = request.user

        # Validate group_id is a valid UUID
        try:
            group_uuid = uuid.UUID(str(group_id))
        except ValueError:
            return Response(
                {"message": "Invalid group ID. It must be a valid UUID."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Attempt to retrieve the group
        try:
            group = Group.objects.get(id=group_uuid)
        except Group.DoesNotExist:
            return Response(
                {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # ✅ Ensure group status is Active
        if group.status.lower() != "active":
            return Response(
                {"message": "You can only join groups that are currently active."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Optional: Deadline check
        if group.deadline < timezone.now():
            return Response(
                {"message": "You cannot join this group. The deadline has passed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if user already joined
        if group.contributors.filter(id=user.id).exists():
            return Response(
                {"message": "You have already joined this group."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check access for private groups
        if group.group_type.lower() == "private":
            if not group.invited_users.filter(id=user.id).exists():
                return Response(
                    {"message": "You are not invited to join this private group."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # Proceed to contribution logic
        return contribute_to_groupbuy(request._request, group_id)

    except Exception as e:
        logger.error(f"Unexpected error in join_group: {e}")

        return Response(
            {"message": "An unexpected error occurred. Please try again later."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# POST /groups/:groupId/invite - Send invitations to users for private groups
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def invite_to_groupbuy(request, group_id):
    # Step 0: Validate group_id format
    if not str(group_id):
        return Response(
            {"message": "Invalid group ID provided."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        group = Group.objects.get(id=group_id)
        user = request.user

        # Step 1: Check if the group is private
        if group.group_type.lower() == "private":
            # Step 2: Check if the requesting user is the group creator
            if group.created_by != user:
                return Response(
                    {"message": "Only the group creator can invite members."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Step 3: Get the list of email addresses to invite
            invited_emails = request.data.get("emails", [])
            if not invited_emails:
                return Response(
                    {"message": "No email addresses provided for invitation."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 4: Validate all emails
            cleaned_emails = set()
            invalid_emails = []

            for email in invited_emails:
                email = email.strip().lower()
                try:
                    validate_email(email)
                    cleaned_emails.add(email)
                except ValidationError:
                    invalid_emails.append(email)

            if not cleaned_emails:
                return Response(
                    {
                        "message": "All provided emails are invalid.",
                        "invalidEmails": invalid_emails,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if invalid_emails:
                # Continue but warn about invalids
                warning_message = (
                    f"Some emails were invalid and skipped: {', '.join(invalid_emails)}"
                )
            else:
                warning_message = None

            # Step 5: Fetch users with those emails
            invited_users = get_user_model().objects.filter(email__in=cleaned_emails)
            if not invited_users.exists():
                return Response(
                    {
                        "message": "No registered users found for the provided email addresses."
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 6: Add the invited users to the group
            group.invited_users.add(*invited_users)

            # Step 7: Send an email to all invited users
            subject = "You're Invited to Join a GroupBuy Investment Opportunity"
            join_link = f"https://myfundmobile.com/groupbuy-invite/{group_id}"

            message = (
                f"Hello,<br><br>"
                f"You've been invited by <strong>{user.first_name} {user.last_name}</strong> to join a private property GroupBuy on MyFund.<br><br>"
                f"GroupBuys allow members to pool funds together and invest in real estate opportunities collaboratively. "
                f"This is a great way to build wealth with like-minded investors.<br><br>"
                f"<a href='{join_link}' style='display:inline-block; padding:10px 20px; background-color:#2c7be5; color:#ffffff; "
                f"text-decoration:none; border-radius:5px;'>Click here to Join the GroupBuy</a><br><br>"
                f"If the button doesn't work, copy and paste this link into your browser:<br>"
                f"{join_link}<br><br>"
                f"Keep growing your funds 🥂<br><br>"
                f"— The MyFund Team"
            )

            from_email = "MyFund <info@myfundmobile.com>"

            recipient_list = [invited_user.email for invited_user in invited_users]
            try:
                send_generic_email(subject, message, from_email, recipient_list)
            except Exception as e:
                return Response(
                    {"error": f"Failed to send email: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            response_data = {"message": "Invitations sent."}
            if warning_message:
                response_data["warning"] = warning_message

            return Response(response_data, status=status.HTTP_200_OK)
        # If the group is not private
        return Response(
            {"message": "This group is not private."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# POST /groups/:groupId/leave - Allow users to exit a group before funding completion
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def leave_groupbuy(request, group_id):
    try:
        group = Group.objects.get(id=group_id)
        user = request.user

        # 1. Disallow leaving if group is completed
        if group.status == "completed":
            return Response(
                {"message": "You cannot leave the group once funding is complete."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2. Ensure user is a contributor
        if not group.contributors.filter(id=user.id).exists():
            return Response(
                {"message": "You are not a member of this group."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 3. Get all confirmed contributions
        contributions = Contribution.objects.filter(
            group=group, user=user, payment_status="Confirmed"
        )

        total_refund = Decimal(0)

        for contribution in contributions:
            amount = contribution.amount
            source = contribution.source

            # Refund to correct account
            if source == "Savings":
                user.savings += amount
            elif source == "Investment":
                user.investment += amount
            elif source == "Wallet":
                user.wallet += amount

            # Mark contribution as refunded
            contribution.payment_status = "Refunded"
            contribution.save()

            total_refund += amount

        user.save()

        # 4. Update group total_raised
        group.total_raised -= total_refund
        group.save()

        # 5. Remove user from contributors list
        group.contributors.remove(user)

        # 6. Remove or update GroupOwnership
        GroupOwnership.objects.filter(group=group, user=user).delete()

        return Response(
            {
                "message": "Successfully left the group. Contributions refunded.",
                "refunded_amount": float(total_refund),
            },
            status=status.HTTP_200_OK,
        )

    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."},
            status=status.HTTP_404_NOT_FOUND,
        )


# GET /users/:userId/groups - Retrieve all groups a user has joined
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_groupbuys(request):
    try:
        # Get the current user
        user = request.user

        # Get all groups the user created or contributed to
        groups = Group.objects.filter(
            Q(created_by=user) | Q(contributors=user)
        ).distinct()

        groups_list = list(groups)

        # Serialize the group data
        serializer = GroupSerializer(groups_list, many=True)

        # Return the serialized data with a 200 OK status
        return Response(serializer.data, status=status.HTTP_200_OK)

    except get_user_model().DoesNotExist:
        return Response(
            {"message": "User not found."}, status=status.HTTP_404_NOT_FOUND
        )


# Contribution Related APIs


# POST /groups/:groupId/contribute - Enable users to contribute funds to a group
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def contribute_to_groupbuy(request, group_id):
    try:
        # 1. Fetch group
        group = Group.objects.get(id=group_id)

        # 2. Check group is active
        if group.status.lower() != "active":
            return Response(
                {"message": "You can only contribute to active groups."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 3. Check deadline
        if timezone.now() > group.deadline:
            return Response(
                {"message": "Contributions are no longer allowed after the deadline."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 4. Check private group invitation
        if (
            group.group_type == "private"
            and not group.invited_users.filter(id=request.user.id).exists()
        ):
            return Response(
                {"message": "You are not an invited contributor to this group."},
                status=status.HTTP_403_FORBIDDEN,
            )

        user = request.user

        # 5. Retrieve and validate input
        try:
            amount = Decimal(request.data.get("amount"))
        except (TypeError, InvalidOperation):
            return Response(
                {"message": "Invalid or missing amount."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if amount <= 0:
            return Response(
                {"message": "Amount must be greater than zero."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        source = request.data.get("source")
        if not source:
            return Response(
                {"message": "Source is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        source = source.capitalize()
        accepted_sources = ["Savings", "Investment", "Wallet"]
        if source not in accepted_sources:
            return Response(
                {
                    "message": f"Invalid source. Accepted values are: {', '.join(accepted_sources)}."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if amount < group.minimum_contribution:
            return Response(
                {
                    "message": f"The minimum contribution for this group is {group.minimum_contribution}."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 6. Check and update user balance
        user_balance = get_user_balance(user, source)
        if user_balance < amount:
            return Response(
                {"message": f"Insufficient {source.lower()} balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 7. Prevent contribution if group is already fully funded
        if group.total_raised >= group.goal_amount:
            return Response(
                {"message": "This group has already reached its funding goal."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 8. Handle overfunding
        total_after = group.total_raised + amount
        excess_amount = max(total_after - group.goal_amount, Decimal("0.00"))

        if excess_amount > 0:
            amount -= excess_amount
            refund_balance = get_user_balance(user, source)
            set_user_balance(user, source, refund_balance + excess_amount)
            user.save()

        # 9. Deduct actual amount
        set_user_balance(user, source, user_balance - amount)
        user.save()

        # 10. Create contribution
        contribution = Contribution.objects.create(
            group=group,
            user=user,
            amount=amount,
            payment_status="Confirmed",
            source=source,
        )

        # 11. Update group total raised
        group.total_raised += amount
        group.save()

        # 12. Ownership calculation
        ownership_obj, _ = GroupOwnership.objects.get_or_create(group=group, user=user)
        ownership_obj.total_contributed += amount
        ownership_obj.ownership_percentage = (
            ownership_obj.total_contributed / group.goal_amount
        ) * 100
        ownership_obj.save()

        # 13. Add user to contributors
        if not group.contributors.filter(id=user.id).exists():
            group.contributors.add(user)

        return Response(
            {"message": "Contribution successful."}, status=status.HTTP_201_CREATED
        )

    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# GET /groups/:groupId/contributions - Fetch all contributions for a group
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_groupbuy_contributions(request, group_id):
    try:
        group = Group.objects.get(id=group_id)

        # Get all ownership records for this group
        ownerships = GroupOwnership.objects.filter(group=group).select_related("user")

        contributions_list = []

        for ownership in ownerships:
            user = ownership.user
            contributions_list.append(
                {
                    "user_id": user.id,
                    "email": user.email,
                    "total_contributed": float(ownership.total_contributed),
                    "ownership_percentage": round(
                        float(ownership.ownership_percentage), 2
                    ),
                }
            )

        return Response(contributions_list, status=status.HTTP_200_OK)

    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# GET /users/:userId/contributions – Fetch all contributions made by a user.
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_groupbuy_contributions(request):
    try:
        # Fetch contributions of the currently authenticated user
        user = request.user  # Get the currently authenticated user
        contributions = Contribution.objects.filter(
            user=user
        )  # Filter contributions by user

        # Serialize the contributions
        serializer = ContributionSerializer(contributions, many=True)

        # Return the serialized data
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Contribution.DoesNotExist:
        return Response(
            {"message": "No contributions found."}, status=status.HTTP_404_NOT_FOUND
        )


from .models import SavingsGoal
from .serializers import SavingsGoalSerializer
from django.db import IntegrityError
from decimal import Decimal, InvalidOperation

MINIMUM_TARGET_AMOUNT = Decimal("10.00")  # Set minimum threshold for the target amount


# POST /savings/create - Create a savings goal
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_savings_goal(request):
    try:
        # Extract data from request body
        data = request.data
        user = request.user  # Get the currently authenticated user

        # Ensure all required fields are provided
        required_fields = ["name", "target_amount", "deadline", "contribution_type"]

        # Check for missing required fields
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return Response(
                {"error": f'Missing fields: {", ".join(missing_fields)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        name = data["name"]
        target_amount_str = data["target_amount"]
        deadline = data["deadline"]
        contribution_type = data["contribution_type"]
        auto_debit_enabled = data.get(
            "auto_debit_enabled", "False"
        )  # Default to 'False' if not provided

        # Validate target_amount
        try:
            target_amount = Decimal(target_amount_str)
            if target_amount < MINIMUM_TARGET_AMOUNT:
                return Response(
                    {
                        "error": f"Target amount must be at least {MINIMUM_TARGET_AMOUNT}"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (ValueError, InvalidOperation):
            return Response(
                {"error": "Invalid target amount format"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate contribution_type (it should be one of the valid options)
        valid_contribution_types = ["daily", "weekly", "monthly"]
        if contribution_type not in valid_contribution_types:
            return Response(
                {
                    "error": f'Invalid contribution type. Valid options are {", ".join(valid_contribution_types)}.'
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate deadline (should be in YYYY-MM-DD format)
        try:
            # Attempt to parse the deadline string to a date object
            deadline_date = datetime.strptime(deadline, "%Y-%m-%d").date()
        except ValueError:
            return Response(
                {"error": "Invalid deadline format. Please use YYYY-MM-DD."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate auto_debit_enabled (should be either 'True' or 'False' string)
        if auto_debit_enabled not in ["True", "False"]:
            return Response(
                {"error": 'auto_debit_enabled must be either "True" or "False".'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Convert auto_debit_enabled to boolean (True or False)
        auto_debit_enabled = auto_debit_enabled == "True"

        # If Auto-Debit is enabled, schedule recurring transactions
        if auto_debit_enabled:
            # Example: schedule_auto_debit(user, goal)
            # (You need to implement scheduling logic or integrate with a scheduler)
            pass

        # Create the savings goal
        goal = SavingsGoal.objects.create(
            user=user,
            name=name,
            target_amount=target_amount,
            saved_amount=0,  # Initial saved amount is 0
            deadline=deadline_date,
            contribution_type=contribution_type,
            auto_debit_enabled=auto_debit_enabled,
        )

        # Serialize the savings goal data and return the response
        serializer = SavingsGoalSerializer(goal)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    except KeyError as e:
        return Response(
            {"error": f"Missing field: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST
        )
    except IntegrityError as e:
        # Log the error for debugging purposes
        logging.error(f"IntegrityError: {str(e)}")
        return Response(
            {"error": "Database integrity error"}, status=status.HTTP_400_BAD_REQUEST
        )
    except ValueError as e:
        return Response(
            {"error": f"Invalid data: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        # General exception for unexpected errors
        logging.error(f"Unexpected error: {str(e)}")
        return Response(
            {"error": "An unexpected error occurred"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# GET /savings/{id} - Fetch a savings goal
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def fetch_savings_goal(request, id):
    try:
        # Fetch the savings goal by ID
        goal = SavingsGoal.objects.get(id=id)

        # Serialize the savings goal data and return the response
        serializer = SavingsGoalSerializer(goal)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except SavingsGoal.DoesNotExist:
        return Response(
            {"error": "Savings goal not found."}, status=status.HTTP_404_NOT_FOUND
        )


# POST /savings/{id}/deposit - Add funds to a goal
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_funds(request, id):
    try:

        user = request.user

        # Retrieve 'amount' and 'source' from the request data
        amount = request.data.get("amount")
        source = request.data.get("source")

        # Check if 'source' is provided and capitalize it, otherwise return an error message
        if source:
            source = source.capitalize()
        else:
            return Response(
                {"message": "Source is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Validate that 'amount' and 'source' are provided
        if not amount:
            return Response(
                {"message": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Validate 'source' value
        accepted_sources = ["Savings", "Wallet"]
        if source not in accepted_sources:
            return Response(
                {
                    "message": "Invalid source. Accepted values are: Savings, Investment, Wallet."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Ensure deposit amount is valid
        try:
            deposit_amount = Decimal(amount)
        except (ValueError, InvalidOperation):
            return Response(
                {"error": "Invalid deposit amount format."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if the deposit amount is positive
        if deposit_amount <= 0:
            return Response(
                {"error": "Deposit amount cannot be less than or equals to zero(0)."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Fetch the savings goal by ID
        try:
            goal = SavingsGoal.objects.get(id=id)
        except SavingsGoal.DoesNotExist:
            return Response(
                {"error": "Target savings not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # Validate if the deposit exceeds the remaining balance required to reach the goal
        remaining_balance = goal.target_amount - goal.saved_amount
        if deposit_amount > remaining_balance:
            return Response(
                {
                    "error": f"Deposit amount exceeds the remaining balance to reach your goal. Remaining balance is {remaining_balance}."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Debit the source
        if source == "Savings":
            if user.savings >= deposit_amount:
                user.savings -= deposit_amount
                user.save()
            else:
                return Response(
                    {"error": "Insufficient savings balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif source == "Wallet":
            if user.wallet >= deposit_amount:
                user.wallet -= deposit_amount
                user.save()
            else:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Update the saved amount for the goal
        goal.saved_amount += deposit_amount
        goal.save()

        # Generate a unique transaction ID (You can also use UUID or another method if needed)
        transaction_id = str(uuid.uuid4())[:16]

        # Log the transaction (Create a new Transaction record)
        transaction = Transaction.objects.create(
            user=request.user,
            transaction_type="credit",  # 'credit' for deposits
            status="confirmed",
            amount=deposit_amount,
            description=f"Transfer [{source} > Target Savings({goal.name})] (Successful)",
            transaction_id=transaction_id,
        )

        # Optional: Send a notification to the user (you can add actual email or push notification logic here)
        subject = f"Deposit to Your Target Savings ({goal.name}) Successful!"
        message = f"Hi {user.first_name},<br><br>We’re excited to let you know that your deposit of ₦{amount} has been successfully added to your Target Savings ({goal.name}) account!<br><br>Thank you for choosing MyFund to help you achieve your savings goals. Keep up the great work—your financial future is looking brighter every day! 🌟<br><br>Keep growing your funds.🥂<br><br>"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_generic_email(subject, message, from_email, recipient_list)

        # Return the success message
        return Response(
            {
                "message": f"{deposit_amount} successfully added to your target savings goal. Remaining balance: {goal.target_amount - goal.saved_amount}",
                "transaction_id": transaction_id,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        # Catch any unexpected exceptions and log them
        logging.error(f"Unexpected error: {str(e)}")
        return Response(
            {"error": f"An unexpected error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def withdraw_savings(request, id):
    try:
        data = request.data
        user = request.user

        # Ensure required fields are provided
        amount = int(data.get("amount"))
        target_bank_account_id = data.get("target_bank_account_id")

        if not amount:
            return Response(
                {"error": "'amount' is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not target_bank_account_id:
            return Response(
                {"error": "'target_bank_account_id' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Convert amount to integer and check if it's valid
        try:
            amount = int(amount)
        except ValueError:
            return Response(
                {"error": "Invalid withdrawal amount. Must be a number."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if amount <= 0:
            return Response(
                {"error": "Withdrawal amount must be positive."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Fetch the savings goal by ID
        try:
            goal = SavingsGoal.objects.get(id=id)
        except SavingsGoal.DoesNotExist:
            return Response(
                {"error": "Savings goal not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # Validate that the target_bank_account_id belongs to the user
        try:
            target_bank_account = BankAccount.objects.get(
                id=target_bank_account_id, user=user
            )
        except BankAccount.DoesNotExist:
            return Response(
                {"error": "Target bank account not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if the goal is complete enough to allow a withdrawal (e.g., 80% of the goal)
        completion_percentage = (goal.saved_amount / goal.target_amount) * 100
        if completion_percentage < 80:
            return Response(
                {
                    "error": f"You must reach at least 80% of your goal to make a withdrawal."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if the withdrawal is within the allowed amount
        if amount > goal.saved_amount:
            return Response(
                {"error": "Insufficient funds."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Optionally, apply a penalty if withdrawn before the goal deadline
        if goal.deadline:
            # Ensure goal.deadline is a datetime object for comparison
            goal_deadline_datetime = datetime.combine(
                goal.deadline, datetime.min.time()
            )

            # Compare the goal deadline with the current time
            if datetime.now() < goal_deadline_datetime:
                penalty = calculate_penalty(
                    amount
                )  # You would implement this function to apply a penalty
                amount -= Decimal(penalty)
                goal.saved_amount -= amount
                goal.save()

        # Generate a unique transaction ID (You can also use UUID or another method if needed)
        reference_code = generate_reference()
        transaction_id = f"withdrawal-{reference_code}"

        # Log the transaction (this could be a simple database record)
        transaction = Transaction.objects.create(
            user=goal.user,
            transaction_type="debit",  # 'credit' for deposits
            status="pending",
            amount=amount,
            description=f"Withdrawal [Target Savings({goal.name}) > Bank] (Pending)",
            transaction_id=transaction_id,
        )

        # Placeholder: Transfer funds to the user's local bank account
        if amount < 500000:
            print("Paystack in progresss...")
            # Perform the withdrawal to the local bank using Paystack API
            paystack_response = make_withdrawal_through_paystack(
                user, target_bank_account, amount, transaction_id
            )

            if paystack_response.get("status"):  # This checks if it's truthy
                # Deduct the total amount (including service charge) from the source account
                print("Paystack API Response:", paystack_response)

                # Update the transaction database table.
                transaction = Transaction(
                    user=user,
                    transaction_type="debit",
                    status="confirmed",
                    amount=amount,
                    service_charge=penalty,
                    total_amount=amount,
                    description=f"Withdrawal [Target Savings({goal.name}) > Bank] (Successful)",
                    transaction_id=transaction_id,
                )
                transaction.save()

                bank_name = target_bank_account.bank_name
                # Send a confirmation email to the user
                subject = f"Withdrawal from Target Savings({goal.name}) Successful!"
                message = f"Hi {user.first_name},<br><br>Your withdrawal of ₦{amount} from your Target Savings({goal.name}) account has been sent to your {bank_name} account successfully.<br><br>Thank you for using MyFund.<br><br>Keep growing your funds.🥂<br><br>"
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_generic_email(subject, message, from_email, recipient_list)

                return Response(
                    {
                        "success": True,
                        "message": paystack_response.get("message"),
                        "transaction_id": transaction_id,
                        "updated_balance": goal.saved_amount,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "error": "Withdrawal to local bank failed. Please try again later."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            print("Admin processing the withdrawal...")
            # Perform the withdrawal to the local bank through the Admin
            response = make_withdrawal_through_admin(user, amount, transaction_id)

            if response is not None:
                return Response(
                    {
                        "success": True,
                        "message": response.get("message"),
                        "transaction_id": transaction_id,
                        "updated_balance": goal.saved_amount,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "error": "Withdrawal to local bank failed. Please try again later."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

    except SavingsGoal.DoesNotExist:
        return Response(
            {"error": "Savings goal not found."}, status=status.HTTP_404_NOT_FOUND
        )
    except ValueError:
        return Response(
            {"error": "Invalid withdrawal amount."}, status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Function to calculate penalties if the user withdraws early
def calculate_penalty(withdrawal_amount):
    # Placeholder for penalty calculation logic
    penalty_percentage = 0.10  # Example: 5% penalty
    return withdrawal_amount * penalty_percentage


# GET /savings/user/{user_id} - Fetch all savings goals of a user
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def fetch_user_savings_goals(request, user_id):
    try:
        # Fetch all savings goals for the given user
        goals = SavingsGoal.objects.filter(user_id=user_id)

        # Serialize the savings goals data
        serializer = SavingsGoalSerializer(goals, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except SavingsGoal.DoesNotExist:
        return Response(
            {"message": "No savings goals found for this user."},
            status=status.HTTP_404_NOT_FOUND,
        )


# DELETE /savings/{id} - Delete a goal (if no active funds)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_savings_goal(request, id):
    try:
        # Fetch the savings goal by ID
        goal = SavingsGoal.objects.get(id=id)

        if goal.saved_amount > 0:
            return Response(
                {"error": "Cannot delete goal with active funds."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Delete the goal
        goal.delete()
        return Response(
            {"message": "Savings goal deleted successfully."}, status=status.HTTP_200_OK
        )

    except SavingsGoal.DoesNotExist:
        return Response(
            {"error": "Savings goal not found."}, status=status.HTTP_404_NOT_FOUND
        )


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.conf import settings
from django.db.models import Sum
from decimal import Decimal
import uuid
from .models import TargetSavings, Transaction, TargetSavingsCompletion
from .serializers import TargetSavingsSerializer
from .utils import send_generic_email, send_push_notification


class TargetSavingsListCreate(ListCreateAPIView):
    serializer_class = TargetSavingsSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        data = serializer.validated_data

        frequency = data["frequency"].upper()
        if frequency not in dict(TargetSavings.FREQUENCY_CHOICES):
            raise ValidationError({"detail": "Invalid frequency"})

        amount = Decimal(str(serializer.validated_data["monthly_payment"]))
        funding_source = data["funding_source"]

        if funding_source == "SAVINGS" and user.savings < amount:
            raise ValidationError({"detail": "Insufficient savings balance"})
        if funding_source == "INVESTMENT" and user.investment < amount:
            raise ValidationError({"detail": "Insufficient investment balance"})

        # Deduct from source and update user balance
        setattr(
            user, funding_source.lower(), getattr(user, funding_source.lower()) - amount
        )
        user.save()

        # Create the TargetSavings instance
        instance = serializer.save(
            user=user,
            current_amount=amount,
            start_date=timezone.now().date(),
        )

        # Set first next_deduction
        instance.next_deduction = instance.calculate_next_deduction_time()
        instance.save()

        # Create initial transaction
        Transaction.objects.create(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=amount,
            description=f"{instance.name}",
            service_charge=0,
            total_amount=amount,
            target_savings=instance,
            source=funding_source,
            transaction_id=f"[{instance.id}]-{uuid.uuid4().hex[:12]}_INITIAL",
        )

        # Calculate progress
        progress = (instance.current_amount / instance.target_amount) * 100
        progress_str = f"{progress:.1f}%"

        # Send creation email via generic template
        try:
            subject = f"{instance.name} Target Savings is LIVE!🚀"
            context = {
                "user": user,
                "plan_name": instance.name,
                "amount": f"₦{amount:,.2f}",
                "frequency": frequency.lower(),
                "progress": progress_str,
            }
            send_generic_email(
                subject,
                context,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                template="email/email.html",
            )
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"Failed to send target savings creation email to {user.email}: {str(e)}"
            )

        # Push notification
        send_push_notification(
            user,
            title=f"🎉 {instance.name} Plan Created! ✅",
            message=(
                f"Your {instance.name} Target Savings plan has been activated with ₦{amount:,.2f}! "
                f"You're now {progress_str} closer to your goal. Well done! 🚀"
            ),
            data={"target_savings_id": instance.id},
            notif_type="TARGET_SAVINGS",
        )

    def get_queryset(self):
        return (
            TargetSavings.objects.filter(
                user=self.request.user,
                is_cancelled=False,
            )
            .prefetch_related("transaction_set")
            .order_by("-start_date")
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def target_savings_total(request):
    total = (
        TargetSavings.objects.filter(
            user=request.user,
            is_cancelled=False,
            is_active=True,  # Only count active targets
        ).aggregate(total=Sum("current_amount"))["total"]
        or 0
    )
    return Response({"total_target_savings": float(total)})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def completed_target_savings(request):
    """Get user's completed or failed target savings"""
    from .models import TargetSavingsCompletion

    completed = (
        TargetSavingsCompletion.objects.filter(user=request.user)
        .select_related("target_savings")
        .order_by("-completed_date")
    )

    data = []
    for completion in completed:
        data.append(
            {
                "id": completion.id,
                "name": completion.target_savings.name,
                "target_amount": completion.target_savings.target_amount,
                "completed_amount": completion.completed_amount,
                "bonus_amount": completion.bonus_amount,
                "total_amount": completion.total_amount,
                "completed_date": completion.completed_date,
                "was_on_time": completion.was_on_time,
                "category": completion.target_savings.category,
                "start_date": completion.target_savings.start_date,
                "end_date": completion.target_savings.end_date,
                "status": completion.status,  # NEW FIELD in response
            }
        )

    return Response({"completed_targets": data})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def force_target_deduction(request, target_id):
    """Force deduction for a specific target savings (for testing)"""
    target = get_object_or_404(TargetSavings, id=target_id, user=request.user)

    # Set next_deduction to now to force processing
    target.next_deduction = timezone.now()
    target.save()

    # Process immediately
    success = target.process_deduction()

    return Response(
        {
            "success": success,
            "message": f"Deduction {'succeeded' if success else 'failed'} for target {target.name}",
            "new_balance": float(target.current_amount),
        }
    )


class TargetSavingsRetrieveUpdateDestroy(RetrieveUpdateDestroyAPIView):
    serializer_class = TargetSavingsSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "pk"

    def get_queryset(self):
        return TargetSavings.objects.filter(
            user=self.request.user,
            is_cancelled=False,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def cancel_target_saving(request, pk):
    target = get_object_or_404(TargetSavings, pk=pk, user=request.user)

    if target.is_cancelled:
        return Response({"detail": "Plan already cancelled"}, status=400)

    # Calculate return amount with 1% charge
    return_amount = target.current_amount * Decimal("0.99")
    charge = target.current_amount - return_amount

    # Update user balance
    user = request.user
    if target.funding_source == "SAVINGS":
        user.savings += return_amount
    elif target.funding_source == "INVESTMENT":
        user.investment += return_amount
    user.save()

    # Create transaction
    Transaction.objects.create(
        user=user,
        transaction_type="debit",
        status="confirmed",
        amount=return_amount,
        description=f"{target.name} - Cancelled",
        service_charge=charge,
        total_amount=return_amount,
        target_savings=target,
        transaction_id=f"[{target.id}]-{uuid.uuid4().hex[:12]}_CANCELLED",
    )

    # Send cancellation email via generic template
    try:
        subject = f"{target.name} Target Savings Cancelled ❌"
        context = {
            "user": user,
            "plan_name": target.name,
            "refunded_amount": f"₦{return_amount:,.2f}",
            "cancellation_charge": f"₦{charge:,.2f}",
        }
        send_generic_email(
            subject,
            context,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            template="email/email.html",
        )
    except Exception as e:
        import logging

        logger = logging.getLogger(__name__)
        logger.error(
            f"Failed to send target savings cancellation email to {user.email}: {str(e)}"
        )

    # Push notification
    send_push_notification(
        user,
        title=f"❌ {target.name} Plan Cancelled",
        message=(
            f"Hi {user.first_name}, Your {target.name} Target Savings plan has been cancelled. ₦{return_amount:,.2f} has been refunded to the sources account."
        ),
        data={"target_savings_id": target.id},
        notif_type="TARGET_SAVINGS",
    )

    # Update target savings
    target.is_active = False
    target.is_cancelled = True
    target.cancellation_charge = charge
    target.save()

    # Create CANCELLED completion record
    TargetSavingsCompletion.objects.create(
        user=user,
        target_savings=target,
        completed_amount=return_amount,
        bonus_amount=0,
        total_amount=return_amount,
        completed_date=timezone.now().date(),
        was_on_time=False,
        status="CANCELLED",
    )

    return Response(
        {
            "status": "cancelled",
            "returned_amount": float(return_amount),
            "charge": float(charge),
            "new_balance": float(
                user.savings if target.funding_source == "SAVINGS" else user.investment
            ),
        }
    )


from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from datetime import timedelta
from .models import MonthlyFinancialRecord
from .serializers import MonthlyFinancialRecordSerializer
from django.db.models import Sum


class CurrentMonthFinancialView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        today = timezone.now().date()
        first_day_of_month = today.replace(day=1)

        # Get or create record for current month
        record, created = MonthlyFinancialRecord.objects.get_or_create(
            user=request.user,
            month=first_day_of_month,
            defaults={
                "total_savings": request.user.savings,
                "total_investments": request.user.investment,
            },
        )

        # Update if not created and values might have changed
        if not created:
            record.total_savings = request.user.savings
            record.total_investments = request.user.investment
            record.save()

        serializer = MonthlyFinancialRecordSerializer(record)
        return Response(serializer.data)


class FinancialHistoryView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MonthlyFinancialRecordSerializer

    def get_queryset(self):
        # Return last 12 months of data
        one_year_ago = timezone.now().date() - timedelta(days=365)
        return MonthlyFinancialRecord.objects.filter(
            user=self.request.user, month__gte=one_year_ago
        ).order_by("-month")


class AllUsersMonthlyTotalsView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff:
            return Response({"detail": "Permission denied"}, status=403)

        current_month = timezone.now().date().replace(day=1)
        totals = MonthlyFinancialRecord.objects.filter(month=current_month).aggregate(
            total_savings=Sum("total_savings"),
            total_investments=Sum("total_investments"),
        )

        return Response(
            {
                "month": current_month.strftime("%B %Y"),
                "total_savings": totals["total_savings"] or 0,
                "total_investments": totals["total_investments"] or 0,
            }
        )


from .models import PushNotifications
from .serializers import PushNotificationsSerializer
from .utils import send_push_notification


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_my_push_notifications(request):
    user = request.user
    notifs = PushNotifications.objects.filter(user=user)
    serializer = PushNotificationsSerializer(notifs, many=True)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_admin_push_notification(request):
    user_ids = request.data.get("user_ids")
    title = request.data.get("title")
    message = request.data.get("message")

    from .models import CustomUser

    users = CustomUser.objects.filter(id__in=user_ids)

    for user in users:
        send_push_notification(user, title, message, notif_type="ADMIN")

    return Response({"message": "Notifications sent"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_expo_push_token(request):
    user = request.user
    token = request.data.get("expo_push_token")
    device_type = request.data.get("device_type", "unknown")
    app_version = request.data.get("app_version")

    if not token:
        return Response({"error": "No token provided"}, status=400)

    # Remove old duplicates
    user.expo_push_tokens = [
        entry for entry in user.expo_push_tokens if entry["token"] != token
    ]

    new_token = {
        "token": token,
        "device_type": device_type.lower(),
        "last_seen": timezone.now().isoformat(),
    }

    if app_version:
        new_token["app_version"] = app_version

    user.expo_push_tokens.append(new_token)
    user.save()
    return Response({"message": "Token saved"})


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Count, Q
from django.core.mail import send_mail
from authentication.utils import send_push_notification
from authentication.models import CustomUser


class TopReferralsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_profile_pic_url(self, user_obj):
        pic = user_obj.profile_picture
        if not pic:
            return None
        if hasattr(pic, "url"):
            return pic.url
        if isinstance(pic, str):
            return pic
        return None

    def send_rank_notification(self, user, old_rank, new_rank):
        """Sends consistent email + push notifications for rank changes."""
        if new_rank < old_rank:
            subject = f"🎉 Congrats! You're Now #{new_rank} on MyFund!"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"Great news! Your referral rank improved from #{old_rank} to #{new_rank}. "
                "Keep referring friends to climb higher!<br><br>"
                "Thank you for using MyFund.<br><br>"
                "MyFund"
            )
            push_title = f"🎉 Rank Improved! Now #{new_rank}"
            push_message = (
                f"Hi {user.first_name}, you moved up to #{new_rank} (from #{old_rank}). "
                "Keep referring to earn more referral rewards!"
            )
        else:
            subject = f"📉 Your MyFund Rank Changed to #{new_rank}"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"Your referral rank changed from #{old_rank} to #{new_rank}. "
                "Share your referral link to move back up and earn more referral bonus!<br><br>"
                "Thank you for using MyFund.<br><br>"
            )
            push_title = f"📉 Referral Rank Changed to #{new_rank}"
            push_message = (
                f"Hi {user.first_name}, your rank is now #{new_rank} (was #{old_rank}). "
                "Refer more friends to climb higher and earn more referral bonus!"
            )

        # Send email
        send_generic_email(
            subject,
            message,
            "MyFund <info@myfundmobile.com>",
            [user.email],
        )

        # Send push notification
        send_push_notification(
            user=user,
            title=push_title,
            message=push_message,
            data={"old_rank": old_rank, "new_rank": new_rank, "type": "ReferralRank"},
            notif_type="SYSTEM",
        )

    def get(self, request):
        user = request.user
        now = timezone.now()
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Get referral performance
        ref_stats = (
            CustomUser.objects.filter(
                referral__isnull=False,
                date_joined__gte=start_of_month,
            )
            .values("referral")
            .annotate(
                monthly_signups=Count("id"),
                monthly_confirmed=Count(
                    "id",
                    filter=Q(
                        referral_reward_confirmed_at__gte=start_of_month,
                        referral_reward_granted=True,
                    ),
                ),
            )
            .order_by("-monthly_confirmed", "-monthly_signups")
        )

        ref_ids = [stat["referral"] for stat in ref_stats]
        ref_users = CustomUser.objects.in_bulk(ref_ids)

        top_users = []
        for stat in ref_stats:
            ref_user = ref_users.get(stat["referral"])
            if not ref_user:
                continue
            top_users.append(
                {
                    "id": ref_user.id,
                    "first_name": ref_user.first_name,
                    "last_name": ref_user.last_name,
                    "email": ref_user.email,
                    "profile_picture": self.get_profile_pic_url(ref_user),
                    "monthly_signups": stat["monthly_signups"],
                    "monthly_confirmed": stat["monthly_confirmed"],
                }
            )

        # Sort and rank
        top_users.sort(key=lambda x: (-x["monthly_confirmed"], -x["monthly_signups"]))

        rank_changes = {}
        for index, user_data in enumerate(top_users):
            u = CustomUser.objects.get(id=user_data["id"])
            new_rank = index + 1
            old_rank = u.last_referral_rank or 0

            if old_rank != new_rank:
                rank_changes[u] = (old_rank, new_rank)
                u.last_referral_rank = new_rank
                u.save(update_fields=["last_referral_rank"])

        # Send notifications
        for user_obj, (old_rank, new_rank) in rank_changes.items():
            self.send_rank_notification(user_obj, old_rank, new_rank)

        # Current user stats
        my_signups = CustomUser.objects.filter(
            referral=user, date_joined__gte=start_of_month
        )
        my_confirmed = my_signups.filter(
            referral_reward_confirmed_at__gte=start_of_month,
            referral_reward_granted=True,
        )

        current_user_stats = {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "profile_picture": self.get_profile_pic_url(user),
            "monthly_signups": my_signups.count(),
            "monthly_confirmed": my_confirmed.count(),
            "rank": next(
                (i + 1 for i, u in enumerate(top_users) if u["email"] == user.email),
                None,
            ),
        }

        return Response(
            {
                "top_referrers": top_users[:50],
                "current_user": current_user_stats,
            }
        )


# views.py - Add this view
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .utils import get_user_roi_summary  # Add this import


@api_view(["GET"])
def get_roi_summary(request):
    """Get ROI summary for current month"""
    today = timezone.now().date()
    month_start = today.replace(day=1)

    summary = get_user_roi_summary(request.user, month_start, today)

    return Response(
        {
            "success": True,
            "data": {
                "period": f"{month_start.strftime('%B %Y')}",
                "savings_roi": summary["savings_roi"],
                "investment_roi": summary["investment_roi"],
                "total_roi": summary["total_roi"],
                "days_count": summary["days_count"],
            },
        }
    )


# views.py
from datetime import date
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from django.db.models import Sum
from .models import DailyROIAccrual
from .serializers import DailyROISerializer


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def earnings_summary(request):
    """Return user's total earnings, current quarter ROI, and next payout date"""
    user = request.user
    today = timezone.now().date()

    # Determine current quarter
    if today.month in [1, 2, 3]:
        quarter_start = date(today.year, 1, 1)
        quarter_end = date(today.year, 3, 31)
        next_payout = date(today.year, 4, 1)
    elif today.month in [4, 5, 6]:
        quarter_start = date(today.year, 4, 1)
        quarter_end = date(today.year, 6, 30)
        next_payout = date(today.year, 7, 1)
    elif today.month in [7, 8, 9]:
        quarter_start = date(today.year, 7, 1)
        quarter_end = date(today.year, 9, 30)
        next_payout = date(today.year, 10, 1)
    else:
        quarter_start = date(today.year, 10, 1)
        quarter_end = date(today.year, 12, 31)
        next_payout = date(today.year + 1, 1, 1)

    # Total all-time ROI
    total_earnings = (
        DailyROIAccrual.objects.filter(user=user)
        .aggregate(total=Sum("total_roi"))
        .get("total")
        or 0
    )

    # ROI for current quarter
    quarterly_earnings = (
        DailyROIAccrual.objects.filter(
            user=user, date__range=[quarter_start, quarter_end]
        )
        .aggregate(total=Sum("total_roi"))
        .get("total")
        or 0
    )

    # Recent 30 daily ROI records
    recent_roi = DailyROIAccrual.objects.filter(user=user).order_by("-date")[:30]
    roi_data = DailyROISerializer(recent_roi, many=True).data

    data = {
        "total_earnings": float(total_earnings),
        "quarterly_earnings": float(quarterly_earnings),
        "next_payout_date": next_payout.isoformat(),
        "daily_records": roi_data,
    }

    return Response(data)
