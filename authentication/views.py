import os
from rest_framework import status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.core.mail import send_mail
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
from authentication.models import CustomUser, Referral
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

            user.pending_referral_reward = 500  # Ensure only 500 is added
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
                "Error processing referral rewards for user %s: %s", user.email, str(e)
            )
            raise

    def process_otp(user, resend=False):
        otp = generate_otp()
        user.otp = otp
        user.is_active = False if not resend else user.is_active
        user.save()
        send_otp_email(user, otp)
        logger.info("OTP %s to user %s", "resent" if resend else "sent", user.email)

    try:
        serializer = SignupSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            user = serializer.save()
            user.how_did_you_hear = serializer.validated_data.get(
                "how_did_you_hear", "OTHER"
            )
            user.save()
            logger.info("New user signup data: %s", user.email)

            is_resend = request.data.get("resend", False)
            process_otp(user, resend=is_resend)

            if is_resend:
                return Response(
                    {"message": "OTP resent successfully"}, status=status.HTTP_200_OK
                )

            if user.referral:
                handle_referral_rewards(user)

            response_data = serializer.data
            if user.referral:
                response_data["referral_email"] = user.referral.email

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
    message = f"Hi {referrer.first_name},\n\nYour referral reward of ₦500.00 is pending. When your friend ({referred_email}) becomes active by making their first savings/investment, your reward will be confirmed in your wallet.\n\nThank you for using MyFund!\n\nKeep growing your funds.🥂\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [referrer.email]

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)


def send_referred_pending_reward_email(user):
    subject = f"{user.first_name}, Your N500 Referral Reward is Pending"
    message = f"Hi {user.first_name},\n\nYou have received a welcome referral reward bonus of ₦500.00 for signing up with a referral email. It will be confirmed in your Wallet when you make your first savings of up to ₦20,000.\n\nThank you for using MyFund!\n\nKeep growing your funds.🥂\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]
    bcc_list = ["newusers@myfundmobile.com"]

    # Combine recipient list and BCC list
    all_recipients = recipient_list + bcc_list

    # Send the email without the bcc argument
    send_mail(subject, message, from_email, all_recipients, fail_silently=False)


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_exempt
def confirm_otp(request):
    def activate_user_account(user):
        user.is_active = True
        user.save()
        logger.info("Account confirmed successfully for user %s", user.email)
        send_welcome_email(user)

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
    subject = "[OTP] Did You Just Signup?"
    current_year = datetime.now().year  # Get the current year
    logo_url = (
        "https://drive.google.com/uc?export=view&id=1MorbW_xLg4k2txNQdhUnBVxad8xeni-N"
    )
    message = f"""
    <p><img src="{logo_url}" alt="MyFund Logo" style="display: block; margin: 0 auto; max-width: 100px; height: auto;"></p>

    <p>Hi {user.first_name}, </p>

    <p>We heard you'd like a shiny new MyFund account. Use the One-Time-Password (OTP) below to complete your signup. This code is valid only for 20 minutes, so chop-chop!</p>

    <h1 style="text-align: center; font-size: 24px;">{otp}</h1>

    <p>If you did not request to create a MyFund account, kindly ignore this email. Otherwise, buckle up, you're in for a treat!</p>

    <p>Cheers! 🥂</p>

    
    ...
    <p>MyFund <br>
    Save, Buy Properties, Earn Rent<br>
    www.myfundmobile.com<br>
    13, Gbajabiamila Street, Ayobo, Lagos.</p>

    <p>MyFund ©{current_year}</p>


    """

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list, html_message=message)


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

    current_year = datetime.now().year
    logo_url = (
        "https://drive.google.com/uc?export=view&id=1MorbW_xLg4k2txNQdhUnBVxad8xeni-N"
    )
    image_url = (
        "https://drive.google.com/uc?export=view&id=1K7sBCm3mgW5jQ1Cfh73LQDZuvGuNFTKw"
    )
    savings_image_url = "https://drive.google.com/uc?export=view&id=1bOVTTicGZJgUKX2aTm2SAqyX-8qfH41Q"  # Your new image link

    message = f"""
    <p><img src="{logo_url}" alt="MyFund Logo" style="display: block; margin: 0 auto; max-width: 100px; height: auto;"></p>

    <p>Hi {user.first_name},</p>

    <p>I'm personally welcoming you to the MyFund family.</p>

    <p>By signing up, you've entered the 4th step toward financial freedom, <strong>SAVINGS</strong> (click WealthMap on the app for details).</p>
    
    <p><img src="{savings_image_url}" alt="Savings Step Image" style="display: block; margin: 10px auto; max-width: 100%; height: auto;"></p>

    <p>The app tracks your progress as you save towards buying properties for a lifetime rental (passive) income.</p>

    <p>In the last few years, thousands have saved to sort their rents, started a business, saved their first million, earned their first passive income, traveled abroad, got married... it's amazing.</p>

    <p>I can't wait to hear your financial success story in the shortest time possible here at MyFund.</p>

    <p>Once again, you're welcome!</p>

    <br>

    <p><img src="{image_url}" alt="Dr Tee" style="display: block; float: left; width: 100px; height: 100px; border-radius: 50%; margin-right: 10px;">
    <strong>Tolulope Ahmed (Dr Tee)</strong><br>
    CEO/Co-founder, MyFund</p>

    <p>MyFund ©{current_year}</p>
    """

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_mail(
        subject,
        message,
        from_email,
        recipient_list,
        html_message=message,
        fail_silently=False,
    )


def send_otp_reset_email(user, otp):
    subject = "[OTP] Password Reset - {otp}"
    current_year = datetime.now().year
    logo_url = (
        "https://drive.google.com/uc?export=view&id=1MorbW_xLg4k2txNQdhUnBVxad8xeni-N"
    )
    message = f"""
    <p><img src="{logo_url}" alt="MyFund Logo" style="display: block; margin: 0 auto; max-width: 100px; height: auto;"></p>

    <p>Hi {user.first_name}, </p>

    <p>You have requested to reset your password. Use the One-Time-Password (OTP) below to complete the password reset. This code is valid only for a short time, so act quickly!</p>

    <h1 style="text-align: center; font-size: 24px;">{otp}</h1>

    <p>If you did not request a password reset, please ignore this email.</p>

    <p>Thank you,</p>
    
    <p>MyFund <br>
    Save, Buy Properties, Earn Rent<br>
    www.myfundmobile.com<br>
    13, Gbajabiamila Street, Ayobo, Lagos.</p>

    <p>MyFund ©{current_year}</p>
    """

    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list, html_message=message)


def test_email(request):
    send_mail(
        "Test Email",
        "This is a test email body.",
        "myfundmobile@gmail.com",
        ["valueplusrecords@gmail.com"],
        fail_silently=False,
    )
    return HttpResponse("Test email sent. This shows the email system is working")


class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        logger.info("User authenticated successfully: %s", user.email)

        # Generate tokens
        tokens = self.get_tokens_for_user(user)

        return Response(tokens)

    @staticmethod
    def get_tokens_for_user(user):
        """
        Generate and return JWT tokens for the given user.
        """
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


from .models import CustomUser, PasswordReset, UserPassword


@api_view(["POST"])
@csrf_exempt
def request_password_reset(request):
    """
    Handles password reset requests by sending an OTP to the user's email.
    """
    email = request.data.get("email")

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

    email = request.data.get("email")
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


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def profile_picture_update(request):
    """
    Updates the authenticated user's profile picture.
    """
    user = request.user

    if "profile_picture" not in request.FILES:
        logger.warning("No profile picture provided for user: %s", user.email)
        return Response(
            {"error": "No image was provided."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        profile_pic = request.FILES["profile_picture"]  # Ensure file is from FILES

        # Upload image to ImageKit
        upload = imagekit.upload_file(
            file=profile_pic, file_name=f"profile_{user.id}.jpg"
        )

        # Debugging: Log response from ImageKit
        logger.info("ImageKit upload response: %s", upload)

        # Check if upload was successful
        if not upload or not hasattr(upload, "url") or not upload.url:
            logger.error("Image upload failed for user: %s", user.email)
            return Response(
                {"error": "Image upload failed, please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Update user's profile picture
        user.profile_picture = upload.url
        user.save()

        logger.info("Profile picture updated successfully for user: %s", user.email)

        updated_user_data = {
            "firstName": user.first_name,
            "lastName": user.last_name,
            "mobileNumber": user.phone_number,
            "email": user.email,
            "profile_picture": user.profile_picture,
        }

        return Response(
            {
                "message": "Profile picture updated successfully.",
                "user": updated_user_data,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(
            "Error updating profile picture for user %s: %s", user.email, str(e)
        )
        return Response(
            {
                "error": f"An error occurred while updating the profile picture: {str(e)}"
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        bank_account = BankAccount.objects.create(
            user=request.user,
            bank_name=bank_name,
            account_number=account_number,
            account_name=account_name,
            bank_code=bank_code,
            is_default=False,
            paystack_recipient_code=paystack_recipient_code,
        )

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


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def quicksave(request):
    # Get the selected card details from the request
    card_id = request.data.get("card_id")
    amount = request.data.get("amount")

    if amount == None:
        return Response(
            {"error": "Amount not inputted"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Retrieve the card details from your database
    try:
        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response(
            {"error": "Selected card not found"}, status=status.HTTP_404_NOT_FOUND
        )

    # Use the card details to initiate a payment with Paystack
    paystack_url = "https://api.paystack.co/charge"

    payload = {
        "card": {
            "number": card.card_number,
            "cvv": card.cvv,
            "expiry_month": card.expiry_date.split("/")[0],
            "expiry_year": card.expiry_date.split("/")[1],
        },
        "email": request.user.email,  # Assuming you have a user authenticated with a JWT token
        "amount": int(amount) * 100,  # Amount in kobo (multiply by 100)
        "pin": card.pin,
    }

    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(paystack_url, json=payload, headers=headers)
    paystack_response = response.json()
    print("Paystack Response:", paystack_response)

    if paystack_response.get("status"):
        user = request.user
        paystack_message = paystack_response["message"]
        paystack_reference = paystack_response["data"]["reference"]
        paystack_status = paystack_response["data"]["status"]

        # Create a transaction record with separate transaction_type and status
        Transaction.objects.create(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=int(amount),
            description="QuickSave (Card)",
            transaction_id=paystack_reference,
        )

        # Update user's savings
        user.savings += int(amount)
        user.save()

        # ✅ Call the referral reward function after successful charge and balance update
        user.confirm_referral_rewards(
            is_referrer=False
        )  # Assuming the charged user is the referred user

        user.update_total_savings_and_investment_this_month()
        user.save()

        if paystack_response["data"]["status"] == "open_url":
            paystack_otp_url = paystack_response["data"]["url"]
            return Response(
                {
                    "message": paystack_message,
                    "reference": paystack_reference,
                    "open_url": paystack_otp_url,
                    "status": paystack_status,
                },
                status=status.HTTP_200_OK,
            )
        else:
            paystack_display_text = paystack_response.get("data", {}).get(
                "gateway_response", "No display text found"
            )

            return Response(
                {
                    "message": paystack_message,
                    "reference": paystack_reference,
                    "display_text": paystack_display_text,
                    "status": paystack_status,
                },
                status=status.HTTP_200_OK,
            )
    else:
        # Payment failed, return an error response
        return JsonResponse(
            {
                "message": paystack_response["data"]["message"],
                "error": "QuickSave failed",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


import time
import threading
import logging


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def autosave(request):
    user = request.user
    card_id = request.data.get("card_id")
    amount = request.data.get("amount")
    frequency = request.data.get("frequency")

    # Validate request data
    if not amount or not card_id or not frequency:
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

    # Validate card
    try:
        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response(
            {"error": "Selected card not found."}, status=status.HTTP_404_NOT_FOUND
        )
    except ValueError:
        return Response(
            {"error": "Invalid card ID format."}, status=status.HTTP_400_BAD_REQUEST
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
        paystack_trans_ref=transaction_reference,
        active=True,
    )

    # Send success notification email
    subject = "AutoSave Activated!"
    message = f"Hi {user.first_name},\n\nYour AutoSave have been activated. You are now saving ₦{amount} {frequency}.\n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    try:
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    except Exception as e:
        return Response(
            {"error": f"Failed to send email: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Mark user as having autosave enabled
    user.autosave_enabled = True
    user.save()

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
        message = f"Hi {user.first_name},\n\nYour AutoSave(s) for {frequency} have been deactivated. \n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

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
    # Get the selected card details from the request
    card_id = request.data.get("card_id")
    amount = request.data.get("amount")

    # Retrieve the card details from your database
    try:
        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response(
            {"error": "Selected card not found"}, status=status.HTTP_404_NOT_FOUND
        )

    # Use the card details to initiate a payment with Paystack
    paystack_url = "https://api.paystack.co/charge"

    payload = {
        "card": {
            "number": card.card_number,
            "cvv": card.cvv,
            "expiry_month": card.expiry_date.split("/")[0],
            "expiry_year": card.expiry_date.split("/")[1],
        },
        "email": request.user.email,
        "amount": int(amount) * 100,  # Amount in kobo (multiply by 100)
        "pin": card.pin,
    }

    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(paystack_url, json=payload, headers=headers)
    paystack_response = response.json()
    print(
        "Paystack Response:", paystack_response
    )  # Make sure this is logged in your backend console

    if paystack_response.get("status"):
        user = request.user
        paystack_message = paystack_response["message"]
        paystack_reference = paystack_response["data"]["reference"]
        paystack_display_text = paystack_response["data"].get(
            "display_text", "No display text provided"
        )
        paystack_status = paystack_response["data"]["status"]

        # Determine transaction status based on Paystack response status
        transaction_status = "confirmed" if paystack_status == "success" else "pending"

        # Create a transaction record
        Transaction.objects.create(
            user=user,
            transaction_type="credit",
            status=transaction_status,  # Update status based on response
            amount=int(amount),
            description="QuickInvest (Card)",
            transaction_id=paystack_reference,
        )

        user.investment += int(amount)
        user.save()

        user.confirm_referral_rewards(is_referrer=False)
        user.update_total_savings_and_investment_this_month()

        user.save()

        # Return a success response
        return Response(
            {
                "message": paystack_message,
                "reference": paystack_reference,
                "display_text": paystack_display_text,
                "status": paystack_status,
            },
            status=status.HTTP_200_OK,
        )
    else:
        # Payment failed, return an error response
        return Response(
            {
                "message": paystack_response["data"]["message"],
                "error": "QuickInvest failed",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


from .models import AutoInvest


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def autoinvest(request):
    user = request.user
    card_id = request.data.get("card_id")
    amount = request.data.get("amount")
    frequency = request.data.get("frequency")

    # Validate request data
    if not all([card_id, amount, frequency]):
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

    # Validate card
    try:
        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response(
            {"error": "Selected card not found."}, status=status.HTTP_404_NOT_FOUND
        )
    except ValueError:
        return Response(
            {"error": "Invalid card ID format."}, status=status.HTTP_400_BAD_REQUEST
        )

    # Check for existing AutoInvest records for the user
    if AutoInvest.objects.filter(user=user, frequency=frequency, active=True).exists():
        return Response(
            {
                "error": f"An active AutoInvest record already exists for frequency: {frequency}."
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
            status="confirmed",  # Add this line to set status as confirmed
            paystack_sub_id=subscription_id,
            paystack_sub_code=subscription_code,
            paystack_sub_token=subscription_token,
            paystack_trans_ref=transaction_reference,
            active=True,
        )

        # Create a Transaction record linked to this AutoSave
        transaction_record = Transaction.objects.create(
            user=user,
            transaction_type="credit",
            status="confirmed",  # Set status to confirmed
            amount=amount,
            description=f"AutoInvest ({frequency.capitalize()})",
            transaction_id=transaction_reference,  # Using Paystack's transaction reference
            service_charge=0.0,  # Adjust if needed
            total_amount=amount,
        )
        # Force update the status to confirmed to override any default or later changes
        Transaction.objects.filter(id=transaction_record.id).update(status="confirmed")

        user.autoinvest_enabled = True
        user.save()

    # Send success notification email
    subject = "AutoInvest Activated!"
    message = f"Hi {user.first_name},\n\nYour AutoInvest have been activated. You are now saving ₦{amount} {frequency}.\n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    from_email = "MyFund <info@myfundmobile.com>"

    try:
        send_mail(subject, message, from_email, [user.email], fail_silently=False)
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return Response(
            {"error": "Failed to send notification email."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

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
        message = f"Hi {user.first_name},\n\nYour {frequency} AutoInvest subscription have been deactivated. \n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

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
    amount = Decimal(request.data.get("amount", 0))

    # Validate that the user has enough savings
    if user.savings < amount:
        return Response(
            {"error": "Insufficient savings balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Generate unique transaction IDs for debit and credit transactions
    debit_transaction_id = str(uuid.uuid4())[:16]
    credit_transaction_id = str(uuid.uuid4())[:16]

    try:
        # Create a debit transaction record
        debit_transaction = Transaction(
            user=user,
            transaction_type="debit",
            status="confirmed",
            amount=amount,
            description="Savings > Investment",
            transaction_id=debit_transaction_id,
            service_charge=0.0,  # Default
            total_amount=amount,  # No extra charges
        )

        debit_transaction.save()

        # Create a credit transaction record
        credit_transaction = Transaction(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=amount,
            description="QuickInvest",
            transaction_id=credit_transaction_id,
            service_charge=0.0,  # Default
            total_amount=amount,  # No extra charges
        )

        credit_transaction.save()

        # Perform the savings to investment transfer
        user.savings -= amount
        user.investment += amount
        user.save()

        return Response(
            {
                "message": "Savings to investment transfer successful.",
                "debit_transaction_id": debit_transaction_id,
                "credit_transaction_id": credit_transaction_id,
            },
            status=status.HTTP_200_OK,
        )

    except IntegrityError:
        # Handle the case where a unique constraint (transaction_id) is violated
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_to_savings(request):
    user = request.user
    amount = Decimal(request.data.get("amount", 0))

    # Validate that the user has enough wallet balance
    if user.wallet < amount:
        return Response(
            {"error": "Insufficient wallet balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Generate a unique transaction ID
    transaction_id = str(uuid.uuid4())[:16]

    try:
        # Create a debit transaction for the wallet deduction
        debit_transaction = Transaction(
            user=user,
            transaction_type="debit",
            status="confirmed",
            amount=amount,
            total_amount=amount,
            description="Wallet > Savings",
            transaction_id=transaction_id + "-D",  # Append '-D' for clarity
        )
        debit_transaction.save()

        # Create a credit transaction for the savings addition
        credit_transaction = Transaction(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=amount,
            total_amount=amount,
            description="QuickSave (Transfer)",
            transaction_id=transaction_id + "-C",  # Append '-C' for clarity
        )
        credit_transaction.save()

        # Perform the wallet to savings transfer
        user.wallet -= amount
        user.savings += amount
        user.save()

        return Response(
            {
                "message": "Wallet to savings transfer successful.",
                "transaction_id": transaction_id,
            },
            status=status.HTTP_200_OK,
        )

    except IntegrityError:
        # Handle the case where a unique constraint (transaction_id) is violated
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_to_investment(request):
    user = request.user
    amount = Decimal(request.data.get("amount", 0))

    # Validate that the user has enough wallet balance
    if user.wallet < amount:
        return Response(
            {"error": "Insufficient wallet balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Generate a unique transaction ID
    transaction_id = str(uuid.uuid4())[:16]

    try:
        # Create a debit transaction for the wallet deduction
        debit_transaction = Transaction(
            user=user,
            transaction_type="debit",
            status="confirmed",
            amount=amount,
            total_amount=amount,
            description="Wallet > Investment",
            transaction_id=transaction_id + "-D",  # Append '-D' for clarity
        )
        debit_transaction.save()

        # Create a credit transaction for the investment addition
        credit_transaction = Transaction(
            user=user,
            transaction_type="credit",
            status="confirmed",
            amount=amount,
            total_amount=amount,
            description="QuickInvest (Transfer)",
            transaction_id=transaction_id + "-C",  # Append '-C' for clarity
        )
        credit_transaction.save()

        # Perform the wallet to investment transfer
        user.wallet -= amount
        user.investment += amount
        user.save()

        return Response(
            {
                "message": "Wallet to investment transfer successful.",
                "transaction_id": transaction_id,
            },
            status=status.HTTP_200_OK,
        )

    except IntegrityError:
        # Handle the case where a unique constraint (transaction_id) is violated
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def withdraw_to_local_bank(request):
    user = request.user
    source_account = request.data.get(
        "source_account", ""
    )  # 'savings', 'investment', 'wallet'

    # when source_account is not provided
    if not source_account:
        return Response(
            {"error": '"source_account" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    target_bank_account_id = request.data.get("target_bank_account_id", "")
    # when target_bank_account_id is not provided
    if not target_bank_account_id:
        return Response(
            {"error": '"target_bank_account_id" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    # when amount is not provided
    if not request.data.get("amount", 0):
        return Response(
            {"error": '"amount" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    amount = Decimal(request.data.get("amount", 0))

    # Validate that the user has enough balance in the source account
    if source_account == "savings" and user.savings < amount:
        # print(f"user.savings({user.savings}) < withdrawal amount({amount})")
        return Response(
            {"error": "Insufficient savings balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if source_account == "investment" and user.investment < amount:
        return Response(
            {"error": "Insufficient investment balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif source_account == "wallet" and user.wallet < amount:
        return Response(
            {"error": "Insufficient wallet balance."},
            status=status.HTTP_400_BAD_REQUEST,
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

    # Calculate the service charge based on the source account
    service_charge_percentage = 0.0
    if source_account == "savings":
        service_charge_percentage = 10
    elif source_account == "investment":
        service_charge_percentage = 15

    # Calculate the service charge and total withdrawal amount
    service_charge = (service_charge_percentage / 100) * float(amount)
    withdrawal_amount = float(amount) - service_charge

    # Generate a unique transaction ID
    transaction_id = str(uuid.uuid4())[:16]

    try:
        transaction = Transaction.objects.create(
            user=user,
            transaction_type="debit",
            status="pending",
            amount=withdrawal_amount,
            service_charge=service_charge,
            total_amount=amount,
            description=f"{source_account.capitalize()} > Bank",
            transaction_id=transaction_id,
        )

        total_amount_decimal = Decimal(amount)
        print(
            f"Before deduction - {source_account.capitalize()} balance: {user.savings if source_account == 'savings' else user.investment if source_account == 'investment' else user.wallet}"
        )

        if source_account == "savings":
            if user.savings >= total_amount_decimal:
                user.savings -= total_amount_decimal
                user.save()
            else:
                # print(f"user.savings({user.savings}) < total_amount_decimal({total_amount_decimal})")
                return Response(
                    {"error": "Insufficient savings balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif source_account == "investment":
            if user.investment >= total_amount_decimal:
                user.investment -= total_amount_decimal
                user.save()
            else:
                return Response(
                    {"error": "Insufficient investment balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif source_account == "wallet":
            if user.wallet >= total_amount_decimal:
                user.wallet -= total_amount_decimal
                user.save()
            else:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        print(
            f"After deduction - {source_account.capitalize()} balance: {user.savings if source_account == 'savings' else user.investment if source_account == 'investment' else user.wallet}"
        )

        updated_balance = {
            "savings": user.savings,
            "investment": user.investment,
            "wallet": user.wallet,
        }

        user.save()

        # print("Paystack processing the withdrawal...")

        # Perform the withdrawal to the local bank using Paystack API
        paystack_response = make_withdrawal_through_paystack(
            user, target_bank_account, withdrawal_amount
        )
        print("Paystack API Response:", paystack_response)

        if paystack_response.get("status"):  # This checks if it's truthy
            # Deduct the total amount (including service charge) from the source account
            # Convert total_amount to Decimal
            print("Paystack API Response:", paystack_response)

            # Update the transaction database table.
            transaction.status = "confirmed"
            transaction.description = f"{source_account.capitalize()} > Bank"
            transaction.save()

            bank_name = target_bank_account.bank_name
            # Send a confirmation email to the user
            subject = f"Withdrawal from {source_account.capitalize()} Successful!"
            message = f"Hi {user.first_name},\n\nYour withdrawal of ₦{amount} from your {source_account.capitalize()} account has been sent to your {bank_name} account successfully.\n\nThank you for using MyFund.\n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            return Response(
                {
                    "success": True,
                    "message": paystack_response.get("message"),
                    "transaction_id": transaction_id,
                    "updated_balance": updated_balance,
                },
                status=status.HTTP_200_OK,
            )
        else:
            print("Paystack withdrawal failed:", paystack_response)

            return Response(
                {
                    "error": "Withdrawal to local bank failed. Please try again later.",
                    "transaction_id": transaction_id,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    except IntegrityError:
        # Handle the case where a unique constraint (transaction_id) is violated
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as e:
        print(f"Error: {str(e)}")
        return Response(
            {"error": "An internal error occurred. Please try again later."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


import string


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def process_withdrawal_to_local_bank(request):
    user = request.user
    data = request.data

    print("Received withdrawal request:", data)  # Debugging log

    source_account = data.get("source_account", "").strip().lower()
    target_bank_account_id = data.get("target_bank_account_id")
    amount = data.get("amount")

    # Validate fields
    if not source_account:
        return Response(
            {"error": '"source_account" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not target_bank_account_id:
        return Response(
            {"error": '"target_bank_account_id" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        target_bank_account_id = int(target_bank_account_id)
        amount = Decimal(amount)
    except (ValueError, TypeError, InvalidOperation):
        return Response(
            {"error": '"amount" or "target_bank_account_id" is invalid.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        return Response(
            {"error": "Invalid withdrawal amount."}, status=status.HTTP_400_BAD_REQUEST
        )

    # Check user balance
    if source_account == "savings" and user.savings < amount:
        return Response(
            {"error": "Insufficient savings balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif source_account == "investment" and user.investment < amount:
        return Response(
            {"error": "Insufficient investment balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif source_account == "wallet" and user.wallet < amount:
        return Response(
            {"error": "Insufficient wallet balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Validate target bank account
    try:
        target_bank_account = BankAccount.objects.get(
            id=target_bank_account_id, user=user
        )
    except BankAccount.DoesNotExist:
        return Response(
            {"error": "Target bank account not found."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    transaction_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=8)
    )

    with transaction.atomic():
        # Create withdrawal record
        withdrawal = WithdrawalsRequestToAdmin.objects.create(
            user=user,
            amount=amount,
            transaction_id=transaction_id,
            source_account=source_account,
            target_bank=target_bank_account.bank_name,
            target_account_number=target_bank_account.account_number,
            is_approved=False,
        )

        # Create transaction record
        Transaction.objects.create(
            user=user,
            transaction_id=transaction_id,
            transaction_type="debit",
            status="pending",
            amount=amount,
            description=f"{source_account.capitalize()} > Bank . . .",
        )

        # Send email acknowledgment to the user
        subject = "Withdrawal Request Received"
        message = f"Hi {user.first_name},\n\nYour withdrawal request of ₦{amount} is pending approval. You will be notified once it is processed.\n\nThank you for using MyFund.\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    return Response(
        {
            "message": "Withdrawal request created and pending approval.",
            "transaction_id": transaction_id,
        },
        status=status.HTTP_201_CREATED,
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


def make_withdrawal_through_paystack(user, target_bank_account, amount):
    # Make a withdrawal request to Paystack API
    url = "https://api.paystack.co/transfer"
    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }
    data = {
        "source": "balance",
        "amount": int(amount * 100),  # Amount in kobo (100 kobo = 1 Naira)
        "recipient": target_bank_account.paystack_recipient_code,  # Paystack recipient code of the target bank account
    }

    # Log the Paystack API request
    print("Paystack API Request:")
    print("URL:", url)
    print("Headers:", headers)
    print("Data:", data)

    response = requests.post(url, headers=headers, json=data)

    # Log the Paystack API response for debugging
    print("Paystack API Response Status Code:", response.status_code)
    print(
        "Paystack API Response Text:", response.text
    )  # This will print the response body

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
        message = f"Hi Admin, \n\nA withdrawal request of ₦{amount} has just been initiated by {user.first_name} {user.last_name} ({user.email}).\n\nPlease log in to the admin panel for review: https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@myfundmobile.com",
            "sammy@myfundmobile.com",
        ]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        # Send a pending quicksave email to the user
        user_subject = "Withdrawal Pending..."
        user_message = f"Hi {user.first_name},\n\nYour withdrawal of ₦{amount} is pending approval. We will notify you once it's processed. \n\nThank you for using MyFund. \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        user_email = [user.email]

        send_mail(
            user_subject, user_message, from_email, user_email, fail_silently=False
        )

        return {"message": "Withdrawal request created and pending admin approval"}

    except Exception as e:
        # print error
        print(f"\n(Error) make_withdrawal_through_admin():  {e}\n")


from decimal import Decimal


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_wallet_transfer(request):
    sender = request.user
    data = request.data
    target_email = data.get(
        "recipient_email"
    )  # Update to match the key in the request data
    amount = Decimal(data.get("amount"))

    # Verify that the sender has enough balance in their wallet
    if sender.wallet < amount:
        return Response(
            {"error": "Insufficient balance in the wallet."},
            status=status.HTTP_BAD_REQUEST,
        )

    # Find the target user by email
    try:
        target_user = CustomUser.objects.get(email=target_email)
    except CustomUser.DoesNotExist:
        return Response(
            {"error": "Target user not found."}, status=status.HTTP_404_NOT_FOUND
        )  # Use the correct status code

    # Perform the wallet-to-wallet transfer
    sender.wallet -= amount
    target_user.wallet += amount
    sender.save()
    target_user.save()

    # Generate unique transaction IDs
    sender_transaction_id = str(uuid.uuid4().hex)[:10]
    target_transaction_id = str(uuid.uuid4().hex)[:10]

    # Create transaction records for sender and target
    sender_transaction = Transaction(
        user=sender,
        transaction_type="debit",
        status="confirmed",
        amount=amount,
        description=f"Sent to {target_user.first_name}",
        transaction_id=sender_transaction_id,
        total_amount=amount,
    )
    sender_transaction.save()

    target_transaction = Transaction(
        user=target_user,
        transaction_type="credit",
        status="confirmed",
        amount=amount,
        description=f"Received from {sender.first_name}",
        transaction_id=target_transaction_id,
        total_amount=amount,
    )
    target_transaction.save()

    # Send confirmation emails to both users
    subject_sender = f"You Sent ₦{amount} to {target_user.first_name}"
    message_sender = f"Hi {sender.first_name}, \n\nYou have successfully transferred ₦{amount} to {target_user.first_name} ({target_user.email}). \n\nThank you for using MyFund!\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    from_email_sender = (
        "MyFund <info@myfundmobile.com>"  # Replace with a valid sender email
    )
    recipient_list_sender = [sender.email]

    subject_target = f"You Received ₦{amount} from {sender.first_name}"
    message_target = f"Hi {target_user.first_name}, \n\nYou have received ₦{amount} from {sender.first_name} ({sender.email}). \n\nThank you for using MyFund!\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    from_email_target = (
        "MyFund <info@myfundmobile.com>"  # Replace with a valid target email
    )
    recipient_list_target = [target_user.email]

    send_mail(
        subject_sender,
        message_sender,
        from_email_sender,
        recipient_list_sender,
        fail_silently=False,
    )
    send_mail(
        subject_target,
        message_target,
        from_email_target,
        recipient_list_target,
        fail_silently=False,
    )

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
    # message = f"Hi {user.first_name},\n\nYou've received an annual rental income of ₦{rent_reward} from your {property_name} property. Keep growing your portfolio to enjoy more returns on your investment.🥂 \n\nThank you for using MyFund!\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    # from_email = "MyFund <info@myfundmobile.com>"
    # recipient_list = [user.email]

    # send_mail(subject, message, from_email, recipient_list, fail_silently=False)


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
            message = f"Hi {user.first_name},\n\nYou've successfully purchased {num_units} {num_units_text} of {property.name} property valued at {property.price}.\n\nYou will earn an annual rental income of ₦{rent_reward} on this property.\n\nCongratulations on being a landlord!\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            from_email = "MyFund <info@myfundmobile.com>"
            recipient_list = [user.email]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

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
                    message = f"Hi {user.first_name},\n\nYou've successfully purchased {num_units} {num_units_text} of {property.name} property valued at {property.price}.\n\nYou will earn an annual rental income of ₦{rent_reward} on this property.\n\nCongratulations on being a landlord!\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = [user.email]

                    send_mail(
                        subject,
                        message,
                        from_email,
                        recipient_list,
                        fail_silently=False,
                    )

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


from .serializers import CustomUserSerializer
from django.db.models.functions import Coalesce  # Add this import
from django.db.models import OuterRef, Subquery, DecimalField  # Add this line
from django.db.models import Sum
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from django.db.models import Q  # Make sure to import Q
from .models import TopSaverHistory


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_top_savers(request):
    now = timezone.now()
    current_month = now.month
    current_year = now.year

    # Calculate and store top savers for the month
    with transaction.atomic():
        # Delete old top savers for the current month and year
        TopSaverHistory.objects.filter(month=current_month, year=current_year).delete()

    # 1. Update ALL users' current month totals
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

    # 2. Get ordered list of users
    users = CustomUser.objects.filter(
        total_savings_and_investments_this_month__gt=0
    ).order_by("-total_savings_and_investments_this_month")

    # 3. Get top amount once for consistent percentage calculations
    top_amount = (
        users.first().total_savings_and_investments_this_month
        if users.exists() and users.first().total_savings_and_investments_this_month > 0
        else 1
    )

    # 4. Serialize data with calculated percentages and save them to TopSaverHistory
    top_savers = []
    rank = 1  # rank starts at 1 for top saver
    for user in users:
        percentage = (
            (user.total_savings_and_investments_this_month / top_amount * 100)
            if top_amount > 0
            else 0
        )
        # Save to the TopSaverHistory model
        TopSaverHistory.objects.create(
            month=current_month,
            year=current_year,
            user=user,
            total_savings=user.total_savings_and_investments_this_month,
            rank=rank,
        )

        top_savers.append(
            {
                "id": user.id,
                "first_name": user.first_name,
                "profile_picture": user.profile_picture,
                "email": user.email,
                "amount": float(user.total_savings_and_investments_this_month),
                "percentage": round(percentage, 1),
            }
        )
        rank += 1  # Increment rank for the next user

    # 5. Get current user data
    current_user = request.user
    current_user_percentage = (
        (current_user.total_savings_and_investments_this_month / top_amount * 100)
        if top_amount > 0
        else 0
    )

    return Response(
        {
            "top_savers": top_savers,
            "current_user": {
                "email": current_user.email,
                "percentage": round(current_user_percentage, 1),
                "amount": float(current_user.total_savings_and_investments_this_month),
            },
        }
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
        # Use the authenticated user as the object to update
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if user.kyc_status != "Updated!":
            user.kyc_status = (
                "Pending..."  # Only update to "Pending..." if not already "Updated!"
            )
            user.save()

        # Notify admin that a KYC update is pending approval
        admin_email = ["info@myfundmobile.com", "company@myfundmobile.com"]
        subject = f"KYC Update for {user.first_name} Pending Approval"
        message = f"Hello Admin, \n\n{user.first_name} {user.last_name} ({user.email}) has submitted a KYC update for approval. Please review it in the <a href='https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/'>admin panel</a>.\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"

        send_mail(subject, message, from_email, admin_email, fail_silently=False)

        return Response(serializer.data)


kyc_update_view = KYCUpdateView.as_view()


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

        # ✅ Notify Admin
        subject = f"[CHECK] {user.first_name} Made A QuickSave Request"
        message = f"Hi Admin,\n\nA bank transfer request of ₦{amount} has been initiated by {user.first_name} {user.last_name} ({user.email}).\n\nReview here: https://myfundapi-myfund-07ce351a.koyeb.app/admin/\n\nMyFund Team"
        send_mail(
            subject,
            message,
            "MyFund <info@myfundmobile.com>",
            ["company@myfundmobile.com", "info@myfundmobile.com"],
        )

        # ✅ Notify User
        user_subject = "QuickSave Pending..."
        user_message = f"Hi {user.first_name},\n\nYour bank transfer request of ₦{amount} is pending approval. We'll notify you once it's processed.\n\nThank you for using MyFund. \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        send_mail(
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
        message = f"Hi Admin, \n\nAn investment transfer request of ₦{amount} has just been initiated by {user.first_name} ({user.email}).\n\nPlease log in to the admin panel for review.\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@myfundmobile.com",
        ]  # Replace with the admin's email address

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        # Send a pending invest email to the user
        user_subject = "QuickInvest Pending..."
        user_message = f"Hi {user.first_name},\n\nYour investment transfer request of ₦{amount} is pending approval. We will notify you once it's processed. \n\nThank you for using MyFund. \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        user_email = user.email

        send_mail(
            user_subject, user_message, from_email, [user_email], fail_silently=False
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
        message = f"From: {first_name} {last_name} ({email})\n\n{message}"

        send_mail(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=[recipient_email],
            fail_silently=False,
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
                message = f"Well done {user.first_name},\n\nYour QuickInvest was successful and ₦{amount} has been successfully added to your INVESTMENTS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False,
                )

            if description[0] == "QuickSave":
                user.savings += int(amount)

                # Send a confirmation email
                subject = "QuickSave Successful!"
                message = f"Well done {user.first_name},\n\nYour QwickSave was successful and ₦{amount} has been successfully added to your SAVINGS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False,
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

        ip_address = request.headers.get("Cf-Connecting-Ip")

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
        recipient_list = ["care@myfundmobile.com", "sammy@myfundmobile.com"]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


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
        recipient_list = ["care@myfundmobile.com", "sammy@myfundmobile.com"]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        match event["event"]:
            case "charge.success":
                reference = event["data"]["reference"]
                email = event["data"]["customer"]["email"]
                transaction = Transaction.objects.filter(
                    transaction_id=reference
                ).first()
                user = CustomUser.objects.get(email=email)

                # Check if this is an AutoSave transaction
                autosave = AutoSave.objects.filter(paystack_trans_ref=reference).first()

                if autosave:
                    amount = (
                        Decimal(event["data"]["amount"]) / 100
                    )  # Use Decimal for precision
                    if not transaction:
                        transaction = Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status="confirmed",
                            amount=amount,
                            description=f"AutoSave ({autosave.frequency.capitalize()})",
                            transaction_id=reference,
                        )

                    # Atomic update for savings
                    CustomUser.objects.filter(pk=user.pk).update(
                        savings=F("savings") + amount
                    )

                    # Refresh user instance
                    user.refresh_from_db()

                    # Update totals and process referrals
                    user.update_total_savings_and_investment_this_month()
                    user.confirm_referral_rewards(is_referrer=True)

                    # Send success email
                    subject = (
                        f"AutoSave ({autosave.frequency.capitalize()}) Successful!"
                    )
                    message = f"Well done {user.first_name},\n\nYour AutoSave was successful and ₦{amount:,.2f} has been added to your SAVINGS account."
                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = [user.email]
                    send_mail(
                        subject,
                        message,
                        from_email,
                        recipient_list,
                        fail_silently=False,
                    )

                    # Update autosave record
                    autosave.last_success = timezone.now()
                    autosave.save()
                    return  # Prevent double processing

                else:
                    # Handle regular transactions
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
                    if (
                        trans_description[1] == "AutoInvest"
                        or AutoInvest.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                    ):
                        # Create a new transaction record for AutoInvest
                        transaction = Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status=(
                                "confirmed"
                                if event["data"]["status"] == "success"
                                else "confirmed"
                            ),
                            amount=int(amount),
                            description=f"{trans_description[1]}",
                            transaction_id=event["data"]["reference"],
                        )

                print(f"transaction before update: {transaction}")

                # Only update AutoSave transactions if they are not already confirmed
                if transaction.description.lower().startswith("autosave"):
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

                    if description[0] == "QuickInvest":
                        user.investment += int(amount)

                        subject = "QuickInvest Successful!"
                        message = f"Well done {user.first_name},\n\nYour QuickInvest was successful and ₦{amount} has been successfully added to your INVESTMENTS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]

                        send_mail(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                            fail_silently=False,
                        )

                    if description[0] == "QuickSave":
                        user.savings += int(amount)

                        subject = "QuickSave Successful!"
                        message = f"Well done {user.first_name},\n\nYour QuickSave was successful and ₦{amount} has been successfully added to your SAVINGS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]

                        send_mail(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                            fail_silently=False,
                        )

                    if description[0] == "AutoSave":
                        user.savings += int(amount)

                        subject = f"{description[0]} Successful!"
                        message = f"Well done {user.first_name},\n\nYour {description[0]} was successful and ₦{amount} has been successfully added to your SAVINGS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]

                        send_mail(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                            fail_silently=False,
                        )

                    if description[0] == "AutoInvest":
                        user.investment += int(amount)

                        subject = f"{description[0]} Successful!"
                        message = f"Well done {user.first_name},\n\nYour {description[0]} was successful and ₦{amount} has been successfully added to your INVESTMENT account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [user.email]

                        send_mail(
                            subject,
                            message,
                            from_email,
                            recipient_list,
                            fail_silently=False,
                        )

                    user.confirm_referral_rewards(is_referrer=True)
                    user.update_total_savings_and_investment_this_month()
                    user.save()

                return JsonResponse({"status": True}, status=status.HTTP_200_OK)

            case "invoice.create":
                sub_code = event["data"]["subscription"]["subscription_code"]
                sub_token = event["data"]["subscription"]["email_token"]
                email = event["data"]["customer"]["email"]
                trans_ref = event["data"]["transaction"]["reference"]
                user = CustomUser.objects.get(email=email)

                print(f"sub_code: {sub_code}, sub_token: {sub_token}")

                
                if AutoSave.objects.get(
                    paystack_sub_code=sub_code,
                    paystack_sub_token=sub_token,
                ):
                    # print(f"AutoSave has a record with the sub_code: {sub_code} and sub_token: {sub_token}")


                    amount = (
                        event["data"]["amount"] / 100
                    )  # convert amount to naira

                    # Check if a transaction with the same transaction_id already exists
                    existing_transaction = Transaction.objects.filter(transaction_id=trans_ref).first()

                    if not existing_transaction:
                        # Create a new transaction if not found
                        Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status="pending",
                            amount=int(amount),
                            description="AutoSave",
                            transaction_id=trans_ref,
                        )
                    
                    return JsonResponse({"status": True}, status=status.HTTP_200_OK)
                
                elif AutoInvest.objects.get(
                    paystack_sub_code=sub_code,
                    paystack_sub_token=sub_token,
                ):
                    # print(f"AutoInvest has a record with the sub_code: {sub_code} and sub_token: {sub_token}")

                    amount = (
                        event["data"]["amount"] / 100
                    )  # convert amount to naira

                    # Check if a transaction with the same transaction_id already exists
                    existing_transaction = Transaction.objects.filter(transaction_id=trans_ref).first()

                    if not existing_transaction:
                        # Create a new transaction if not found
                        Transaction.objects.create(
                            user=user,
                            transaction_type="credit",
                            status="pending",
                            amount=int(amount),
                            description="AutoInvest",
                            transaction_id=trans_ref,
                        )
                    
                    return JsonResponse({"status": True}, status=status.HTTP_200_OK)
                
                else:                
                    print(
                        f'\n"invoice.create" details does not exist in MyFund database\n'
                    )

            case "invoice.payment_failed":

                event_data = event["data"]

                # Send an email of the data of the failed payment
                subject = "Paystack Webhook(Payment Failed)"
                message = f"Invoice Data:  \n\n{event_data}"

                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = ["care@myfundmobile.com", "sammy@myfundmobile.com"]

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
                message = f"Hi Admin, \n\nA withdrawal request of ₦{amount} that was initiated by {user.first_name} {user.last_name} ({user.email}) has just FAILED!\n\nReason for failure: {reason}\n\nPlease log in to the admin panel for review: https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [
                    "company@myfundmobile.com",
                    "info@myfundmobile.com",
                    "sammy@myfundmobile.com",
                ]

                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )

                return JsonResponse({"status": True}, status=status.HTTP_200_OK)

    except Exception as e:
        # print error
        print(f"\nPaystack Webhook(Internal Server Error):  {e}\n")

        # Send an email of the error that ocurred
        subject = "Paystack Webhook Error!"
        message = f"Paystack Webhook Internal Server Error:  {e}"

        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = ["care@myfundmobile.com", "sammy@myfundmobile.com"]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ------------------------------ ADMIN SECTION FUNCTIONS

from datetime import timedelta
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from django.shortcuts import get_object_or_404


@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_all_users(request):
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

    # Filter users based on the date range and exclude unsubscribed users
    if start_date:
        users = CustomUser.objects.filter(
            date_joined__gte=start_date, is_subscribed=True
        )
    else:
        users = CustomUser.objects.filter(is_subscribed=True)

    serializer = UserSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


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
def create_group(request):
    if request.method == "POST":
        data = request.data

    # Step 1: Check if the required fields are in the request data
    required_fields = ["propertyId", "minimumContribution", "groupType", "deadline"]
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        return JsonResponse(
            {"error": f'Missing required fields: {", ".join(missing_fields)}'},
            status=400,
        )

    # Ensure the property exists
    try:
        property_obj = Property.objects.get(id=data["propertyId"])
    except Property.DoesNotExist:
        return JsonResponse({"error": "Invalid Property ID"}, status=400)

    # Step 2: Check if the available units are less than 1
    if property_obj.units_available < 1:
        return JsonResponse(
            {"error": "The group limit for this property has already been reached"},
            status=400,
        )

    # Decrease the available units of the property by 1 since a new group is being created
    property_obj.units_available -= 1
    property_obj.save()

    # Make sure the deadline is aware of timezones
    try:
        deadline = datetime.strptime(data["deadline"], "%Y-%m-%d")
        deadline = timezone.make_aware(deadline)
    except ValueError:
        return JsonResponse(
            {"error": "Invalid deadline format. Use YYYY-MM-DD."}, status=400
        )

    # Step 4: Create the new group with the selected type (Public or Private)
    group = Group.objects.create(
        property_id=data["propertyId"],
        created_by=request.user,
        goal_amount=property_obj.price,
        minimum_contribution=data["minimumContribution"],
        total_raised=0,  # Initially set total raised to 0
        status="Active",  # Group starts as active
        group_type=data["groupType"],
        deadline=deadline,
    )

    # Serialize and return the created group data
    serializer = GroupSerializer(group)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# GET /groups/:propertyId - Retrieve group buy details for a specific property
@api_view(["GET"])
def get_group_by_property(request, property_id):
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


# POST /groups/:groupId/join - Allow a user to join a group
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def join_group(request, group_id):
    try:
        group = Group.objects.get(id=group_id)
        print(f"user: {request.user}")
        print(f"group: {group}")
        group.contributors.add(request.user)  # Add current user as contributor
        return Response(
            {"message": "You successfully joined the group."}, status=status.HTTP_200_OK
        )
    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# POST /groups/:groupId/invite - Send invitations to users for private groups
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def invite_to_group(request, group_id):
    try:
        group = Group.objects.get(id=group_id)
        user = request.user

        # Step 1: Check if the group is private
        if group.group_type == "Private":
            # Step 2: Check if the requesting user is the group creator
            if group.created_by != user:
                return Response(
                    {"message": "Only the group creator can invite members."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Step 3: Get the list of user IDs to invite
            invited_user_ids = request.data.get("userIds", [])
            if not invited_user_ids:
                return Response(
                    {"message": "No user IDs provided for invitation."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Step 4: Validate the user IDs
            invited_users = get_user_model().objects.filter(id__in=invited_user_ids)
            if not invited_users:
                return Response(
                    {"message": "Some or all users are not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Step 5: Add the invited users to the group
            group.invited_users.add(*invited_users)

            # Step 6: Send an email to all invited users
            subject = "Invitation to Join Property Investment Group"
            message = f"Hello,\n\nYou have been invited by {user.email} to join a private property investment group. Please consider joining to participate in the joint property investment.\n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
            from_email = "MyFund <info@myfundmobile.com>"

            # Loop through the invited users and send emails
            recipient_list = [invited_user.email for invited_user in invited_users]
            try:
                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )
            except Exception as e:
                return Response(
                    {"error": f"Failed to send email: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response({"message": "Invitations sent."}, status=status.HTTP_200_OK)

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
def leave_group(request, group_id):
    try:
        group = Group.objects.get(id=group_id)

        # Check if the group has completed funding
        if group.status == "completed":
            return Response(
                {"message": "You cannot leave the group once funding is complete."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if the user is a contributor to the group
        if request.user not in group.contributors.all():
            return Response(
                {"message": "You are not a member of this group."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Retrieve the contributor's contribution
        contribution = Contribution.objects.filter(
            group=group, user=request.user
        ).first()
        if contribution:
            # Refund the contribution to the appropriate source (wallet, savings, or investments)
            amount_to_refund = contribution.amount
            source = contribution.source

            # Refund the contribution amount to the user based on their source
            if source == "Savings":
                request.user.savings += amount_to_refund
            elif source == "Investment":
                request.user.investment += amount_to_refund
            elif source == "Wallet":
                request.user.wallet += amount_to_refund

            # Save the user after updating their balance
            request.user.save()

            # Refund the contribution status to 'Refunded'
            contribution.payment_status = "Refunded"
            contribution.save()

        # Remove the user from the group contributors
        group.contributors.remove(request.user)

        return Response(
            {"message": "Successfully left the group and contribution refunded."},
            status=status.HTTP_200_OK,
        )

    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# GET /users/:userId/groups - Retrieve all groups a user has joined
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_groups(request):
    try:
        # Get the current user
        user = request.user

        # Get all groups where the user is a contributor
        groups = Group.objects.filter(
            contributors=user
        ).distinct()  # Assumes Group has a 'contributors' field

        # Serialize the group data
        serializer = GroupSerializer(groups, many=True)

        # Return the serialized data with a 200 OK status
        return Response(serializer.data, status=status.HTTP_200_OK)

    except get_user_model().DoesNotExist:
        # If the user is not found
        return Response(
            {"message": "User not found."}, status=status.HTTP_404_NOT_FOUND
        )


# Contribution Related APIs


# POST /groups/:groupId/contribute - Enable users to contribute funds to a group
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def contribute_to_group(request, group_id):
    try:
        # Get the group by ID
        group = Group.objects.get(id=group_id)

        # Check if the current time is after the group's deadline
        if timezone.now() > group.deadline:
            return Response(
                {"message": "Contributions are no longer allowed after the deadline."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check if the group is private and if the user is not an invited user
        if (
            group.group_type == "private"
            and request.user not in group.invited_users.all()
        ):
            return Response(
                {"message": "You are not an invited contributor to this group."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Get user object
        user = request.user

        # Retrieve 'amount' and 'source' from the request data
        amount = int(request.data.get("amount"))
        source = request.data.get("source").capitalize()

        # Validate that 'amount' and 'source' are provided
        if not amount:
            return Response(
                {"message": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not source:
            return Response(
                {"message": "Source is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Validate 'source' value
        accepted_sources = ["Savings", "Investment", "Wallet"]
        if source not in accepted_sources:
            return Response(
                {
                    "message": "Invalid source. Accepted values are: Savings, Investment, Wallet."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate that the amount is not less than the minimum contribution in the group
        if amount < group.minimum_contribution:
            return Response(
                {
                    "message": f"The minimum contribution for this group is {group.minimum_contribution}."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate that the user has enough balance in the source account
        if source == "Savings" and user.savings < amount:
            return Response(
                {"error": "Insufficient savings balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if source == "Investment" and user.investment < amount:
            return Response(
                {"error": "Insufficient investment balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        elif source == "Wallet" and user.wallet < amount:
            return Response(
                {"error": "Insufficient wallet balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Debit the source
        if source == "Savings":
            if user.savings >= amount:
                user.savings -= amount
                user.save()
            else:
                return Response(
                    {"error": "Insufficient savings balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif source == "Investment":
            if user.investment >= amount:
                user.investment -= amount
                user.save()
            else:
                return Response(
                    {"error": "Insufficient investment balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif source == "Wallet":
            if user.wallet >= amount:
                user.wallet -= amount
                user.save()
            else:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Create the contribution record
        contribution = Contribution.objects.create(
            group=group,
            user=request.user,
            amount=amount,
            payment_status="Pending",  # You can change this based on actual payment status
            source=source,  # Store the source of the contribution
        )

        # Check if the contribution would exceed the goal amount
        total_raised_after_contribution = group.total_raised + amount
        excess_amount = 0

        if total_raised_after_contribution > group.goal_amount:
            # Calculate excess
            excess_amount = total_raised_after_contribution - group.goal_amount
            # Adjust contribution amount to fit the goal
            amount -= excess_amount
            # Refund the excess amount
            if source == "Savings":
                user.savings += excess_amount
            elif source == "Investment":
                user.investment += excess_amount
            elif source == "Wallet":
                user.wallet += excess_amount
            user.save()

        # Add the valid contribution amount to the group's total_raised
        group.total_raised += amount
        group.save()

        # Calculate the ownership percentage for the contributor
        ownership_percentage = (amount / group.goal_amount) * 100

        # Update the contribution's ownership percentage
        contribution.ownership_percentage = ownership_percentage
        contribution.save()

        # Change the contribution payment_status to Confirmed
        contribution.payment_status = "Confirmed"
        contribution.save()

        # Add user to the contributors if not already a contributor
        if user not in group.contributors.all():
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
def get_contributions(request, group_id):
    try:
        group = Group.objects.get(id=group_id)

        # Get all users who contributed to the group
        contributors = group.contributors.all()

        # Prepare a dictionary to hold the total contributions for each user
        user_contributions = {}

        # Loop through each contributor
        for contributor in contributors:
            # Get all contributions made by the current contributor in the group
            contributions = Contribution.objects.filter(group=group, user=contributor)

            # Sum the total contribution amount for this user
            total_amount = sum(contribution.amount for contribution in contributions)

            # Calculate the total ownership percentage
            ownership_percentage = (
                (total_amount / group.goal_amount) * 100 if group.goal_amount > 0 else 0
            )

            # Store the data in the user_contributions dictionary
            user_contributions[contributor.email] = {
                "total_amount": total_amount,
                "ownership_percentage": ownership_percentage,
            }

        return Response(user_contributions)

    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )


# GET /users/:userId/contributions – Fetch all contributions made by a user.
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_contributions(request):
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
        message = f"Hi {user.first_name},\n\nWe’re excited to let you know that your deposit of ₦{amount} has been successfully added to your Target Savings ({goal.name}) account!\n\nThank you for choosing MyFund to help you achieve your savings goals. Keep up the great work—your financial future is looking brighter every day! 🌟\n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

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
        transaction_id = str(uuid.uuid4())[:16]

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
                user, target_bank_account, amount
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
                message = f"Hi {user.first_name},\n\nYour withdrawal of ₦{amount} from your Target Savings({goal.name}) account has been sent to your {bank_name} account successfully.\n\nThank you for using MyFund.\n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )

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
