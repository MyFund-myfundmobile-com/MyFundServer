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
from .serializers import SignupSerializer, ConfirmOTPSerializer, UserSerializer
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

load_dotenv()


@api_view(["POST"])
@csrf_exempt
def signup(request):
    serializer = SignupSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()

        # Access the new field through the serializer's validated data
        how_did_you_hear = serializer.validated_data.get("how_did_you_hear", "OTHER")
        user.how_did_you_hear = how_did_you_hear
        user.save()
        print("Received data:", request.data)

        # Check if it's a resend request
        is_resend = request.data.get("resend", False)

        if is_resend:
            # If it's a resend request, generate a new OTP and send it
            otp = generate_otp()
            user.otp = otp
            user.save()
            send_otp_email(user, otp)

            # Update the response data for resend case
            response_data = {"message": "OTP resent successfully"}
            return Response(response_data, status=status.HTTP_200_OK)

        # Generate OTP for initial signup
        otp = generate_otp()
        user.otp = otp
        user.is_active = False  # Set the user as inactive until OTP confirmation
        user.save()

        # Send OTP to the user's email
        send_otp_email(user, otp)

        # Check if the user has a referrer (referral relationship)
        if user.referral:
            # Create pending credit transactions for both the referrer and the referred user
            transaction_id = str(uuid.uuid4())[
                :10
            ]  # Generate a UUID and truncate it to 10 characters
            credit_transaction_referred = Transaction.objects.create(
                user=user,
                referral_email=user.referral.email,  # Include the referrer's email
                transaction_type="pending",
                amount=500,
                description="Referral Reward (Pending)",
                transaction_id=transaction_id,
            )
            credit_transaction_referred.save()

            user.pending_referral_reward = F("pending_referral_reward") + 500

            user.save()

            # Update the user and referrer's pending reward
            if not user.referral.is_hired_referrer:
                transaction_id = str(uuid.uuid4())[
                    :10
                ]  # Generate a UUID and truncate it to 10 characters
                credit_transaction_referrer = Transaction.objects.create(
                    user=user.referral,
                    referral_email=user.email,  # Include the referral email
                    transaction_type="pending",
                    amount=500,
                    description="Referral Reward (Pending)",
                    transaction_id=transaction_id,
                )

                credit_transaction_referrer.save()

                user.referral.pending_referral_reward = (
                    F("pending_referral_reward") + 500
                )

                user.referral.save()

                # Send an email to the referrer (old user)
                send_referrer_pending_reward_email(user.referral, user.email)

            if user.referral.is_hired_referrer:
                hired_referrer = Referral.objects.create(
                    user=user, referrer=user.referral
                )

                hired_referrer.save()

            # Send an email to the referred user (new user)
            send_referred_pending_reward_email(user)

        # Modify the response data to include the referral email for pending transactions
        response_data = serializer.data
        if user.referral:
            response_data["referral_email"] = user.referral.email

        return Response(response_data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
    serializer = ConfirmOTPSerializer(data=request.data)
    if serializer.is_valid():
        otp = serializer.validated_data["otp"]

        try:
            user = CustomUser.objects.get(otp=otp)
            if user.is_active:
                return Response(
                    {"message": "Account already confirmed."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.is_active = True
            user.save()
            print("Account confirmed successfully.")

            # Send welcome email
            send_welcome_email(user)

            return Response(
                {"message": "Account confirmed successfully."},
                status=status.HTTP_200_OK,
            )
        except CustomUser.DoesNotExist:
            print("Invalid OTP.")
            return Response(
                {"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )

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
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user_id": user.id,
            }
        )


from rest_framework.permissions import AllowAny


class LogoutView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this endpoint

    def post(self, request):
        logout(request)
        return Response(
            {"detail": "Logged out successfully."}, status=status.HTTP_200_OK
        )


class OTPVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        received_otp = request.data.get("otp")
        user = request.user  # Assuming the user is authenticated

        if user.otp == received_otp and not user.otp_verified:
            # OTP matches and is not yet verified
            user.otp_verified = True
            user.save()
            return Response({"success": True})
        else:
            return Response({"success": False})


from .models import CustomUser, PasswordReset


@api_view(["POST"])
@csrf_exempt
def request_password_reset(request):
    if request.method == "POST":
        email = request.data.get("email")

        try:
            user = CustomUser.objects.get(email=email)
            # Generate and store OTP
            otp = generate_otp()
            password_reset = PasswordReset.objects.create(user=user, otp=otp)

            # Send OTP reset email
            send_otp_reset_email(user, otp)

            return Response({"detail": "Password reset OTP sent successfully."})
        except CustomUser.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )

    return Response({"detail": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@csrf_exempt
def reset_password(request):
    if request.method == "POST":
        email = request.data.get("email")
        otp = request.data.get("otp")
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        try:
            user = CustomUser.objects.get(email=email)
            # Check if the OTP is valid
            password_reset = PasswordReset.objects.get(user=user, otp=otp)

            if password == confirm_password:
                # Reset the password
                user.set_password(password)
                user.save()
                password_reset.delete()  # Delete the used OTP entry
                return Response({"message": "Password reset successful"})
            else:
                return Response(
                    {"error": "Passwords do not match"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (CustomUser.DoesNotExist, PasswordReset.DoesNotExist):
            return Response(
                {"error": "Invalid email or OTP"}, status=status.HTTP_400_BAD_REQUEST
            )

    return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    print("Headers:", request.headers)
    print("Data:", request.data)
    print("Token:", request.auth)  # Print the token to verify it's being extracted

    if request.user.is_authenticated:
        print("Authenticated user:", request.user)
    else:
        print("User not authenticated.")

    user = request.user
    profile_data = {
        "firstName": user.first_name,
        "lastName": user.last_name,
        "mobileNumber": user.phone_number,
        "email": user.email,
        "profile_picture": user.profile_picture if user.profile_picture else None,
        "preferred_asset": user.preferred_asset,
        "savings_goal_amount": user.savings_goal_amount,
        "time_period": user.time_period,
    }
    return Response(profile_data)


@api_view(["PATCH"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    user = request.user
    first_name = request.data.get("first_name")
    last_name = request.data.get("last_name")
    phone_number = request.data.get("phone_number")

    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name
    if phone_number:
        user.phone_number = phone_number

    user.save()
    return Response(
        {"message": "Profile updated successfully."}, status=status.HTTP_200_OK
    )


import base64


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def profile_picture_update(request):
    try:
        user = request.user

        if not bool(request.data):
            return JsonResponse(
                "No image was provided", status=status.HTTP_404_NOT_FOUND
            )

        profile_pic = request.data["profile_picture"]

        imgstr = base64.b64encode(profile_pic.read())

        upload = imagekit.upload_file(file=imgstr, file_name="profile_pic.jpg")

        if not bool(upload.response_metadata.raw):
            return JsonResponse(
                "Process failed, please try again.",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        print(upload.response_metadata.raw)

        image_url = list(upload.response_metadata.raw.values())[5]

        print("image", image_url)

        user.profile_picture = image_url

        user.save()

        updated_user_data = {
            "firstName": user.first_name,
            "lastName": user.last_name,
            "mobileNumber": user.phone_number,
            "email": user.email,
            "profile_picture": user.profile_picture,
        }

        return JsonResponse(
            {
                "message": "Profile picture updated successfully.",
                "user": updated_user_data,
            }
        )
    except Exception as e:
        return JsonResponse(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


from .serializers import SavingsGoalUpdateSerializer


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def update_savings_goal(request):
    user = request.user

    serializer = SavingsGoalUpdateSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()

        # Set is_first_time_signup flag to False after first login
        if user.is_first_time_signup:
            user.is_first_time_signup = False
            user.save()

        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
    user = request.user
    content = request.data.get("content")
    image = request.data.get("image")

    recipient_id = 1

    try:
        recipient = get_user_model().objects.get(id=recipient_id)
    except get_user_model().DoesNotExist:
        return Response(
            {"error": "Recipient not found"}, status=status.HTTP_404_NOT_FOUND
        )

    if not content and not image:
        return Response(
            {"error": "Message content or image is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    message = Message.objects.create(
        sender=user, recipient=recipient, content=content, image=image
    )

    message_data = {
        "type": "chat.message",
        "message": {
            "content": message.content,
            "image": message.image.url if message.image else None,
            "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "sender_id": message.sender.id,
        },
    }

    return Response({"success": True})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_messages(request, recipient_id):
    user = request.user
    recipient = get_user_model().objects.get(id=recipient_id)

    # Retrieve messages from the database
    messages = Message.objects.filter(
        sender__in=[user, recipient], recipient__in=[user, recipient]
    ).order_by("timestamp")

    # Serialize messages and create a list of message data
    message_data_list = []
    for message in messages:
        message_data = {
            "content": message.content,
            "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "sender_id": message.sender.id,
            "image": (
                message.image.url if message.image else None
            ),  # Include the image URL if available
        }
        message_data_list.append(message_data)

    return Response(message_data_list)


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
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=["get"])
    def get_user_banks(self, request):
        user_banks = BankAccount.objects.filter(user=request.user)
        serializer = BankAccountSerializer(user_banks, many=True)
        return Response(serializer.data)

    def resolve_account(self, account_number, bank_code):
        secret_key = os.environ.get(
            "PAYSTACK_KEY_LIVE",
            default="  ",
        )
        url = f"https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={bank_code}"
        headers = {"Authorization": f"Bearer {secret_key}"}

        response = requests.get(url, headers=headers)

        if response.status_code == status.HTTP_200_OK:
            response_data = response.json()
            account_name = response_data.get("data", {}).get("account_name", "")
            return account_name
        else:
            return None


def perform_create(self, serializer):
    account_number = self.request.data.get("accountNumber")
    bank_code = self.request.data.get("bankCode")

    if account_number and bank_code:
        account_name = self.resolve_account(account_number, bank_code)

        if account_name is not None:
            # Create a dictionary with all the data to save
            data_to_save = {
                "user": self.request.user,
                "bank_name": serializer.validated_data.get("bank_name", ""),
                "account_number": account_number,
                "bank_code": bank_code,
                "account_name": account_name,
            }

            paystack_recipient_code = create_paystack_recipient(
                account_name, account_number, bank_code
            )
            data_to_save["paystack_recipient_code"] = paystack_recipient_code

            serializer = BankAccountSerializer(data=data_to_save)

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"message": "Bank account added successfully."},
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(
                {"message": "Failed to resolve account details."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        data_to_save = {
            "user": self.request.user,
            "bank_name": "",
            "account_number": "",
            "bank_code": "",
            "account_name": "",
        }

        serializer = BankAccountSerializer(data=data_to_save)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Bank account added without account details resolution."},
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from django.db import IntegrityError

import logging

logger = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_bank_account(request):
    bank_name = request.data.get("bankName")
    account_number = request.data.get("accountNumber")
    account_name = request.data.get("accountName")
    bank_code = request.data.get("bankCode")  # Add this line to get the bank_code

    if bank_name and account_number and account_name and bank_code:
        try:
            paystack_recipient_code = create_paystack_recipient(
                bank_name, account_number, bank_code
            )  # Pass bank_code

            if paystack_recipient_code:
                bank_account = BankAccount(
                    user=request.user,
                    bank_name=bank_name,
                    account_number=account_number,
                    account_name=account_name,
                    bank_code=bank_code,  # Include bank_code here
                    is_default=False,
                    paystack_recipient_code=paystack_recipient_code,  # Store the recipient code
                )
                bank_account.save()

                serializer = BankAccountSerializer(bank_account)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                error_message = "Failed to create Paystack recipient."
                logger.error(error_message)
                return Response(
                    {"error": error_message}, status=status.HTTP_400_BAD_REQUEST
                )

        except IntegrityError:
            error_message = "This bank account is already associated with another user."
            logger.error(error_message)
            return Response(
                {"error": error_message}, status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            logger.error(error_message)
            return Response(
                {"error": error_message}, status=status.HTTP_400_BAD_REQUEST
            )

    else:
        error_message = (
            "accountNumber, bankName, bankCode, and accountName are required."
        )
        logger.error(error_message)
        return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)


from django.db.models import Count
from django.db import transaction


@api_view(["DELETE"])
def delete_bank_account(request, account_number):
    try:
        bank_account = BankAccount.objects.get(account_number=account_number)
    except BankAccount.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == "DELETE":
        duplicates = (
            BankAccount.objects.filter(account_number=account_number)
            .annotate(count=Count("id"))
            .filter(count__gt=1)
        )

        with transaction.atomic():
            for duplicate in duplicates:
                if duplicate.id != bank_account.id:
                    duplicate.delete()

            bank_account.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_banks(request):
    user_banks = BankAccount.objects.filter(user=request.user)
    serializer = BankAccountSerializer(user_banks, many=True)
    return Response(serializer.data)


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
    print(paystack_response)

    if paystack_response.get("status"):
        user = request.user
        paystack_message = paystack_response["message"]
        paystack_reference = paystack_response["data"]["reference"]
        paystack_status = paystack_response["data"]["status"]

        #     Create a transaction record
        Transaction.objects.create(
            user=user,
            transaction_type="pending",
            amount=int(amount),
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="QuickSave (pending)",
            transaction_id=paystack_reference,
        )

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
            paystack_display_text = paystack_response["data"]["display_text"]

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

logger = logging.getLogger(__name__)


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

    valid_frequencies = ["daily", "weekly", "monthly"]
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

    # Prepare Paystack plan creation request
    paystack_frequency = frequency  # Paystack uses same intervals
    plan_payload = {
        "name": f"{frequency.capitalize()} Autosave Plan for {user.email}",
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
    except requests.RequestException as e:
        return Response(
            {"error": f"Subscription failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 3: Save AutoSave record to the database
    AutoSave.objects.create(user=user, frequency=frequency, amount=amount, active=True)

    # Send success notification email
    subject = "AutoSave Activated!"
    message = f"Well done {user.first_name},\n\nAutoSave ({frequency}) was successfully activated. You are now saving ₦{amount} {frequency}."
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

    try:
        # Find the active AutoSave for the user with the given frequency
        autosave = AutoSave.objects.get(user=user, frequency=frequency, active=True)

        # Deactivate the AutoSave by setting it to False
        autosave.active = False
        autosave.save()

        # Delete the AutoSave object from the database
        autosave.delete()

        user.autosave_enabled = False
        user.save()

        # Send a confirmation email
        subject = "AutoSave Deactivated!"
        message = f"Hi {user.first_name},\n\nYour AutoSave ({frequency}) has been deactivated. \n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

        # Return a success response indicating that AutoSave has been deactivated
        return Response({"message": "AutoSave deactivated"}, status=status.HTTP_200_OK)

    except AutoSave.DoesNotExist:
        return Response(
            {"error": "AutoSave not found"}, status=status.HTTP_404_NOT_FOUND
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_autosave_status(request):
    user = request.user
    autosave_enabled = user.autosave_enabled

    # You can retrieve the user's active auto-save settings here
    try:
        active_autosave = AutoSave.objects.get(user=user, active=True)
        autoSaveSettings = {
            "active": True,
            "amount": active_autosave.amount,
            "frequency": active_autosave.frequency,
        }
    except AutoSave.DoesNotExist:
        autoSaveSettings = {
            "active": False,
            "amount": 0,
            "frequency": "",
        }

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

    if paystack_response.get("status"):
        user = request.user
        paystack_message = paystack_response["message"]
        paystack_reference = paystack_response["data"]["reference"]
        paystack_display_text = paystack_response["data"]["display_text"]
        paystack_status = paystack_response["data"]["status"]

        # Create a transaction record
        Transaction.objects.create(
            user=user,
            transaction_type="pending",
            amount=int(amount),
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="QuickInvest (pending)",
            transaction_id=paystack_reference,
        )

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
    if not amount or not card_id or not frequency:
        return Response(
            {"error": "Missing required fields: card_id, amount, and frequency."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = int(amount)
        if amount < 100:
            return Response(
                {"error": "Amount cannot be less than N100."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    except ValueError:
        return Response(
            {"error": "Invalid amount. Amount should be a number."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    valid_frequencies = ["daily", "weekly", "monthly"]
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

    # Prepare Paystack plan creation request
    paystack_frequency = frequency  # Paystack uses the same intervals
    plan_payload = {
        "name": f"{frequency.capitalize()} AutoInvest Plan for {user.email}",
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
        plan_response.raise_for_status()  # Raises an HTTPError for bad responses
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
    subscription_payload = {
        "customer": user.email,  # Assuming you saved the customer's ID
        "plan": plan_code,
    }

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
    except requests.RequestException as e:
        return Response(
            {"error": f"Subscription failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 3: Save AutoInvest record to the database
    AutoInvest.objects.create(
        user=user,
        frequency=frequency,
        amount=amount,
        active=True,
        # need to add subscription_id to the database attributes
        # subscription_id=subscription_data.get("data").get("id")  # Store subscription ID
    )

    # Send success notification email
    subject = "AutoInvest Activated!"
    message = f"Well done {user.first_name},\n\nAutoInvest ({frequency}) was successfully activated. You are now investing ₦{amount} {frequency}."
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    try:
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    except Exception as e:
        return Response(
            {"error": f"Failed to send email: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Mark user as having auto-invest enabled
    user.autoinvest_enabled = True
    user.save()

    return Response({"message": "AutoInvest activated"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def deactivate_autoinvest(request):
    user = request.user
    frequency = request.data.get("frequency")

    try:
        # Find the active AutoInvest for the user with the given frequency
        autoinvest = AutoInvest.objects.get(user=user, frequency=frequency, active=True)

        # Deactivate the AutoInvest by setting it to False
        autoinvest.active = False
        autoinvest.save()

        # Delete the AutoInvest object from the database
        autoinvest.delete()

        user.autoinvest_enabled = False
        user.save()

        # Send a confirmation email
        subject = "AutoInvest Deactivated!"
        message = f"Hi {user.first_name},\n\nYour AutoInvest ({frequency}) has been deactivated. \n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

        # Return a success response indicating that AutoInvest has been deactivated
        return Response(
            {"message": "AutoInvest deactivated"}, status=status.HTTP_200_OK
        )

    except AutoInvest.DoesNotExist:
        return Response(
            {"error": "AutoInvest not found"}, status=status.HTTP_404_NOT_FOUND
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_autoinvest_status(request):
    user = request.user
    autoinvest_enabled = user.autoinvest_enabled

    # You can retrieve the user's active auto-invest settings here
    try:
        active_autoinvest = AutoInvest.objects.get(user=user, active=True)
        autoInvestSettings = {
            "active": True,
            "amount": active_autoinvest.amount,
            "frequency": active_autoinvest.frequency,
        }
    except AutoInvest.DoesNotExist:
        autoInvestSettings = {
            "active": False,
            "amount": 0,
            "frequency": "",
        }

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
            amount=amount,
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="Withdrawal (Savings > Investment)",
            transaction_id=debit_transaction_id,
        )
        debit_transaction.save()

        # Create a credit transaction record
        credit_transaction = Transaction(
            user=user,
            transaction_type="credit",
            amount=int(amount),
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="QuickInvest",
            transaction_id=credit_transaction_id,
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
def investment_to_savings(request):
    user = request.user
    amount = Decimal(request.data.get("amount", 0))

    # Validate that the user has enough investment balance
    if user.investment < amount:
        return Response(
            {"error": "Insufficient investment balance."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Generate a unique transaction ID
    transaction_id = str(uuid.uuid4())[:16]

    try:
        # Create a transaction record with the details
        transaction = Transaction(
            user=user,
            transaction_type="credit",  # Change to 'credit' for funds going back to savings
            amount=amount,
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="Withdrawal (Investment > Savings)",  # Update description
            transaction_id=transaction_id,
        )
        transaction.save()

        # Perform the investment to savings transfer
        user.investment -= amount
        user.savings += amount  # Adjust savings
        user.save()

        return Response(
            {
                "message": "Investment to savings transfer successful.",
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
        # Create a transaction record with the details
        transaction = Transaction(
            user=user,
            transaction_type="credit",  # Debit for withdrawal
            amount=amount,
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="Withdrawal (Wallet > Savings)",
            transaction_id=transaction_id,
        )
        transaction.save()

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
        # Create a transaction record with the details
        transaction = Transaction(
            user=user,
            transaction_type="debit",  # Debit for withdrawal
            amount=amount,
            date=timezone.now().date(),
            time=timezone.now().time(),
            description="Withdrawal (Wallet > Investment)",
            transaction_id=transaction_id,
        )
        transaction.save()

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
    target_bank_account_id = request.data.get("target_bank_account_id", "")
    amount = Decimal(request.data.get("amount", 0))

    # Validate that the user has enough balance in the source account
    if source_account == "savings" and user.savings < amount:
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
        # Create a transaction record with the details
        transaction = Transaction(
            user=user,
            transaction_type="debit",
            amount=withdrawal_amount,
            service_charge=service_charge,
            total_amount=amount,
            date=timezone.now().date(),
            time=timezone.now().time(),
            description=f"Withdrawal ({source_account.capitalize()} > Bank)",
            transaction_id=transaction_id,
        )
        transaction.save()

        total_amount_decimal = Decimal(amount)
        print(
            f"Before deduction - {source_account.capitalize()} balance: {user.savings if source_account == 'savings' else user.investment if source_account == 'investment' else user.wallet}"
        )

        if source_account == "savings":
            if user.savings >= total_amount_decimal:
                user.savings -= total_amount_decimal
                user.save()
            else:
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

        # Perform the withdrawal to the local bank using Paystack API
        paystack_response = make_withdrawal_to_local_bank(
            user, target_bank_account, withdrawal_amount
        )
        print("Paystack API Response:", paystack_response)

        if paystack_response.get("status"):  # This checks if it's truthy
            # Deduct the total amount (including service charge) from the source account
            # Convert total_amount to Decimal
            print("Paystack API Response:", paystack_response)

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
                {"error": "Withdrawal to local bank failed. Please try again later."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    except IntegrityError:
        # Handle the case where a unique constraint (transaction_id) is violated
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )


import logging

logger = logging.getLogger(__name__)


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


def make_withdrawal_to_local_bank(user, target_bank_account, amount):
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
    sender_transaction_id = str(uuid.uuid4())[:16]
    target_transaction_id = str(uuid.uuid4())[:16]

    # Create transaction records for sender and target
    sender_transaction = Transaction(
        user=sender,
        transaction_type="debit",
        amount=amount,
        date=timezone.now().date(),
        time=timezone.now().time(),
        description=f"Sent to User",
        transaction_id=sender_transaction_id,
    )
    sender_transaction.save()

    target_transaction = Transaction(
        user=target_user,
        transaction_type="credit",
        amount=amount,
        date=timezone.now().date(),
        time=timezone.now().time(),
        description=f"Received from User",
        transaction_id=target_transaction_id,
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
from datetime import datetime, timedelta
from django.utils import timezone
import uuid


def schedule_rent_reward(user_id, rent_reward, transaction_id, property_name):
    # Calculate the next payment date (365 days from now)
    next_payment_date = timezone.now() + timedelta(days=1)

    # Create a transaction for the rent reward with the unique transaction_id
    transaction = Transaction(
        user_id=user_id,
        transaction_type="pending",
        amount=rent_reward,
        description="Annual Rent (Pending)",
        date=next_payment_date.date(),  # Use the calculated next_payment_date
        time=next_payment_date.time(),  # Use the calculated next_payment_date
        transaction_id=transaction_id,  # Include the unique transaction_id
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
                transaction_type="credit",
                amount=total_price,
                description=f"{property.name}",
                property_name=property.name,
                property_value=property.price,
                rent_earned_annually=rent_reward,
                date=timezone.now().date(),
                time=timezone.now().time(),
                transaction_id=generate_short_id(),
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

                    transaction_id = str(uuid.uuid4())

                    # Generate a unique ID with 15 characters
                    def generate_short_id():
                        unique_id = str(uuid.uuid4().int)
                        return unique_id[:10]

                    transaction = Transaction(
                        user=user,
                        transaction_type="credit",
                        amount=total_price,
                        description=f"{property.name}",
                        property_name=property.name,
                        property_value=property.price,
                        rent_earned_annually=rent_reward,
                        date=timezone.now().date(),
                        time=timezone.now().time(),
                        transaction_id=generate_short_id(),
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


from .serializers import CustomUserSerializer


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_top_savers(request):
    users = CustomUser.objects.filter(total_savings_and_investments_this_month__gt=0)
    top_savers = []

    for user in users:
        user.update_total_savings_and_investment_this_month()
        serializer = CustomUserSerializer(user)
        top_savers.append(serializer.data)

    top_savers.sort(key=lambda user: user["individual_percentage"], reverse=True)

    current_user = request.user
    current_user_serializer = CustomUserSerializer(current_user)
    current_user_data = current_user_serializer.data

    response_data = {"top_savers": top_savers, "current_user": current_user_data}

    return Response(response_data)


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
        print(f"User: {user}")  # Add this line for debugging
        amount = request.data.get("amount")

        # Create a BankTransferRequest record
        request = BankTransferRequest(user=user, amount=amount)
        request.save()

        # Send an email to admin
        subject = f"[CHECK] {user.first_name} Made A QuickSave Request"
        message = f"Hi Admin, \n\nA bank transfer request of ₦{amount} has just been initiated by {user.first_name} {user.last_name} ({user.email}).\n\nPlease log in to the admin panel for review: https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/\n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@myfundmobile.com",
        ]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        # Send a pending quicksave email to the user
        user_subject = "QuickSave Pending..."
        user_message = f"Hi {user.first_name},\n\nYour bank transfer request of ₦{amount} is pending approval. We will notify you once it's processed. \n\nThank you for using MyFund. \n\n\nMyFund\nSave, Buy Properties, Earn Rent\nwww.myfundmobile.com\n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        user_email = user.email

        send_mail(
            user_subject, user_message, from_email, [user_email], fail_silently=False
        )

        # Create a pending transaction for the user with date and time
        current_datetime = timezone.now()  # Get the current date and time
        referral_email = (
            user.referral.email if user.referral else None
        )  # Check if referral is set

        transaction = Transaction.objects.create(
            user=user,
            referral_email=referral_email,  # Include the referrer's email if it exists
            transaction_type="pending",
            amount=amount,
            date=current_datetime.date(),  # Set the date to the current date
            time=current_datetime.time(),  # Set the time to the current time
            description="QuickSave (Pending)",  # Adjust the description as needed
            transaction_id=str(uuid.uuid4())[:10],
        )
        transaction.save()

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

        # Create an InvestTransferRequest record
        request = InvestTransferRequest(user=user, amount=amount)
        request.save()

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

        transaction = Transaction.objects.create(
            user=user,
            referral_email=referral_email,
            transaction_type="pending",
            amount=amount,
            date=current_datetime.date(),
            time=current_datetime.time(),
            description="QuickInvest (Pending)",
            transaction_id=str(uuid.uuid4())[:10],
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
            transaction.description = description[0] + " (Confirmed)"
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


paystack_ips = ["52.31.139.75", "52.49.173.169", "52.214.14.220"]


@api_view(["POST"])
def paystack_webhook(request):
    try:
        event = request.data

        ip_address = request.headers.get("True-Client-Ip")

        ip_is_paystack = ip_address in paystack_ips

        print(str(event))

        # Do something with event
        subject = "Paystack Webhook Received!"
        message = (
            str(event)
            + " ip Address:"
            + str(ip_address)
            + "  verified:"
            + str(ip_is_paystack)
            + " headers:"
            + str(request.headers)
        )

        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = ["care@myfundmobile.com"]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        if not ip_is_paystack:
            return JsonResponse(
                {
                    "status": False,
                    "message": "Request not from paystack",
                    "ip": ip_address,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        reference = event["data"]["reference"]
        transaction = Transaction.objects.get(transaction_id=reference)
        description = transaction.description
        description = description.split(" ")
        user = transaction.user

        if (
            description[1] == "(Confirmed)"
            or description[1] == "(Failed)"
            or description[1] == "(successful)"
        ):
            return JsonResponse({"status": True}, status=status.HTTP_200_OK)

        if event["data"]["status"] != "success":
            transaction.transaction_type = "failed"
            transaction.description = description[0] + " (Failed)"
            transaction.save()

        if event["data"]["status"] == "success":
            transaction.transaction_type = "credit"
            transaction.description = description[0] + " (Confirmed)"
            transaction.save()

            amount = transaction.amount

            if description[0] == "QuickInvest":
                user.investment += int(amount)

                subject = "QuickInvest Successful!"
                message = f"Well done {user.first_name},\n\nYour QuickInvest was successful and ₦{amount} has been successfully added to your INVESTMENTS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )

            if description[0] == "QuickSave":
                user.savings += int(amount)

                subject = "QuickSave Successful!"
                message = f"Well done {user.first_name},\n\nYour QwickSave was successful and ₦{amount} has been successfully added to your SAVINGS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(
                    subject, message, from_email, recipient_list, fail_silently=False
                )

        user.confirm_referral_rewards(is_referrer=True)
        user.update_total_savings_and_investment_this_month()
        user.save()

        return JsonResponse({"status": True}, status=status.HTTP_200_OK)
    except Exception as e:
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
@permission_classes([IsAuthenticated])
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
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

BATCH_SIZE = 30  # Number of emails per batch

# Set up logging
logger = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_email(request):
    sender = request.data.get("sender")
    subject = request.data.get("subject")
    body = request.data.get("body")
    recipients = request.data.get("recipients", [])

    # Ensure all fields are present and valid
    if not all([sender, subject, body, recipients]):
        return Response(
            {"message": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST
        )

    failed_recipients = []  # To track recipients that failed

    try:
        total_recipients = len(recipients)
        logger.info(f"Total recipients: {total_recipients}")

        for i in range(0, total_recipients, BATCH_SIZE):
            batch_recipients = recipients[i : i + BATCH_SIZE]
            logger.info(
                f"Processing batch {i // BATCH_SIZE + 1} with {len(batch_recipients)} recipients"
            )

            for recipient in batch_recipients:
                email = EmailMultiAlternatives(
                    subject=subject,
                    body=body,
                    from_email=sender,
                    to=[recipient],
                )
                email.attach_alternative(body, "text/html")

                try:
                    email.send(fail_silently=False)
                    logger.info(f"Email sent to {recipient}")
                except Exception as e:
                    logger.error(f"Error sending email to {recipient}: {str(e)}")
                    failed_recipients.append(
                        recipient
                    )  # Keep track of failed recipients

        # Return success, but include information about failed recipients
        if failed_recipients:
            return Response(
                {
                    "message": "Emails sent with some failures.",
                    "failed_recipients": failed_recipients,
                },
                status=status.HTTP_207_MULTI_STATUS,  # Indicates partial success
            )
        else:
            return Response(
                {"message": "All emails sent successfully!"}, status=status.HTTP_200_OK
            )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return Response(
            {"message": f"Error: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


from .models import EmailTemplate
from .serializers import EmailTemplateSerializer
from django.views.decorators.http import require_http_methods

import logging


logger = logging.getLogger(__name__)


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
