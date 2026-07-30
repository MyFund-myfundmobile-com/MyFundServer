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
<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from rest_framework.views import APIView
from django.contrib.auth import logout
from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from authentication.models import CustomUser, AmbassadorAttendanceSubmission
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
    update_top_savers,
)
from .utils import send_generic_email
from django.db import transaction
from .utils import (
    send_sms_via_payless,
    validate_phone_number,
    send_bulk_sms,
    send_admin_push_notification,
    approve_quicksave_credit,
)
from rest_framework.exceptions import AuthenticationFailed
import threading
from .utils import create_transaction
<<<<<<< HEAD
=======
from django.conf import settings
>>>>>>> staging

load_dotenv()

logger = logging.getLogger(__name__)

from django.db import transaction
from .utils import create_paystack_customer, create_dedicated_account
<<<<<<< HEAD

MINIMUM_INVESTMENT = Decimal("100000")

=======
from django.core.cache import cache
from .models import OTPDeliveryLog
>>>>>>> staging


@api_view(["POST"])
@csrf_exempt
@permission_classes([AllowAny])
def signup(request):
    phone_number = request.data.get("phone_number")
<<<<<<< HEAD
=======

>>>>>>> staging
    if not phone_number:
        return Response(
            {"error": "Phone number is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    phone_check = validate_phone_number(phone_number)
    if not phone_check.get("valid"):
        return Response(
            {"error": phone_check.get("error")},
            status=status.HTTP_400_BAD_REQUEST,
        )

    validated_phone = phone_check.get("formatted")

<<<<<<< HEAD
    try:
        serializer = SignupSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # --- Create inactive user ---
        user = serializer.save()

        # Create Paystack customer
        customer_code = create_paystack_customer(user)

        if customer_code:
            user.paystack_customer_code = customer_code
            user.save()

            # Create DVA
            create_dedicated_account(user)

=======
    phone_key = f"signup_phone:{validated_phone}"
    ip_key = f"signup_ip_attempts:{request.META.get('REMOTE_ADDR')}"

    # -----------------------
    # PHONE RATE LIMIT (soft cooldown)
    # -----------------------
    if cache.get(phone_key):
        return Response(
            {"error": "Please wait a moment before trying again."},
            status=429,
        )

    # -----------------------
    # IP RATE LIMIT (counter-based, not hard block)
    # -----------------------
    ip_attempts = cache.get(ip_key, 0)

    if ip_attempts >= 10:
        return Response(
            {"error": "Too many signup attempts. Try again shortly."},
            status=429,
        )

    # increment attempts
    cache.set(ip_key, ip_attempts + 1, timeout=60)

    # short phone cooldown (prevents spam clicks)
    cache.set(phone_key, True, timeout=60)

    try:
        serializer = SignupSerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # -----------------------
        # CREATE USER
        # -----------------------
        user = serializer.save()

>>>>>>> staging
        user.phone_number = validated_phone
        user.how_did_you_hear = serializer.validated_data.get(
            "how_did_you_hear", "OTHER"
        )
        user.is_active = False

<<<<<<< HEAD
        # --- Generate OTP ---
        otp = generate_otp()
        user.otp = otp
        user.last_otp_sent_at = timezone.now()
=======
        # -----------------------
        # PAYSTACK CUSTOMER
        # -----------------------
        customer_code = create_paystack_customer(user)

        if not customer_code:
            logger.warning(f"Paystack customer creation failed for user {user.email}")
        else:
            user.paystack_customer_code = customer_code
            user.save(update_fields=["paystack_customer_code"])

            try:
                create_dedicated_account(user)
            except Exception as e:
                logger.exception(f"DVA creation failed for {user.email}: {e}")

        # OTP GENERATION
        otp = generate_otp()

        user.otp = otp
        user.otp_created_at = timezone.now()

        if hasattr(user, "last_otp_sent_at"):
            user.last_otp_sent_at = timezone.now()
>>>>>>> staging

        user.save(
            update_fields=[
                "phone_number",
                "how_did_you_hear",
                "is_active",
                "otp",
<<<<<<< HEAD
                "last_otp_sent_at",
                "updated_at",
            ]
        )

        # --- Send OTP AFTER response (never block, never fail signup) ---
        def send_otp_async():
            # Email (best-effort)
            try:
                send_otp_email(user, otp)
            except Exception as exc:
                logger.warning(f"OTP email failed for {user.email}: {exc}")

            # SMS should still attempt even if email fails
            try:
                if user.phone_number:
                    send_otp_sms(user, otp)
            except Exception as exc:
                logger.warning(f"OTP SMS failed for {user.phone_number}: {exc}")
=======
                "otp_created_at",
                "paystack_customer_code",
                "updated_at",
                *(["last_otp_sent_at"] if hasattr(user, "last_otp_sent_at") else []),
            ]
        )

        # CREATE DELIVERY LOG
        otp_log = OTPDeliveryLog.objects.create(
            user=user,
            otp=otp,
        )

        # -----------------------
        # SEND OTP AFTER COMMIT
        # -----------------------
        def send_otp_async():
            # -----------------------
            # EMAIL OTP (always)
            # -----------------------
            try:
                send_otp_email(user, otp)

                otp_log.email_status = "sent"
                otp_log.save(update_fields=["email_status"])

            except Exception as exc:
                logger.warning(f"OTP email failed for {user.email}: {exc}")

                otp_log.email_status = "failed"
                otp_log.save(update_fields=["email_status"])

            # -----------------------
            # SMS OTP (max 2/day)
            # -----------------------
            try:
                if user.phone_number:

                    sms_count_key = f"signup_sms_otp_count:{user.phone_number}"

                    sms_count = cache.get(sms_count_key, 0)

                    if sms_count < 2:

                        sms_success = send_otp_sms(user, otp)

                        if sms_success:
                            cache.set(
                                sms_count_key,
                                sms_count + 1,
                                timeout=60 * 60 * 24,  # 24 hours
                            )

                            otp_log.sms_sent = True
                            otp_log.save(update_fields=["sms_sent"])

                            logger.info(
                                f"SMS OTP sent to {user.phone_number}. "
                                f"Count: {sms_count + 1}/2"
                            )

                        else:
                            logger.warning(f"SMS OTP failed for {user.phone_number}")

                    else:
                        logger.info(
                            f"Daily SMS OTP limit reached for {user.phone_number}"
                        )

            except Exception as sms_exc:
                logger.warning(
                    f"SMS OTP sending error for {user.phone_number}: {sms_exc}"
                )
>>>>>>> staging

        transaction.on_commit(send_otp_async)

        response_data = serializer.data
        response_data["referral_email"] = user.referral.email if user.referral else None
        response_data["message"] = "OTP sent successfully"

        return Response(response_data, status=status.HTTP_201_CREATED)

<<<<<<< HEAD
    except Exception:
        logger.exception("Unexpected error during signup")


import threading
=======
    except Exception as e:
        logger.exception(f"Unexpected error during signup: {e}")
        return Response(
            {"error": "Signup failed. Try again later."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


import threading
from .push_deep_links import dl
>>>>>>> staging


@api_view(["POST"])
@csrf_exempt
@permission_classes([AllowAny])
def confirm_otp(request):
    serializer = ConfirmOTPSerializer(data=request.data)
<<<<<<< HEAD
=======

>>>>>>> staging
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    otp = serializer.validated_data["otp"]

    try:
<<<<<<< HEAD
        user = CustomUser.objects.get(otp=otp)
    except CustomUser.DoesNotExist:
        return Response({"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

    if user.is_active:
        return Response({"message": "Account already confirmed."}, status=400)

    # --- Activate user immediately ---
    user.is_active = True
    user.otp = None
    user.save(update_fields=["is_active", "otp"])
    logger.info("Account activated for %s", user.email)

    # --- Background function for emails/pushes/referrals ---
    def background_tasks(u):
        try:
            try:
                u.send_welcome_email()
            except Exception as e:
                logger.warning(f"Welcome email failed: {e}")

=======
        email = (request.data.get("email") or "").strip().lower()

        user = CustomUser.objects.filter(
            email__iexact=email,
            is_active=False,
        ).first()

        if not user:
            logger.warning(f"OTP attempt for non-existent/inactive user: {email}")

            return Response(
                {"message": "Invalid OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # OTP must exist
        if not user.otp:
            return Response(
                {"message": "OTP expired. Please request a new one."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # normalize OTP comparison
        if str(user.otp).strip() != str(otp).strip():
            logger.warning(f"Invalid OTP attempt: {otp} for {email}")

            return Response(
                {"message": "Invalid OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    except Exception as e:
        logger.exception(f"OTP validation error: {e}")

        return Response(
            {"message": "Invalid OTP."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # expiry check
    if user.otp_created_at and timezone.now() > user.otp_created_at + timedelta(
        minutes=20
    ):
        return Response(
            {"message": "OTP has expired."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # -----------------------
    # ACTIVATE USER + CLEAN OTP
    # -----------------------
    user.is_active = True

    # HARD CLEAR OTP STATE
    user.otp = None
    user.otp_created_at = None

    if hasattr(user, "last_otp_sent_at"):
        user.last_otp_sent_at = None

    update_fields = ["is_active", "otp", "otp_created_at"]

    if hasattr(user, "last_otp_sent_at"):
        update_fields.append("last_otp_sent_at")

    user.save(update_fields=update_fields)

    logger.info(f"Account activated for {user.email}")

    # -----------------------
    # BREVO CONTACT SYNC
    # -----------------------
    try:
        from .tasks import sync_user_to_brevo

        sync_user_to_brevo.delay(user.id)

        logger.info(f"Brevo sync queued for {user.email}")

    except Exception as e:
        logger.warning(f"Could not queue Brevo sync: {e}")

    # -----------------------
    # BACKGROUND TASKS
    # -----------------------
    def background_tasks(u):
        try:

            # -----------------------
            # WELCOME EMAIL
            # -----------------------
            try:
                u.send_welcome_email()

            except Exception as e:
                logger.warning(f"Welcome email failed: {e}")

            # -----------------------
            # WELCOME PUSH
            # -----------------------
>>>>>>> staging
            try:
                send_push_notification(
                    user=u,
                    title="Welcome to MyFund 🎉",
<<<<<<< HEAD
                    message=f"Hi {u.first_name}, Welcome to MyFund! Your account is now active. Earn daily returns up to 20% p.a. Make a quicksave to get started!",
                    data={"type": "welcome"},
                    notif_type="SYSTEM",
                )
            except Exception as e:
                logger.warning(f"Welcome push failed: {e}")
            try:
                if u.referral:
                    u.create_pending_referral_reward()
            except Exception as e:
                logger.warning(f"Referral reward failed: {e}")

            # Admin push
            admin_emails = [
                "tolulopeahmed@gmail.com",
                "ceo@myfundmobile.com",
                "janet.adegbenro@gmail.com",
            ]
            admin_users = CustomUser.objects.filter(email__in=admin_emails)
            for admin_user in admin_users:
                try:
                    if getattr(admin_user, "expo_push_tokens", None):
                        send_push_notification(
                            user=admin_user,
                            title=f"🎉 New User Signup ({u.first_name})",
                            message=f"{u.first_name} {u.last_name} ({u.email}) has just completed signup.",
                            data={
                                "user_id": u.id,
                                "email": u.email,
                                "type": "admin_signup_alert",
                            },
                            notif_type="ADMIN_ALERT",
                        )
                        logger.info(f"Admin push sent to {admin_user.email}")
                except Exception as e:
                    logger.warning(f"Admin push failed for {admin_user.email}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected background error for {u.email}: {e}")

    # Start background thread
    threading.Thread(target=background_tasks, args=(user,), daemon=True).start()

    return Response({"message": "Account confirmed successfully."}, status=200)
=======
                    message=f"Hi {u.first_name}, Welcome to MyFund! Your account is now active.",
                    data={"type": "welcome"},
                    notif_type="SYSTEM",
                )

            except Exception as e:
                logger.warning(f"Welcome push failed: {e}")

            # -----------------------
            # REFERRAL REWARD
            # -----------------------
            try:
                if u.referral:
                    u.create_pending_referral_reward()

            except Exception as e:
                logger.warning(f"Referral reward failed: {e}")

            # -----------------------
            # ADMIN PUSH NOTIFICATIONS
            # -----------------------
            try:

                # Single source of truth: is_staff is what actually gates
                # the admin-action endpoints, so it's also what gates who
                # gets notified - hardcoded email lists drift out of sync
                # (this one didn't even match the other admin push blocks)
                # and silently drop new admins from alerts.
                admin_users = CustomUser.objects.filter(
                    is_staff=True,
                    is_active=True,
                )

                from django.utils import timezone
                import calendar

                today = timezone.now().date()

                current_month_name = calendar.month_name[today.month]

                # -----------------------
                # FORMAT PHONE NUMBER
                # -----------------------
                formatted_phone = u.phone_number or "N/A"

                digits = "".join(filter(str.isdigit, formatted_phone))

                if len(digits) == 11:
                    formatted_phone = f"{digits[:4]} {digits[4:7]} {digits[7:]}"

                # -----------------------
                # SIGNUP METRICS
                # -----------------------

                # TODAY SIGNUPS
                today_signup_count = CustomUser.objects.filter(
                    date_joined__date=today,
                    is_active=True,
                ).count()

                # CURRENT MONTH SIGNUPS
                month_signup_count = CustomUser.objects.filter(
                    date_joined__year=today.year,
                    date_joined__month=today.month,
                    is_active=True,
                ).count()

                # TOTAL CONFIRMED USERS
                total_confirmed_users = CustomUser.objects.filter(
                    is_active=True,
                    is_deleted=False,
                ).count()

                # LAST MONTH CALCULATION
                if today.month == 1:
                    previous_month = 12
                    previous_year = today.year - 1
                else:
                    previous_month = today.month - 1
                    previous_year = today.year

                last_month_signup_count = CustomUser.objects.filter(
                    date_joined__year=previous_year,
                    date_joined__month=previous_month,
                    is_active=True,
                ).count()

                # GROWTH %
                growth_percentage = 0

                if last_month_signup_count > 0:
                    growth_percentage = round(
                        (
                            (month_signup_count - last_month_signup_count)
                            / last_month_signup_count
                        )
                        * 100,
                        1,
                    )

                growth_prefix = "📈 +" if growth_percentage >= 0 else "📉 "

                # -----------------------
                # SEND ADMIN PUSHES
                # -----------------------
                for admin_user in admin_users:

                    try:

                        if not getattr(
                            admin_user,
                            "expo_push_tokens",
                            None,
                        ):
                            continue

                        send_push_notification(
                            user=admin_user,
                            title=f"🎉 {u.first_name} Just Signed Up",
                            message=(
                                f"{u.first_name} {u.last_name}\n"
                                f"{u.email}\n"
                                f"{formatted_phone}\n\n"
                                f"Today: {today_signup_count} users\n"
                                f"{current_month_name}: {month_signup_count} users\n"
                                f"Total Confirmed: {total_confirmed_users:,}\n"
                                f"vs Last Month: "
                                f"{growth_prefix}{growth_percentage}%"
                            ),
                            data={
                                "user_id": u.id,
                                "email": u.email,
                                "phone_number": u.phone_number,
                                "today_signups": today_signup_count,
                                "month_signups": month_signup_count,
                                "total_confirmed_users": total_confirmed_users,
                                "growth_percentage": growth_percentage,
                                "type": "admin_signup_alert",
                                **dl.admin_new_user(u.phone_number, u.email),
                            },
                            notif_type="ADMIN",
                        )

                        logger.info(f"Admin push sent to {admin_user.email}")

                    except Exception as e:
                        logger.warning(
                            f"Admin push failed for " f"{admin_user.email}: {e}"
                        )

            except Exception as e:
                logger.warning(f"Admin notification block failed: {e}")

        except Exception as e:
            logger.exception(f"Background error for {u.email}: {e}")

    threading.Thread(
        target=background_tasks,
        args=(user,),
        daemon=True,
    ).start()

    return Response(
        {"message": "Account confirmed successfully."},
        status=status.HTTP_200_OK,
    )
>>>>>>> staging


def generate_otp():
    return "".join(random.choices("0123456789", k=6))


def send_otp_email(user, otp):
    """
<<<<<<< HEAD
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
=======
    Sends signup OTP email using Resend2 via send_generic_email.
    """

    subject = f"[OTP-{otp}] Did You Just Signup?"

    inner_html = f"""
    <p>Hi {user.first_name},</p>

    <p>
    We heard you'd like a shiny new MyFund account.
    Use the One-Time-Password (OTP) below to complete your signup.
    This code is valid for 20 minutes.
    </p>

    <h1 style="text-align:center; font-size:36px;">
        {otp}
    </h1>

    <p>
    If you did not request this, kindly ignore this email.
    </p>
>>>>>>> staging

    <p>Cheers! 🥂</p>
    """

<<<<<<< HEAD
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
=======
    try:
        send_generic_email(
            subject=subject,
            message=inner_html,
            recipient_list=[user.email],
            from_email="MyFund <noreply@mg.myfundmobile.com>",
            use_celery_threshold=0,
            template="email/email.html",
        )

        logger.info(f"✅ Signup OTP email sent to {user.email}")

    except Exception as exc:
        logger.exception(f"❌ Failed to send signup OTP email to {user.email}: {exc}")

>>>>>>> staging
        try:
            user.otp = None
            user.save(update_fields=["otp"])
        except Exception:
            user.save()
<<<<<<< HEAD
=======

>>>>>>> staging
        raise


def send_otp_sms(user, otp):
<<<<<<< HEAD
=======
    from django.core.cache import cache
>>>>>>> staging
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
<<<<<<< HEAD
=======
        sms_lock_key = f"sms_otp_lock:{phone_number}"

        if cache.get(sms_lock_key):
            logger.warning(f"SMS cooldown active for {phone_number}")
            return False

        cache.set(sms_lock_key, True, timeout=30)
>>>>>>> staging
        success = send_sms_via_payless(phone_number, message)
        if success:
            logger.info(f"📱 SMS OTP sent to {phone_number}")
        else:
            logger.warning(f"⚠️ SMS OTP failed to send for {phone_number}")
        return success
    except Exception as e:
        logger.exception(f"❌ SMS sending failed for {phone_number}: {e}")
        return False


<<<<<<< HEAD
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
=======
def send_otp_for_user(user, send_sms=False):
    otp = generate_otp()

    user.otp = otp
    user.otp_created_at = timezone.now()

    if hasattr(user, "last_otp_sent_at"):
        user.last_otp_sent_at = timezone.now()

    update_fields = ["otp", "otp_created_at", "updated_at"]

    if hasattr(user, "last_otp_sent_at"):
        update_fields.append("last_otp_sent_at")

    user.save(update_fields=update_fields)

    otp_log = OTPDeliveryLog.objects.create(
        user=user,
        otp=otp,
    )

    try:
        send_otp_email(user, otp)
        otp_log.email_status = "sent"
        otp_log.save(update_fields=["email_status"])

    except Exception as e:
        logger.warning(f"Email OTP failed: {e}")

        otp_log.email_status = "failed"
        otp_log.save(update_fields=["email_status"])

    if send_sms:
        try:
            sms_count_key = f"sms_signup_count:{user.phone_number}"

            sms_count = cache.get(sms_count_key, 0)

            if sms_count < 2:
                sms_success = send_otp_sms(user, otp)

                if sms_success:
                    cache.set(
                        sms_count_key,
                        sms_count + 1,
                        timeout=60 * 60 * 24,
                    )

                    otp_log.sms_sent = True
                    otp_log.save(update_fields=["sms_sent"])

        except Exception as e:
            logger.warning(f"SMS OTP failed: {e}")

    return True
>>>>>>> staging


@api_view(["POST"])
@csrf_exempt
@permission_classes([AllowAny])
def resend_otp(request):
<<<<<<< HEAD
    """
    Resend OTP for an existing, inactive user.
    Payload: { "email": "user@example.com" }
    """
    email = (request.data.get("email") or "").strip().lower()
    if not email:
        logger.warning("Resend OTP called without email.")
        return Response(
            {"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
=======
    email = (request.data.get("email") or "").strip().lower()

    if not email:
        return Response(
            {"detail": "Email is required."},
            status=status.HTTP_400_BAD_REQUEST,
>>>>>>> staging
        )

    try:
        user = CustomUser.objects.get(email__iexact=email)
<<<<<<< HEAD
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
=======

    except CustomUser.DoesNotExist:
        return Response(
            {"detail": "User not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    if user.is_active:
        return Response(
            {"detail": "Account already verified."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    COOLDOWN_SECONDS = 60

    last_sent = getattr(user, "last_otp_sent_at", None)

    if last_sent and timezone.now() - last_sent < timedelta(seconds=COOLDOWN_SECONDS):
        return Response(
            {"detail": "Please wait before requesting another code."},
            status=429,
        )

    try:
        resend_count_key = f"otp_resend_count:{user.email}"

        resend_count = cache.get(resend_count_key, 0)

        # First resend = email only
        # Second resend onwards = email + SMS
        send_sms = resend_count >= 1

        send_otp_for_user(
            user=user,
            send_sms=send_sms,
        )

        cache.set(
            resend_count_key,
            resend_count + 1,
            timeout=60 * 60 * 24,
        )

        return Response(
            {
                "detail": (
                    "OTP resent via email and SMS."
                    if send_sms
                    else "OTP resent successfully."
                ),
                "email": user.email,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        logger.exception(f"Error resending OTP: {e}")

        return Response(
            {"detail": "Failed to resend OTP."},
>>>>>>> staging
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
    try:
        subject = f"{user.first_name}, WELCOME TO MyFund! 🥂🎊🔥"

        image_url = "https://drive.google.com/uc?export=view&id=1K7sBCm3mgW5jQ1Cfh73LQDZuvGuNFTKw"
        savings_image_url = "https://drive.google.com/uc?export=view&id=1bOVTTicGZJgUKX2aTm2SAqyX-8qfH41Q"

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
        print(f"✅ Welcome email sent successfully to {user.email}")

    except KeyError as e:
        print(f"❌ KeyError: Missing field {e} in user object")
        # Handle missing user fields gracefully
        raise
    except AttributeError as e:
        print(f"❌ AttributeError: User object missing attribute: {e}")
        raise
    except Exception as e:
        print(
            f"❌ Error sending welcome email to {user.email if hasattr(user, 'email') else 'unknown user'}: {e}"
        )
        # Log the error but don't crash the signup process
        # You could also log to a monitoring service here
        import traceback

        print(f"Full traceback: {traceback.format_exc()}")


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

<<<<<<< HEAD
    from_email = "MyFund <info@myfundmobile.com>"
=======
    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
    recipient_list = [user.email]

    send_generic_email(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=recipient_list,
    )


def test_email(request):
    subject = f"Test Email"
    message = f"""
    This is a test email body.

    Thank you,
    
    MyFund
    """

<<<<<<< HEAD
    from_email = "MyFund <info@myfundmobile.com>"
=======
    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
    recipient_list = ["sammy@myfundmobile.com"]

    send_generic_email(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=recipient_list,
    )

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


from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        try:
            username = request.data.get("username", "").strip().lower()
            password = request.data.get("password", "")

            # Check if this is an admin login request
            is_admin_endpoint = request.path.startswith("/api/admin/login/")
            is_ambassador_endpoint = request.path.startswith("/api/ambassador/login/")

            # 🔍 Find user
            try:
                user = CustomUser.objects.get(
                    Q(email__iexact=username) | Q(phone_number__iexact=username)
                )
            except CustomUser.DoesNotExist:
                return Response(
                    {
                        "status": "email_not_found",
                        "message": "This email/phone isn't registered. Would you like to sign up instead?",
                        "suggestion": "signup",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            # ❌ Wrong password
            if not user.check_password(password):
                return Response(
                    {
                        "status": "wrong_password",
                        "message": "Incorrect password. Please try again.",
                        "suggestion": "forgot_password",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # 🔒 Admin check
            if is_admin_endpoint:
                if not (user.is_staff or user.is_superuser):
                    return Response(
                        {
                            "status": "forbidden",
                            "message": "You do not have admin access.",
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

            # 🔒 Ambassador check
            if is_ambassador_endpoint:
                if not getattr(user, "is_ambassador", False):
                    return Response(
                        {
                            "status": "forbidden",
                            "message": "You are not registered as an ambassador.",
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

            # 🚫 Banned user
            if getattr(user, "is_banned", False):
                return Response(
                    {
                        "status": "banned",
                        "message": "Your account has been disabled. Contact support.",
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # ⚠️ Inactive user
            if not user.is_active:
                if is_admin_endpoint:
                    return Response(
                        {
                            "status": "inactive",
                            "message": "Admin account inactive.",
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

                # For regular users, send OTP
<<<<<<< HEAD
                from authentication.views import send_otp_for_user

                send_otp_for_user(user)

                return Response(
                    {
                        "status": "inactive",
                        "message": "Account not verified. OTP sent.",
=======
                return Response(
                    {
                        "status": "inactive",
                        "message": "Account not verified.",
>>>>>>> staging
                        "next_step": "enter_otp",
                        "email": user.email,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # ✅ SUCCESS
            tokens = self.get_tokens_for_user(user)

            return Response(tokens)

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response(
                {"error": "Something went wrong."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @staticmethod
    def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user)

        # 👇 DETERMINE ROLE
        if user.is_superuser or user.is_staff:
            role = "admin"
        elif getattr(user, "is_ambassador", False):
            role = "ambassador"
        else:
            role = "user"

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_id": user.id,
            "role": role,  # 🔥 IMPORTANT
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


from .models import (
    CustomUser,
    GroupDeparture,
    GroupOwnership,
    PasswordReset,
    UserPassword,
)


import logging
import random
from datetime import timedelta, datetime
from django.utils import timezone
<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_exempt

from .models import CustomUser, PasswordReset
from .utils import send_sms_via_payless, send_generic_email

logger = logging.getLogger(__name__)


def _send_otp(user, otp, purpose="signup"):
    """
    Internal helper to send OTP via email and SMS.
    purpose: 'signup' | 'password_reset'
    """
    try:
        # Compose template message
        if purpose == "signup":
            subject = f"[OTP-{otp}] Complete Your MyFund Signup"
            inner_html = f"""
                <p>Hi {user.first_name},</p>
                <p>Use the One-Time-Password (OTP) below to complete your MyFund signup. Valid for 20 minutes.</p>
                <h1 style="text-align:center; font-size:36px;">{otp}</h1>
                <p>If you did not request this, ignore this email.</p>
                <p>Cheers! 🥂</p>
            """
        else:  # password_reset
            subject = f"[OTP-{otp}] Password Reset Request"
            inner_html = f"""
                <p>Hi {user.first_name},</p>
                <p>You requested to reset your password. Use the OTP below to continue. Valid for 20 minutes.</p>
                <h1 style="text-align:center; font-size:36px;">{otp}</h1>
                <p>If you did not request this, ignore this email.</p>
                <p>Thanks, <br> MyFund Team</p>
            """

        # Send email
        try:
            send_generic_email(
                subject=subject,
                message=inner_html,  # pass HTML content directly
                recipient_list=[user.email],
<<<<<<< HEAD
                from_email="MyFund <info@myfundmobile.com>",
=======
                from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                use_celery_threshold=30,
                template="email/email.html",
            )
            logger.info(f"OTP email sent to {user.email} for {purpose}")
        except Exception as e:
            logger.error(f"Error sending OTP email to {user.email}: {e}")

        # Send SMS OTP if phone is available
<<<<<<< HEAD
        phone_number = getattr(user, "phone_number", None)
        if phone_number:
            sms_message = (
                f"Hi {user.first_name}, your OTP for MyFund "
                f"{'signup' if purpose=='signup' else 'password reset'} is {otp}. "
                "Valid for 20 minutes."
            )
            try:
                if send_sms_via_payless(phone_number, sms_message):
                    logger.info(f"SMS OTP sent to {phone_number}")
                else:
                    logger.warning(f"Failed to send SMS OTP to {phone_number}")
            except Exception as sms_err:
                logger.error(f"Error sending SMS OTP to {phone_number}: {sms_err}")
=======
        # Password reset uses email only.
        # No SMS fallback here intentionally.
>>>>>>> staging

        return True

    except Exception as e:
        logger.exception(f"Error sending OTP to {user.email}: {e}")
        raise


def send_password_change_confirmation(user):
    """
    Send confirmation email when password is changed successfully.
    """
    try:
        subject = "Your MyFund Password Has Been Changed"
        inner_html = f"""
            <p>Hi {user.first_name},</p>
            <p>This is a confirmation that your MyFund account password was successfully changed.</p>
            <p>If you did not make this change, please contact our support team immediately.</p>
            <p>Thanks, <br> MyFund Security Team</p>
        """

        try:
            send_generic_email(
                subject=subject,
                message=inner_html,  # fixed from context dict to plain HTML
                recipient_list=[user.email],
<<<<<<< HEAD
                from_email="MyFund Security <info@myfundmobile.com>",
=======
                from_email="MyFund Security <info@mg.myfundmobile.com>",
>>>>>>> staging
                use_celery_threshold=30,
                template="email/email.html",
            )
            logger.info(f"Password change confirmation sent to {user.email}")
            return True
        except Exception as e:
            logger.error(
                f"Failed sending password change confirmation to {user.email}: {e}"
            )
            return False

    except Exception as e:
        logger.error(
            f"Error preparing password change confirmation for {user.email}: {e}"
        )
        return False


@api_view(["POST"])
@csrf_exempt
@permission_classes([AllowAny])
def request_password_reset(request):
    email = (request.data.get("email") or "").strip().lower()
    if not email:
        return Response({"detail": "Email is required."}, status=400)

    try:
        user = CustomUser.objects.get(email=email)
        logger.info(f"Password reset request for user: {user.email}")

        # Remove previous OTPs
        PasswordReset.objects.filter(user=user).delete()

        otp = generate_otp()
        PasswordReset.objects.create(user=user, otp=otp, created_at=timezone.now())
        user.otp = otp
        if hasattr(user, "last_otp_sent_at"):
            user.last_otp_sent_at = timezone.now()
        user.save(
            update_fields=(
                ["otp", "last_otp_sent_at", "updated_at"]
                if hasattr(user, "last_otp_sent_at")
                else ["otp", "updated_at"]
            )
        )

        # Send OTP with try-except to avoid breaking UX
        try:
            threading.Thread(
                target=_send_otp, args=(user, otp, "password_reset")
            ).start()
        except Exception as e:
            logger.error(
                f"Failed to send email/SMS for password reset to {user.email}: {e}"
            )

        return Response({"detail": "Password reset OTP sent successfully."}, status=200)

    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found."}, status=404)
    except Exception as e:
        logger.exception(f"Error in password reset request: {e}")
        return Response({"detail": "An error occurred. Try again later."}, status=500)


@api_view(["POST"])
@csrf_exempt
def reset_password(request):
    required_fields = ["email", "otp", "password", "confirm_password"]
    for field in required_fields:
        if field not in request.data:
            return Response({"error": f"'{field}' is required."}, status=400)

    email = request.data.get("email").strip().lower()
    otp = request.data.get("otp")
    password = request.data.get("password")
    confirm_password = request.data.get("confirm_password")

    if password != confirm_password:
        return Response({"error": "Passwords do not match."}, status=400)

    try:
        user = CustomUser.objects.get(email=email)
        password_reset = PasswordReset.objects.get(user=user, otp=otp)

        user.set_password(password)
        user.save()
        password_reset.delete()
        user.otp = None
        user.save(update_fields=["otp", "updated_at"])
        logger.info(f"Password reset successful for user: {user.email}")

        # Send confirmation email safely
        try:
            threading.Thread(
                target=send_password_change_confirmation,
                args=(user,),
                daemon=True,  # optional, ensures thread dies with main process
            ).start()
        except Exception as e:
            logger.warning(
                f"Could not send password change confirmation to {user.email}: {e}"
            )

        return Response({"message": "Password reset successful."}, status=200)

    except CustomUser.DoesNotExist:
        return Response({"error": "Invalid email."}, status=400)
    except PasswordReset.DoesNotExist:
        return Response({"error": "Invalid or expired OTP."}, status=400)
    except Exception as e:
        logger.exception(f"Error resetting password for {email}: {e}")
        return Response(
            {"error": "An error occurred while resetting password."}, status=500
        )


@api_view(["POST"])
@csrf_exempt
@permission_classes([AllowAny])
def resend_password_otp(request):
    email = (request.data.get("email") or "").strip().lower()
    if not email:
        return Response({"detail": "Email is required."}, status=400)

    try:
        user = CustomUser.objects.get(email=email)

        if hasattr(user, "last_otp_sent_at"):
            cooldown = timedelta(seconds=60)
            last_sent = user.last_otp_sent_at
            if last_sent and timezone.now() - last_sent < cooldown:
                return Response(
                    {"detail": "Please wait before requesting another OTP."}, status=429
                )

        otp = generate_otp()
        PasswordReset.objects.filter(user=user).delete()
        PasswordReset.objects.create(user=user, otp=otp, created_at=timezone.now())
        user.otp = otp
        if hasattr(user, "last_otp_sent_at"):
            user.last_otp_sent_at = timezone.now()
        user.save(
            update_fields=(
                ["otp", "last_otp_sent_at", "updated_at"]
                if hasattr(user, "last_otp_sent_at")
                else ["otp", "updated_at"]
            )
        )

        try:
            threading.Thread(
                target=_send_otp, args=(user, otp, "password_reset")
            ).start()
        except Exception as e:
            logger.error(
                f"Failed to resend email/SMS for password reset to {user.email}: {e}"
            )

        return Response({"detail": "OTP resent successfully."}, status=200)

    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found."}, status=404)
    except Exception as e:
        logger.exception(f"Error resending password OTP to {email}: {e}")
        return Response({"detail": "Failed to resend OTP."}, status=500)


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

        bank_accounts = BankAccount.objects.filter(user=user)

        profile_data = {
            "id": user.id,
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
            "is_first_time_signup": user.is_first_time_signup,
            "is_confirmed": user.is_confirmed,
            "is_subscribed": user.is_subscribed,
            "is_ambassador": user.is_ambassador,
            "savings": user.savings,
            "investment": user.investment,
            "properties": user.properties,
            "wallet": user.wallet,
            "total_savings_and_investments_this_month": user.total_savings_and_investments_this_month,
            "how_did_you_hear": user.how_did_you_hear,
            # DVA / Paystack fields
            "dva_account_number": user.dva_account_number,
            "dva_account_name": user.dva_account_name,
            "dva_bank_name": user.dva_bank_name,
            "dva_assigned_at": user.dva_assigned_at,
            "dva_account_id": user.dva_account_id,
            "paystack_identified": user.paystack_identified,
            "paystack_identification_status": user.paystack_identification_status,
            "paystack_identification_reason": user.paystack_identification_reason,
            # Related data
            "bank_accounts": BankAccountSerializer(bank_accounts, many=True).data,
            "bankRecords": BankAccountSerializer(bank_accounts, many=True).data,
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


<<<<<<< HEAD
import time
=======
from authentication.services.phone_change import (
    create_phone_change_request,
    verify_phone_change_otp,
    approve_phone_change,
)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def request_phone_change(request):
    new_phone = request.data.get("new_phone")

    if not new_phone:
        return Response({"error": "new_phone is required"}, status=400)

    req = create_phone_change_request(request.user, new_phone)

    return Response(
        {
            "message": "OTP sent to old and new phone numbers",
            "request_id": req.id,
            "status": req.status,
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_phone_change(request):
    request_id = request.data.get("request_id")
    old_otp = request.data.get("old_otp")
    new_otp = request.data.get("new_otp")

    if not request_id:
        return Response({"error": "request_id is required"}, status=400)

    if not old_otp or not new_otp:
        return Response({"error": "Both old_otp and new_otp are required"}, status=400)

    try:
        req = verify_phone_change_otp(
            request_id=request_id, old_otp=old_otp, new_otp=new_otp
        )
    except ValueError as e:
        return Response({"error": str(e)}, status=400)

    return Response(
        {
            "status": req.status,
            "old_verified": req.old_phone_otp_verified,
            "new_verified": req.new_phone_otp_verified,
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def approve_phone_change_view(request):
    request_id = request.data.get("request_id")

    req = approve_phone_change(request_id=request_id, admin_user=request.user)

    return Response(
        {"status": req.status, "message": "Phone number updated successfully"}
    )


import base64
import time
import uuid
>>>>>>> staging
import logging
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from imagekitio import ImageKit
<<<<<<< HEAD
from django.conf import settings
=======
from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions
>>>>>>> staging

logger = logging.getLogger(__name__)

imagekit = ImageKit(
    private_key=settings.IMAGEKIT_PRIVATE_KEY,
    public_key=settings.IMAGEKIT_PUBLIC_KEY,
    url_endpoint=settings.IMAGEKIT_URL_ENDPOINT,
)


<<<<<<< HEAD
=======
def upload_to_imagekit(file_data, user_id, filename):
    """Shared upload logic"""
    timestamp = int(time.time())
    unique_id = str(uuid.uuid4())[:8]
    ext = filename.split(".")[-1].lower()
    if ext not in ["jpg", "jpeg", "png", "gif", "webp"]:
        ext = "jpg"

    final_filename = f"profile_{user_id}_{timestamp}_{unique_id}.{ext}"

    upload_options = UploadFileRequestOptions()
    upload_options.use_unique_file_name = False
    upload_options.is_private_file = False

    result = imagekit.upload(
        file=file_data,
        file_name=final_filename,
        options=upload_options,
    )

    base_url = "https://ik.imagekit.io/myfundmobile"
    public_url = f"{base_url}/{final_filename}"

    return public_url


>>>>>>> staging
@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def profile_picture_update(request):
<<<<<<< HEAD
    user = request.user
    pic = request.FILES.get("profile_picture")
=======
    """iOS: Handles FormData upload"""
    user = request.user
    pic = request.FILES.get("profile_picture")

>>>>>>> staging
    if not pic:
        return Response(
            {"error": "No image file provided"}, status=status.HTTP_400_BAD_REQUEST
        )

<<<<<<< HEAD
    # optional: enforce size/type here…

    ext = pic.name.rsplit(".", 1)[-1]
    filename = f"profile_{user.id}.{ext}"

    try:
        # upload to ImageKit
        result = imagekit.upload_file(
            file=pic.read(),  # 🔥 THIS IS KEY
            file_name=filename,
            options={
                "folder": "/profile_pictures/",
                "tags": [f"user_{user.id}"],
                "use_unique_file_name": False,
                "overwrite_file": True,
                "overwrite_ai_tags": True,
                "overwrite_tags": True,
            },
        )

        url = result["response"]["url"]

        user.profile_picture = url
        user.save()
=======
    if pic.size > 5 * 1024 * 1024:
        return Response(
            {"error": "Image too large. Max size is 5MB"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        pic.seek(0)
        file_content = pic.read()
        encoded_string = base64.b64encode(file_content).decode("utf-8")

        public_url = upload_to_imagekit(encoded_string, user.id, pic.name)

        user.profile_picture = public_url
        user.save(update_fields=["profile_picture"])

        logger.info(f"iOS upload success for user {user.id}: {public_url}")
>>>>>>> staging

        return Response(
            {
                "message": "Profile picture updated successfully",
<<<<<<< HEAD
                "profile_picture": url,
=======
                "profile_picture": public_url,
>>>>>>> staging
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
<<<<<<< HEAD
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
                "message": "Profile picture updated successfully!",
                "profile_picture": local_url,
                "warning": "Cloud upload failed, using local storage",
=======
        logger.error(f"ImageKit upload failed for user {user.id}: {str(e)}")
        return Response(
            {"error": f"Upload failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def profile_picture_update_base64(request):
    """Android: Handles base64 upload"""
    user = request.user
    image_base64 = request.data.get("image_base64")
    filename = request.data.get("filename", "profile_image.jpg")

    if not image_base64:
        return Response(
            {"error": "No image data provided"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Remove data URL prefix if present
        if "," in image_base64:
            image_base64 = image_base64.split(",")[1]

        public_url = upload_to_imagekit(image_base64, user.id, filename)

        user.profile_picture = public_url
        user.save(update_fields=["profile_picture"])

        logger.info(f"Android base64 upload success for user {user.id}: {public_url}")

        return Response(
            {
                "message": "Profile picture updated successfully",
                "profile_picture": public_url,
>>>>>>> staging
            },
            status=status.HTTP_200_OK,
        )

<<<<<<< HEAD
=======
    except Exception as e:
        logger.error(f"ImageKit base64 upload failed for user {user.id}: {str(e)}")
        return Response(
            {"error": f"Upload failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

>>>>>>> staging

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
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import BankAccount
from .serializers import BankAccountSerializer
from .utils import (
    create_paystack_recipient,
    create_paystack_customer,
    identify_paystack_customer,
    create_dedicated_account,
)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_bank_account(request):
    user = request.user

    bank_name = request.data.get("bankName")
    account_number = request.data.get("accountNumber")
    account_name = request.data.get("accountName")
    bank_code = request.data.get("bankCode")
    bvn = (request.data.get("bvn") or "").strip()

    if not all([bank_name, account_number, account_name, bank_code]):
        return Response(
            {
                "error": "bankName, accountNumber, accountName and bankCode are required."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    print("ADD BANK REQUEST USER ID:", user.id)
    print("ADD BANK REQUEST USER EMAIL:", user.email)
    print("ADD BANK REQUEST BANK NAME:", bank_name)
    print("ADD BANK REQUEST ACCOUNT NUMBER:", account_number)
    print("ADD BANK REQUEST ACCOUNT NAME:", account_name)
    print("ADD BANK REQUEST BANK CODE:", bank_code)
    print("ADD BANK REQUEST BVN:", bvn)

    try:
        # 1. Create Paystack recipient
        paystack_recipient_code = create_paystack_recipient(
            account_name,
            account_number,
            bank_code,
        )

        print("PAYSTACK RECIPIENT CODE:", paystack_recipient_code)

        if not paystack_recipient_code:
            return Response(
                {"error": "Failed to create Paystack recipient."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2. Save or update bank account
        try:
            existing_bank = BankAccount.objects.filter(
                user=user,
                account_number=account_number,
            ).first()

            if existing_bank:
                print("EXISTING BANK ACCOUNT FOUND:", existing_bank.id)
                bank_account = existing_bank
                bank_account.bank_name = bank_name
                bank_account.account_name = account_name
                bank_account.bank_code = bank_code
                bank_account.paystack_recipient_code = paystack_recipient_code
                bank_account.save(
                    update_fields=[
                        "bank_name",
                        "account_name",
                        "bank_code",
                        "paystack_recipient_code",
                    ]
                )
            else:
                print("NO EXISTING BANK ACCOUNT FOUND. CREATING NEW ONE.")
                bank_account = BankAccount.objects.create(
                    user=user,
                    bank_name=bank_name,
                    account_number=account_number,
                    account_name=account_name,
                    bank_code=bank_code,
                    paystack_recipient_code=paystack_recipient_code,
                    is_default=False,
                )
                user.bank_accounts.add(bank_account)

        except IntegrityError as e:
            print("BANK ACCOUNT INTEGRITY ERROR:", str(e))
            return Response(
                {
                    "error": "This bank account already exists or conflicts with another saved record. Please use another",
                    "details": str(e),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 3. Create Paystack customer
        ok, result = create_paystack_customer(user)
        print("CREATE PAYSTACK CUSTOMER OK:", ok)
        print("CREATE PAYSTACK CUSTOMER RESULT:", result)
        print("USER PAYSTACK CUSTOMER CODE AFTER CREATE:", user.paystack_customer_code)

        if not ok:
            return Response(
                {
                    "error": "Failed to create Paystack customer.",
                    "details": result,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.paystack_customer_code = str(user.paystack_customer_code or "").strip()

        if not user.paystack_customer_code.startswith("CUS_"):
            return Response(
                {
                    "error": "Invalid Paystack customer code stored for user.",
                    "details": {"paystack_customer_code": user.paystack_customer_code},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 4. If BVN is not provided yet, save bank account and stop here
        if not bvn:
            print("NO BVN PROVIDED. SAVING BANK ACCOUNT WITHOUT IDENTIFICATION/DVA.")

            user.paystack_identified = False
            user.paystack_identification_status = "failed"
            user.paystack_identification_reason = "BVN not yet provided"
            user.save(
                update_fields=[
                    "paystack_identified",
                    "paystack_identification_status",
                    "paystack_identification_reason",
                ]
            )

            return Response(
                {
                    "message": "Bank account added successfully. BVN not provided yet, so virtual account creation is pending.",
                    "bank_account": BankAccountSerializer(bank_account).data,
                    "bvn_required_for_dva": True,
                },
                status=status.HTTP_201_CREATED,
            )

        # 5. Identify customer using BVN
        ok, result = identify_paystack_customer(
            user=user,
            bvn=bvn,
            bank_code=bank_code,
            account_number=account_number,
        )

        already_validated = (
            not ok
            and isinstance(result, dict)
            and result.get("raw", {}).get("message")
            == "Customer already validated using the same credentials"
        )

        if already_validated:
            print(
                f"Customer already validated for {user.email}. Proceeding to DVA creation."
            )
            user.paystack_identified = True
            user.paystack_identification_status = "success"
            user.paystack_identification_reason = None
            user.save(
                update_fields=[
                    "paystack_identified",
                    "paystack_identification_status",
                    "paystack_identification_reason",
                ]
            )
            ok = True

        if not ok:
            if isinstance(result, dict) and result.get("status_code") == 202:
                user.paystack_identified = False
                user.paystack_identification_status = "processing"
                user.paystack_identification_reason = (
                    "Customer identification in progress"
                )
                user.save(
                    update_fields=[
                        "paystack_identified",
                        "paystack_identification_status",
                        "paystack_identification_reason",
                    ]
                )

                return Response(
                    {
                        "message": "Bank account saved. Customer identification is still processing.",
                        "identification_in_progress": True,
                        "bank_account": BankAccountSerializer(bank_account).data,
                        "details": result,
                    },
                    status=status.HTTP_202_ACCEPTED,
                )

            raw_message = (
                (result.get("raw") or {}).get("message", "")
                if isinstance(result, dict)
                else ""
            )

            raw_text = (
                (result.get("raw_text") or "") if isinstance(result, dict) else ""
            )

            combined_message = f"{raw_message} {raw_text}".strip()

            if is_paystack_name_mismatch_reason(combined_message):
                user.paystack_identified = False
                user.paystack_identification_status = "failed"
                user.paystack_identification_reason = "NAME_MISMATCH"
                user.save(
                    update_fields=[
                        "paystack_identified",
                        "paystack_identification_status",
                        "paystack_identification_reason",
                    ]
                )

                return Response(
                    {
                        "error": "NAME_MISMATCH",
                        "message": "Your profile name does not match your BVN details. Update your name and try again.",
                        "details": result,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.paystack_identified = False
            user.paystack_identification_status = "failed"
            user.paystack_identification_reason = (
                combined_message or "Customer identification failed"
            )
            user.save(
                update_fields=[
                    "paystack_identified",
                    "paystack_identification_status",
                    "paystack_identification_reason",
                ]
            )

            return Response(
                {
                    "error": "Customer identification failed.",
                    "details": result,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 6. Create DVA
        ok, dva_result = create_dedicated_account(
            user,
            preferred_bank="wema-bank",
            force_create=True,
        )

        print("CREATE DVA OK:", ok)
        print("CREATE DVA RESULT:", dva_result)

        if not ok:
            return Response(
                {
                    "error": "Bank saved but DVA creation failed.",
                    "bank_account": BankAccountSerializer(bank_account).data,
                    "details": dva_result,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 7. Notify user after successful DVA creation
        send_push_notification(
            user=user,
            title="Deposit Account Ready ✅",
            message=(
                f"Hi {user.first_name}, your MyFund Dedicated Virtual Account is now ready. "
                f"You can now fund your QuickSave with "
                f"{dva_result.get('account_name')} "
                f"({dva_result.get('account_number')} - {dva_result.get('bank_name')})."
            ),
            data={
                "type": "DVA_READY",
                "account_number": dva_result.get("account_number"),
                "bank_name": dva_result.get("bank_name"),
                "account_name": dva_result.get("account_name"),
            },
            notif_type="SYSTEM",
        )

        send_generic_email(
            subject="Your MyFund deposit account is ready ✅",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Your dedicated MyFund deposit account has been created successfully.<br><br>"
                f"<b>Bank:</b> {dva_result.get('bank_name')}<br>"
                f"<b>Account Number:</b> {dva_result.get('account_number')}<br>"
                f"<b>Account Name:</b> {dva_result.get('account_name')}<br><br>"
                f"You can now fund your QuickSave by bank transfer."
            ),
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[user.email],
        )

        # 8. Success
        return Response(
            {
                "message": "Bank account added and DVA created successfully.",
                "bank_account": BankAccountSerializer(bank_account).data,
                "dva": {
                    "account_number": dva_result.get("account_number"),
                    "bank_name": dva_result.get("bank_name"),
                    "account_name": dva_result.get("account_name"),
                },
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        print("ADD BANK ACCOUNT GENERAL ERROR:", str(e))
        return Response(
            {"error": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


from django.db.models import Count
from django.db import transaction


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
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


from rest_framework import generics
from .serializers import CardSerializer


class UserCardListView(generics.ListAPIView):
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return (
            Card.objects.filter(
                user=self.request.user,
                is_active=True,
                reusable=True,
            )
            .exclude(
                authorization_code__isnull=True,
            )
            .exclude(
                authorization_code="",
            )
            .order_by("-is_default", "-created_at")
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def remove_card(request):
    card_id = request.data.get("card_id")

    if not card_id:
        return Response(
            {"error": "card_id is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        card = Card.objects.get(id=card_id, user=request.user)
    except Card.DoesNotExist:
        return Response(
            {"error": "Card not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # Soft delete
    card.is_active = False
    card.is_default = False
    card.save()

    # Assign new default if needed
    replacement = (
        Card.objects.filter(user=request.user, is_active=True, reusable=True)
        .order_by("-created_at")
        .first()
    )

    if (
        replacement
        and not Card.objects.filter(
            user=request.user, is_active=True, is_default=True
        ).exists()
    ):
        replacement.is_default = True
        replacement.save()

    return Response(
        {"message": "Card removed successfully."},
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def set_default_card(request):
    card_id = request.data.get("card_id")

    if not card_id:
        return Response(
            {"error": "card_id is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        card = Card.objects.get(
            id=card_id,
            user=request.user,
            is_active=True,
            reusable=True,
        )
    except Card.DoesNotExist:
        return Response(
            {"error": "Card not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    card.is_default = True
    card.save()

    return Response(
        {"message": "Default card updated successfully."},
        status=status.HTTP_200_OK,
    )


from django.db import transaction, IntegrityError


from django.db import transaction


from django.db import transaction


def save_or_update_card_from_paystack_auth(user, authorization):
    """
    Save or update a card from Paystack authorization payload.

    Supports:
    - same physical card being used by multiple users
    - multiple saved cards per user
    - same-user updates by signature, authorization_code, or fingerprint
    """
    if not authorization:
<<<<<<< HEAD
        print("⚠️ save_or_update_card_from_paystack_auth: authorization payload missing")
=======
        print(
            "⚠️ save_or_update_card_from_paystack_auth: authorization payload missing"
        )
>>>>>>> staging
        return None

    authorization_code = (authorization.get("authorization_code") or "").strip()
    signature = (authorization.get("signature") or "").strip()

    print("========== SAVE CARD DEBUG ==========")
    print("user:", getattr(user, "email", None))
    print("authorization_code:", authorization_code)
    print("signature:", signature)
    print("raw reusable from paystack:", authorization.get("reusable"))
    print("brand:", authorization.get("brand"))
    print("last4:", authorization.get("last4"))
    print("bin:", authorization.get("bin"))
    print("exp_month:", authorization.get("exp_month"))
    print("exp_year:", authorization.get("exp_year"))
    print("bank:", authorization.get("bank"))

    if not authorization_code:
        print("⚠️ Card not saved: authorization_code missing")
        return None

    owner_name = (
        authorization.get("account_name")
        or f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}".strip()
        or getattr(user, "full_name", "")
        or getattr(user, "email", "")
        or "MyFund User"
    ).strip()

    card_first6 = (authorization.get("bin") or "").strip()
    card_last4 = (authorization.get("last4") or "").strip()
    expiry_month = str(authorization.get("exp_month") or "").strip()
    expiry_year = str(authorization.get("exp_year") or "").strip()

    card_defaults = {
        "authorization_code": authorization_code,
        "signature": signature or None,
        "card_type": (
            authorization.get("card_type") or authorization.get("channel") or ""
        ).strip(),
        "card_brand": (authorization.get("brand") or "").strip(),
        "card_first6_digits": card_first6,
        "card_last4_digits": card_last4,
        "card_owner_name": owner_name,
        "expiry_month": expiry_month,
        "expiry_year": expiry_year,
        "bank_name": (authorization.get("bank") or "").strip(),
        "country_code": (authorization.get("country_code") or "NG").strip(),
        "reusable": True,
        "is_active": True,
    }

    with transaction.atomic():
        existing_card = None

        # 1) Same user + signature
        if signature:
            existing_card = (
                Card.all_objects.select_for_update()
                .filter(user=user, signature=signature)
                .first()
            )

        # 2) Same user + authorization code
        if not existing_card:
            existing_card = (
                Card.all_objects.select_for_update()
                .filter(user=user, authorization_code=authorization_code)
                .first()
            )

        # 3) Same user + fingerprint fallback
        if not existing_card:
            existing_card = (
                Card.all_objects.select_for_update()
                .filter(
                    user=user,
                    card_first6_digits=card_first6,
                    card_last4_digits=card_last4,
                    expiry_month=expiry_month,
                    expiry_year=expiry_year,
                )
                .first()
            )

        if existing_card:
            for field, value in card_defaults.items():
                setattr(existing_card, field, value)

            existing_card.is_active = True
            existing_card.reusable = True

            has_other_default = (
                Card.all_objects.filter(user=user, is_active=True, is_default=True)
                .exclude(id=existing_card.id)
                .exists()
            )
            if not has_other_default:
                existing_card.is_default = True

            existing_card.save()
            print(
                f"✅ Existing card updated successfully for {user.email} | "
                f"card_id={existing_card.id} | signature={existing_card.signature}"
            )
            return existing_card

        is_first_card = not Card.all_objects.filter(user=user, is_active=True).exists()

        new_card = Card.all_objects.create(
            user=user,
            is_default=is_first_card,
            **card_defaults,
        )

        print(
            f"✅ New card saved successfully for {user.email} | "
            f"card_id={new_card.id} | signature={new_card.signature}"
        )
        return new_card


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
<<<<<<< HEAD
        transactions = Transaction.objects.filter(user=user).order_by("-date", "-time")
        return transactions
=======

        return (
            Transaction.objects.filter(user=user)
            .exclude(status__iexact="abandoned")
            .exclude(
                status__iexact="pending",
                source_channel="CARD",
            )
            .order_by("-date", "-time")
        )
>>>>>>> staging


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
from decimal import Decimal
from rest_framework import status
import requests
<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

# make sure these are already imported in your file
# from .models import Card, Transaction
# from .utils import send_generic_email


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def quicksave(request):
    """
    QuickSave flow:
    1. If card_id is sent, try instant charge with saved card
    2. If no card_id is sent, fall back to normal Paystack popup/webview flow
    """

    amount = request.data.get("amount")
    payment_channels = request.data.get("channels", ["card"])
    card_id = request.data.get("card_id")

    if amount is None:
        return Response(
            {"error": "amount required"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        amount = Decimal(str(amount))
    except Exception:
        return Response(
            {"error": "Invalid amount supplied"},
            status=status.HTTP_400_BAD_REQUEST,
        )

<<<<<<< HEAD
    if amount < Decimal("100"):
        return Response(
            {"error": "Amount cannot be less than ₦100"},
=======
    if amount < settings.MIN_DEPOSIT_AMOUNT:
        return Response(
            {"error": f"Amount cannot be less than ₦{settings.MIN_DEPOSIT_AMOUNT}"},
>>>>>>> staging
            status=status.HTTP_400_BAD_REQUEST,
        )

    amount_kobo = int(amount * 100)

    # ===================================
    # CHECK FOR SAVED CARD ONLY IF card_id IS PROVIDED
    # ===================================
    saved_card = None

    if card_id:
        try:
            saved_card = Card.objects.get(
                id=card_id,
                user=request.user,
                is_active=True,
                reusable=True,
            )
        except Card.DoesNotExist:
            return Response(
                {
                    "error": "Selected card not found or not available for instant payment"
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    # ===================================
    # INSTANT PAYMENT WITH SAVED CARD
    # ===================================
    if saved_card:
        payload = {
            "authorization_code": saved_card.authorization_code,
            "email": request.user.email,
            "amount": amount_kobo,
            "metadata": {
                "user_id": request.user.id,
                "transaction_type": "quicksave",
                "card_id": saved_card.id,
            },
        }

        try:
            resp = requests.post(
                "https://api.paystack.co/transaction/charge_authorization",
                json=payload,
                headers={
                    "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
        except requests.RequestException as e:
            print(f"Instant payment request failed: {str(e)}")
            return Response(
                {"error": "Instant payment request failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            data = resp.json()
        except Exception:
            data = {}

        if resp.status_code != 200 or not data.get("status"):
            print(f"Instant charge failed: {resp.text}")
            return Response(
                {
                    "error": data.get("message", "Instant card charge failed"),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        charge_data = data.get("data", {})
        charge_status = charge_data.get("status")
        reference = charge_data.get("reference")

        if charge_status == "success":
            tx = create_transaction(
                user=request.user,
                amount=amount,
                transaction_type="credit",
                credited_to="SAVINGS",
                description="QuickSave (Card)",
                reference=reference,
            )

            tx.paystack_auth_code = saved_card.authorization_code
            tx.paystack_reference = reference
            tx.save(update_fields=["paystack_auth_code", "paystack_reference"])

            request.user.refresh_from_db(fields=["savings"])
            request.user.update_total_savings_and_investment_this_month()

            try:
                subject = "QuickSave Successful! ✅"
                message = (
                    f"Well done {request.user.first_name},<br><br>"
                    f"Your <b>QuickSave</b> of <b>₦{amount:,.2f}</b> was successful and has been added to your SAVINGS account.<br><br>"
                    f"Payment Method: {saved_card.card_brand.upper()} •••• {saved_card.card_last4_digits}<br>"
                    f"Transaction ID: {reference}<br><br>"
                    f"Keep growing your funds.🥂"
                )
                send_generic_email(
                    subject=subject,
                    message=message,
<<<<<<< HEAD
                    from_email="MyFund <info@myfundmobile.com>",
=======
                    from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                    recipient_list=[request.user.email],
                )
            except Exception as e:
                print(f"Failed to send email: {str(e)}")

            return Response(
                {
                    "status": "success",
                    "payment_method": "instant",
                    "message": "QuickSave successful! Amount added to your savings.",
                    "amount": float(amount),
                    "reference": reference,
                    "card_used": {
                        "brand": saved_card.card_brand,
                        "last4": saved_card.card_last4_digits,
                        "bank": saved_card.bank_name,
                    },
                    "new_balance": float(request.user.savings),
                },
                status=status.HTTP_200_OK,
            )

        if charge_status in [
            "send_otp",
            "send_pin",
            "send_phone",
            "send_birthday",
            "pending",
        ]:
            return Response(
                {
                    "error": "This saved card requires additional authentication. Please pay through the secure payment page instead."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "error": charge_data.get(
                    "gateway_response", "Instant card charge failed"
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # ===================================
    # REGULAR PAYMENT FLOW (FIRST TIME / NO card_id)
    # ===================================
    payload = {
        "email": request.user.email,
        "amount": amount_kobo,
        "channels": payment_channels,
        "metadata": {
            "user_id": request.user.id,
            "transaction_type": "quicksave",
        },
    }

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers={
                "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
    except requests.RequestException as e:
        return Response(
            {"error": f"Payment initialization failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    try:
        data = resp.json()
    except Exception:
        return Response(
            {"error": "Invalid response from payment gateway"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if resp.status_code != 200:
        return Response(
            {"error": data.get("message", "Payment initialization failed")},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not data.get("status"):
        return Response(
            {
                "error": f"Payment initialization failed: {data.get('message', 'Unknown error')}"
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    reference = data["data"]["reference"]
    access_code = data["data"]["access_code"]

    # KEEP THIS AS PENDING PLACEHOLDER
    Transaction.objects.create(
        user=request.user,
        transaction_type="credit",
        status="pending",
        amount=amount,
        description="QuickSave",
        transaction_id=reference,
        paystack_access_code=access_code,
    )

    return Response(
        {
            "status": "transaction_initiated",
            "payment_method": "popup",
            "message": "Authorization of QuickSave transaction on Paystack required",
            "authorization_url": data["data"]["authorization_url"],
            "access_code": access_code,
            "reference": reference,
        },
        status=status.HTTP_200_OK,
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
    card_id = request.data.get("card_id")  # Get card_id from request

    # Validate request data
    if not amount or not frequency:
        return Response(
            {"error": "Missing required fields: amount and frequency."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not card_id:
        return Response(
            {"error": "card_id is required to activate AutoSave."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = int(amount)
<<<<<<< HEAD
        if amount < 100:
            return Response(
                {"error": "Amount cannot be less than ₦100"},
=======
        if amount < settings.MIN_DEPOSIT_AMOUNT:
            return Response(
                {"error": f"Amount cannot be less than ₦{settings.MIN_DEPOSIT_AMOUNT}"},
>>>>>>> staging
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

    # Get the selected card
    try:
        card = Card.objects.get(id=card_id, user=user, is_active=True, reusable=True)
    except Card.DoesNotExist:
        return Response(
            {"error": "Selected card not found or not available for AutoSave."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # Get authorization code from the card
    authorization_code = card.authorization_code

    if not authorization_code:
        return Response(
            {"error": "This card does not have a valid authorization code."},
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

    # Step 2: Subscribe user to the plan using the card's authorization code
    subscription_payload = {
        "customer": user.email,
        "plan": plan_code,
        "authorization": authorization_code,  # Use authorization code from selected card
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
            error_message = subscription_data.get("message", "Subscription failed.")
            return Response(
                {"error": error_message},
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
        card=card,
        active=True,
    )

    # Send success notification email
    subject = "AutoSave Activated!"
    message = (
        f"Hi {user.first_name},<br><br>"
        f"Your AutoSave has been activated. You are now saving ₦{amount:,} {frequency}.<br><br>"
        f"Payment Method: {card.card_brand.upper()} •••• {card.card_last4_digits}<br>"
        f"Bank: {card.bank_name}<br><br>"
        f"Keep growing your funds.🥂"
    )
<<<<<<< HEAD
    from_email = "MyFund <info@myfundmobile.com>"
=======
    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
    recipient_list = [user.email]

    send_generic_email(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=recipient_list,
    )

    # Mark user as having autosave enabled
    user.autosave_enabled = True
    user.save()

    # Send push notification
    send_push_notification(
        user=user,
        title="AutoSave Activated! ✅",
        message=f"Well done {user.first_name}! You're now saving ₦{amount:,} {frequency} using your {card.card_brand.upper()} card. Keep growing your funds.",
        data={
            "amount": str(amount),
            "frequency": frequency,
            "card_brand": card.card_brand,
            "card_last4": card.card_last4_digits,
            "type": "AutoSave",
            "status": "activated",
        },
        notif_type="SYSTEM",
    )

    return Response(
        {
            "message": "AutoSave activated successfully",
            "autosave": {
                "amount": amount,
                "frequency": frequency,
                # "card_used": {
                #     "brand": card.card_brand,
                #     "last4": card.card_last4_digits,
                #     "bank": card.bank_name,
                # },
                # "subscription_code": subscription_code,
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def deactivate_autosave(request):
    user = request.user
    frequency = request.data.get("frequency")

    if not frequency:
        return Response(
            {
                "error": "Frequency Missing: Please provide the frequency of the autosave."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        active_autosaves = AutoSave.objects.filter(
            user=user,
            frequency=frequency,
            active=True,
        )

        if not active_autosaves.exists():
            user.autosave_enabled = False
            user.save(update_fields=["autosave_enabled"])
            return Response(
                {"message": "No active AutoSave found for this frequency."},
                status=status.HTTP_200_OK,
            )

        headers = {
            "Authorization": f"Bearer {paystack_secret_key}",
            "Content-Type": "application/json",
        }

        for autosave in active_autosaves:
            # If Paystack subscription exists, disable it first
            if autosave.paystack_sub_code and autosave.paystack_sub_token:
                data = {
                    "code": autosave.paystack_sub_code,
                    "token": autosave.paystack_sub_token,
                }

                deactivate_response = requests.post(
                    "https://api.paystack.co/subscription/disable",
                    json=data,
                    headers=headers,
                    timeout=30,
                )
                deactivate_response.raise_for_status()

            # Whether or not Paystack details exist, make sure record is no longer active
            autosave.active = False
            autosave.save(update_fields=["active"])
            autosave.delete()

        # Check if user still has any active autosave left
        still_has_active_autosave = AutoSave.objects.filter(
            user=user,
            active=True,
        ).exists()

        user.autosave_enabled = still_has_active_autosave
        user.save(update_fields=["autosave_enabled"])

        subject = "AutoSave Deactivated!"
        message = (
            f"Hi {user.first_name},<br><br>"
            f"Your {frequency} AutoSave has been deactivated successfully."
            f"<br><br>Keep growing your funds.🥂"
        )
<<<<<<< HEAD
        from_email = "MyFund <info@myfundmobile.com>"
=======
        from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
        recipient_list = [user.email]

        send_generic_email(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
        )

        return Response(
            {"message": "AutoSave deactivated"},
            status=status.HTTP_200_OK,
        )

    except requests.RequestException as e:
        return Response(
            {"error": f"Failed to deactivate subscription on Paystack: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception as e:
        return Response(
            {"error": str(e)},
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


from decimal import Decimal
from rest_framework import status
import requests
<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

# make sure these are already imported in your file
# from .models import Card, Transaction
# from .utils import send_generic_email


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def quickinvest(request):
    """
    QuickInvest flow:
    1. If card_id is sent, try instant charge with saved card
    2. If no card_id is sent, fall back to normal Paystack popup/webview flow
    """

    from .utils import create_transaction

    amount = request.data.get("amount")
    payment_channels = request.data.get("channels", ["card"])
    card_id = request.data.get("card_id")

    if amount is None:
        return Response(
            {"error": "amount required"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        amount = Decimal(str(amount))
    except Exception:
        return Response(
            {"error": "Invalid amount supplied"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount < Decimal("100000"):
        return Response(
            {"error": "Amount cannot be less than ₦100,000"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    amount_kobo = int(amount * 100)

    saved_card = None

    if card_id:
        try:
            saved_card = Card.objects.get(
                id=card_id,
                user=request.user,
                is_active=True,
                reusable=True,
            )
        except Card.DoesNotExist:
            return Response(
                {
                    "error": "Selected card not found or not available for instant payment"
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    # ===============================
    # INSTANT PAYMENT (SAVED CARD)
    # ===============================
    if saved_card:
        payload = {
            "authorization_code": saved_card.authorization_code,
            "email": request.user.email,
            "amount": amount_kobo,
            "metadata": {
                "user_id": request.user.id,
                "transaction_type": "quickinvest",
                "card_id": saved_card.id,
            },
        }

        try:
            resp = requests.post(
                "https://api.paystack.co/transaction/charge_authorization",
                json=payload,
                headers={
                    "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
        except requests.RequestException as e:
            print(f"Instant payment request failed: {str(e)}")
            return Response(
                {"error": "Instant payment request failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            data = resp.json()
        except Exception:
            data = {}

        if resp.status_code != 200 or not data.get("status"):
            print(f"Instant charge failed: {resp.text}")
            return Response(
                {"error": data.get("message", "Instant card charge failed")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        charge_data = data.get("data", {})
        charge_status = charge_data.get("status")
        reference = charge_data.get("reference")

        if charge_status == "success":
            tx = create_transaction(
                user=request.user,
                amount=amount,
                transaction_type="credit",
                credited_to="INVESTMENT",
                description=f"QuickInvest (Instant - {saved_card.card_brand.upper()} •••• {saved_card.card_last4_digits})",
                reference=reference,
            )

            # attach Paystack metadata AFTER creation
            tx.paystack_auth_code = saved_card.authorization_code
            tx.paystack_reference = reference
            tx.save(update_fields=["paystack_auth_code", "paystack_reference"])

            request.user.refresh_from_db(fields=["investment"])
            request.user.update_total_savings_and_investment_this_month()

            try:
                subject = "QuickInvest Successful! 🎉"
                message = (
                    f"Well done {request.user.first_name},<br><br>"
                    f"Your <b>QuickInvest</b> of <b>₦{amount:,.2f}</b> was successful and has been added to your INVESTMENT account.<br><br>"
                    f"Payment Method: {saved_card.card_brand.upper()} •••• {saved_card.card_last4_digits}<br>"
                    f"Transaction ID: {reference}<br><br>"
                    f"Keep growing your funds.🥂"
                )
                send_generic_email(
                    subject=subject,
                    message=message,
<<<<<<< HEAD
                    from_email="MyFund <info@myfundmobile.com>",
=======
                    from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                    recipient_list=[request.user.email],
                )
            except Exception as e:
                print(f"Failed to send email: {str(e)}")

            return Response(
                {
                    "status": "success",
                    "payment_method": "instant",
                    "message": "QuickInvest successful! Amount added to your investments.",
                    "amount": float(amount),
                    "reference": reference,
                    "card_used": {
                        "brand": saved_card.card_brand,
                        "last4": saved_card.card_last4_digits,
                        "bank": saved_card.bank_name,
                    },
                    "new_balance": float(request.user.investment),
                },
                status=status.HTTP_200_OK,
            )

        if charge_status in [
            "send_otp",
            "send_pin",
            "send_phone",
            "send_birthday",
            "pending",
        ]:
            return Response(
                {
                    "error": "This saved card requires additional authentication. Please pay through the secure payment page instead."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "error": charge_data.get(
                    "gateway_response", "Instant card charge failed"
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # ===============================
    # NORMAL FLOW (NO CARD)
    # ===============================
    payload = {
        "email": request.user.email,
        "amount": amount_kobo,
        "channels": payment_channels,
        "metadata": {
            "user_id": request.user.id,
            "transaction_type": "quickinvest",
        },
    }

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers={
                "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
    except requests.RequestException as e:
        return Response(
            {"error": f"Payment initialization failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    try:
        data = resp.json()
    except Exception:
        return Response(
            {"error": "Invalid response from payment gateway"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if resp.status_code != 200:
        return Response(
            {"error": data.get("message", "Payment initialization failed")},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not data.get("status"):
        return Response(
            {
                "error": f"Payment initialization failed: {data.get('message', 'Unknown error')}"
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    reference = data["data"]["reference"]
    access_code = data["data"]["access_code"]

    # KEEP THIS AS PENDING
    Transaction.objects.create(
        user=request.user,
        transaction_type="credit",
        status="pending",
        amount=amount,
        description="QuickInvest",
        transaction_id=reference,
        paystack_access_code=access_code,
    )

    return Response(
        {
            "status": "transaction_initiated",
            "payment_method": "popup",
            "message": "Authorization of QuickInvest transaction on Paystack required",
            "authorization_url": data["data"]["authorization_url"],
            "access_code": access_code,
            "reference": reference,
        },
        status=status.HTTP_200_OK,
    )


from .models import AutoInvest


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def autoinvest(request):
    user = request.user
    amount = request.data.get("amount")
    frequency = request.data.get("frequency")
    card_id = request.data.get("card_id")  # Get card_id from request

    # Validate request data
    if not amount or not frequency:
        return Response(
            {"error": "Missing required fields: amount and frequency."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not card_id:
        return Response(
            {"error": "card_id is required to activate AutoInvest."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = int(amount)
        if amount < 100000:
            return Response(
                {"error": "Amount cannot be less than ₦100,000."},
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

    # Check for existing AutoInvest records for the user
    if AutoInvest.objects.filter(user=user, frequency=frequency, active=True).exists():
        return Response(
            {
                "error": f"An active AutoInvest record already exists for frequency: {frequency}."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Get the selected card
    try:
        card = Card.objects.get(id=card_id, user=user, is_active=True, reusable=True)
    except Card.DoesNotExist:
        return Response(
            {"error": "Selected card not found or not available for AutoInvest."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # Get authorization code from the card
    authorization_code = card.authorization_code

    if not authorization_code:
        return Response(
            {"error": "This card does not have a valid authorization code."},
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

        if not plan_data.get("status"):
            return Response(
                {"error": "Failed to create plan on Paystack."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        plan_code = plan_data["data"]["plan_code"]
    except requests.RequestException as e:
        logger.error(f"Paystack plan creation failed: {e}")
        return Response(
            {"error": f"Failed to create plan on Paystack: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 2: Subscribe user to the plan using the card's authorization code
    subscription_payload = {
        "customer": user.email,
        "plan": plan_code,
        "authorization": authorization_code,  # Use authorization code from selected card
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
            error_message = subscription_data.get("message", "Subscription failed.")
            return Response(
                {"error": error_message},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        subscription_id = subscription_data.get("data", {}).get("id")
        subscription_code = subscription_data.get("data", {}).get("subscription_code")
        subscription_token = subscription_data.get("data", {}).get("email_token")
        transaction_reference = subscription_data.get("data", {}).get("reference")
    except requests.RequestException as e:
        logger.error(f"Subscription failed: {e}")
        return Response(
            {"error": f"Subscription failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 3: Save AutoInvest record to the database
    with transaction.atomic():
        autoinvest_record = AutoInvest.objects.create(
            user=user,
            frequency=frequency,
            amount=amount,
            paystack_sub_id=subscription_id,
            paystack_sub_code=subscription_code,
            paystack_sub_token=subscription_token,
            paystack_plan_code=plan_code,
            paystack_trans_ref=transaction_reference,
            card=card,
            active=True,
        )

    # Send success notification email
    subject = "AutoInvest Activated!"
    message = (
        f"Hi {user.first_name},<br><br>"
        f"Your AutoInvest has been activated. You are now investing ₦{amount:,} {frequency}.<br><br>"
        f"Payment Method: {card.card_brand.upper()} •••• {card.card_last4_digits}<br>"
        f"Bank: {card.bank_name}<br><br>"
        f"Keep growing your funds.🥂"
    )
<<<<<<< HEAD
    from_email = "MyFund <info@myfundmobile.com>"
=======
    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
    recipient_list = [user.email]

    send_generic_email(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=recipient_list,
    )

    # Optional: Send push notification
    try:
        send_push_notification(
            user=user,
            title="AutoInvest Activated! 🎉",
            message=f"Well done {user.first_name}! You're now investing ₦{amount:,} {frequency} using your {card.card_brand.upper()} card. Keep growing your funds.",
            data={
                "amount": str(amount),
                "frequency": frequency,
                "card_brand": card.card_brand,
                "card_last4": card.card_last4_digits,
                "type": "AutoInvest",
                "status": "activated",
            },
            notif_type="SYSTEM",
        )
    except Exception as e:
        logger.error(f"Push notification failed: {e}")

    return Response(
        {
            "message": "AutoInvest activated successfully",
            "autoinvest": {
                "id": autoinvest_record.id,
                "amount": amount,
                "frequency": frequency,
                "card_used": {
                    "brand": card.card_brand,
                    "last4": card.card_last4_digits,
                    "bank": card.bank_name,
                },
                "subscription_code": subscription_code,
            },
        },
        status=status.HTTP_200_OK,
    )


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
<<<<<<< HEAD
        from_email = "MyFund <info@myfundmobile.com>"
=======
        from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
        recipient_list = [user.email]

        send_generic_email(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
        )

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

<<<<<<< HEAD
=======
MINIMUM_INVESTMENT_AMOUNT = Decimal("100000")

>>>>>>> staging

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def savings_to_investment(request):
    user = request.user

<<<<<<< HEAD
    # Ensure user is authenticated
=======
>>>>>>> staging
    if not user or not user.is_authenticated:
        return Response(
            {"error": "Authentication credentials were not provided."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

<<<<<<< HEAD
    # Validate and parse amount
=======
>>>>>>> staging
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

<<<<<<< HEAD
    try:
        with transaction.atomic():
            # Refresh user to get latest balance and lock row for update
=======
    if amount < MINIMUM_INVESTMENT_AMOUNT:
        return Response(
            {
                "error": f"Minimum investment amount is ₦{MINIMUM_INVESTMENT_AMOUNT:,.0f}."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
>>>>>>> staging
            user = user.__class__.objects.select_for_update().get(pk=user.pk)

            if user.savings < amount:
                return Response(
                    {"error": "Insufficient savings balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

<<<<<<< HEAD
            # Use full UUID for transaction IDs (no truncation)
            base_transaction_id = str(uuid.uuid4())[:16]
=======
            base_transaction_id = str(uuid.uuid4())[:16]
            debit_transaction_id = base_transaction_id + "-D"
            credit_transaction_id = base_transaction_id + "-C"
>>>>>>> staging

            create_transaction(
                user=user,
                amount=amount,
                transaction_type="debit",
                status="confirmed",
                source="SAVINGS",
                description="Savings > Investment",
                service_charge=0,
<<<<<<< HEAD
                reference=base_transaction_id + "-D",
=======
                reference=debit_transaction_id,
>>>>>>> staging
            )

            create_transaction(
                user=user,
                amount=amount,
                transaction_type="credit",
                status="confirmed",
                credited_to="INVESTMENT",
                description="QuickInvest",
                service_charge=0,
<<<<<<< HEAD
                reference=base_transaction_id + "-C",
            )

            # Send push notification after successful transfer
            send_push_notification(
                user=user,
                title="Savings > Investment Transfer ✅",
                message=f"You have successfully transferred ₦{amount:,.0f} from your Savings to Investment.",
                data={
                    "amount": float(amount),
                    "from": "savings",
                    "to": "investment",
                    "debit_transaction_id": debit_transaction_id,
                    "credit_transaction_id": credit_transaction_id,
                },
                notif_type="TRANSACTION",
            )
=======
                reference=credit_transaction_id,
            )

            # Refresh to get updated balances after create_transaction mutations
            user.refresh_from_db()

            try:
                send_push_notification(
                    user=user,
                    title="Savings > Investment Transfer ✅",
                    message=f"You have successfully transferred ₦{amount:,.0f} from your Savings to Investment.",
                    data={
                        "amount": float(amount),
                        "from": "savings",
                        "to": "investment",
                        "debit_transaction_id": debit_transaction_id,
                        "credit_transaction_id": credit_transaction_id,
                    },
                    notif_type="TRANSACTION",
                )
            except Exception:
                pass  # Don't let push notification failure roll back the transaction
>>>>>>> staging

            return Response(
                {
                    "message": "Savings to investment transfer successful.",
                    "debit_transaction_id": debit_transaction_id,
                    "credit_transaction_id": credit_transaction_id,
<<<<<<< HEAD
=======
                    "newAccountBalances": {
                        "savings": float(user.savings),
                        "investment": float(user.investment),
                        "wallet": float(user.wallet),
                        "properties": float(user.properties),
                    },
>>>>>>> staging
                },
                status=status.HTTP_200_OK,
            )

<<<<<<< HEAD
    except Transaction.DoesNotExist:
        return Response(
            {"error": "User account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
=======
>>>>>>> staging
    except IntegrityError:
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )
<<<<<<< HEAD

    return Response(
        {
            "message": "Savings to investment transfer successful.",
            "debit_transaction_id": debit_transaction_id,
            "credit_transaction_id": credit_transaction_id,
        },
        status=status.HTTP_200_OK,
    )
=======
    except Exception as e:
        return Response(
            {"error": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
>>>>>>> staging


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_to_savings(request):
    user = request.user

<<<<<<< HEAD
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
=======
    amount_raw = request.data.get("amount", None)
    if amount_raw is None:
        return Response(
            {"error": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST
>>>>>>> staging
        )

    try:
        amount = Decimal(amount_raw)
    except (InvalidOperation, TypeError):
        return Response(
<<<<<<< HEAD
            {"error": "Invalid amount format."},
            status=status.HTTP_400_BAD_REQUEST,
=======
            {"error": "Invalid amount format."}, status=status.HTTP_400_BAD_REQUEST
>>>>>>> staging
        )

    if amount <= 0:
        return Response(
            {"error": "Amount must be greater than zero."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
<<<<<<< HEAD
            # Lock user record to prevent race conditions
=======
>>>>>>> staging
            user = user.__class__.objects.select_for_update().get(pk=user.pk)

            if user.wallet < amount:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

<<<<<<< HEAD
            # Use full UUID for transaction IDs with clear suffixes
=======
>>>>>>> staging
            base_transaction_id = str(uuid.uuid4())[:16]

            create_transaction(
                user=user,
                amount=amount,
                transaction_type="debit",
                status="confirmed",
                source="WALLET",
                description="Wallet > Savings",
                service_charge=0,
                reference=base_transaction_id + "-D",
            )

            create_transaction(
                user=user,
                amount=amount,
                transaction_type="credit",
                status="confirmed",
                credited_to="SAVINGS",
                description="QuickSave (Transfer)",
                service_charge=0,
                reference=base_transaction_id + "-C",
            )

<<<<<<< HEAD
            # Send push notification after successful transfer
            send_push_notification(
                user=user,
                title="Wallet > Savings Successful ✅",
                message=f"You have successfully transferred ₦{amount:,.0f} from your Wallet to Savings. Well done!",
                data={
                    "amount": float(amount),
                    "from": "wallet",
                    "to": "savings",
                    "transaction_id": base_transaction_id,
                },
                notif_type="TRANSACTION",
            )
=======
            user.refresh_from_db()

            try:
                send_push_notification(
                    user=user,
                    title="Wallet > Savings Successful ✅",
                    message=f"You have successfully transferred ₦{amount:,.0f} from your Wallet to Savings. Well done!",
                    data={
                        "amount": float(amount),
                        "from": "wallet",
                        "to": "savings",
                        "transaction_id": base_transaction_id,
                    },
                    notif_type="TRANSACTION",
                )
            except Exception:
                pass
>>>>>>> staging

            return Response(
                {
                    "message": "Wallet to savings transfer successful.",
                    "transaction_id": base_transaction_id,
<<<<<<< HEAD
=======
                    "newAccountBalances": {
                        "savings": float(user.savings),
                        "investment": float(user.investment),
                        "wallet": float(user.wallet),
                        "properties": float(user.properties),
                    },
>>>>>>> staging
                },
                status=status.HTTP_200_OK,
            )

<<<<<<< HEAD
    except user.DoesNotExist:
        return Response(
            {"error": "User account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
=======
>>>>>>> staging
    except IntegrityError:
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )
<<<<<<< HEAD

    return Response(
        {
            "message": "Wallet to savings transfer successful.",
            "transaction_id": base_transaction_id,
        },
        status=status.HTTP_200_OK,
    )
=======
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


MINIMUM_INVESTMENT_AMOUNT = Decimal("100000")
>>>>>>> staging


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_to_investment(request):
    user = request.user

<<<<<<< HEAD
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
=======
    amount_raw = request.data.get("amount", None)
    if amount_raw is None:
        return Response(
            {"error": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST
>>>>>>> staging
        )

    try:
        amount = Decimal(amount_raw)
    except (InvalidOperation, TypeError):
        return Response(
<<<<<<< HEAD
            {"error": "Invalid amount format."},
            status=status.HTTP_400_BAD_REQUEST,
=======
            {"error": "Invalid amount format."}, status=status.HTTP_400_BAD_REQUEST
>>>>>>> staging
        )

    if amount <= 0:
        return Response(
            {"error": "Amount must be greater than zero."},
            status=status.HTTP_400_BAD_REQUEST,
        )

<<<<<<< HEAD
    try:
        with transaction.atomic():
            # Lock user record to prevent race conditions
=======
    if amount < MINIMUM_INVESTMENT_AMOUNT:
        return Response(
            {
                "error": f"Minimum investment amount is ₦{MINIMUM_INVESTMENT_AMOUNT:,.0f}."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
>>>>>>> staging
            user = user.__class__.objects.select_for_update().get(pk=user.pk)

            if user.wallet < amount:
                return Response(
                    {"error": "Insufficient wallet balance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

<<<<<<< HEAD
            # Use full UUID as base transaction ID
=======
>>>>>>> staging
            base_transaction_id = str(uuid.uuid4())[:16]

            create_transaction(
                user=user,
                amount=amount,
                transaction_type="debit",
                status="confirmed",
                source="WALLET",
                description="Wallet > Investment",
                service_charge=0,
                reference=base_transaction_id + "-D",
            )

            create_transaction(
                user=user,
                amount=amount,
                transaction_type="credit",
                status="confirmed",
                credited_to="INVESTMENT",
                description="QuickInvest (Transfer)",
                service_charge=0,
                reference=base_transaction_id + "-C",
            )

<<<<<<< HEAD
            # Send push notification after successful transfer
            send_push_notification(
                user=user,
                title="Wallet > Investment Successful ✅",
                message=f"You have successfully transferred ₦{amount:,.0f} from your Wallet to Investment. Well done!",
                data={
                    "amount": float(amount),
                    "from": "wallet",
                    "to": "investment",
                    "transaction_id": base_transaction_id,
                },
                notif_type="TRANSACTION",
            )
=======
            user.refresh_from_db()

            try:
                send_push_notification(
                    user=user,
                    title="Wallet > Investment Successful ✅",
                    message=f"You have successfully transferred ₦{amount:,.0f} from your Wallet to Investment. Well done!",
                    data={
                        "amount": float(amount),
                        "from": "wallet",
                        "to": "investment",
                        "transaction_id": base_transaction_id,
                    },
                    notif_type="TRANSACTION",
                )
            except Exception:
                pass
>>>>>>> staging

            return Response(
                {
                    "message": "Wallet to investment transfer successful.",
                    "transaction_id": base_transaction_id,
<<<<<<< HEAD
=======
                    "newAccountBalances": {
                        "savings": float(user.savings),
                        "investment": float(user.investment),
                        "wallet": float(user.wallet),
                        "properties": float(user.properties),
                    },
>>>>>>> staging
                },
                status=status.HTTP_200_OK,
            )

<<<<<<< HEAD
    except user.DoesNotExist:
        return Response(
            {"error": "User account not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
=======
>>>>>>> staging
    except IntegrityError:
        return Response(
            {"error": "Transaction ID conflict. Please try again."},
            status=status.HTTP_400_BAD_REQUEST,
        )
<<<<<<< HEAD

    return Response(
        {
            "message": "Wallet to investment transfer successful.",
            "transaction_id": base_transaction_id,
        },
        status=status.HTTP_200_OK,
    )
=======
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
>>>>>>> staging


import uuid
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db import IntegrityError
from django.core.mail import send_mail
from authentication.models import BankAccount, Transaction, WithdrawalsRequestToAdmin

import threading
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
import random
import string
from datetime import datetime, timedelta


def _bg(fn, **kwargs):
    """Fire-and-forget a function in a daemon thread."""
    threading.Thread(target=fn, kwargs=kwargs, daemon=True).start()


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def withdraw_to_local_bank(request):
    User = get_user_model()
    user = request.user
    source_account = request.data.get("source_account", "").strip().lower()
    target_bank_account_id = request.data.get("target_bank_account_id", "")
    amount_raw = request.data.get("amount", 0)

    if not source_account:
        return Response({"error": '"source_account" was NOT provided.'}, status=400)
    if not target_bank_account_id:
        return Response(
            {"error": '"target_bank_account_id" was NOT provided.'}, status=400
        )
    if not request.data.get("amount", 0):
        return Response(
            {"error": '"amount" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        amount = Decimal(str(amount_raw)).quantize(
            Decimal("0.00"), rounding=ROUND_HALF_EVEN
        )
    except Exception:
        return Response({"error": "Invalid amount format."}, status=400)

    VALID_SOURCES = ["savings", "investment", "wallet"]
    if source_account not in VALID_SOURCES:
        return Response({"error": "Invalid source account."}, status=400)

    if amount <= 0:
        return Response({"error": "Amount must be greater than zero."}, status=400)

    with transaction.atomic():
        user = User.objects.select_for_update().get(pk=request.user.pk)

        if source_account == "savings" and user.savings < amount:
            return Response({"error": "Insufficient savings balance."}, status=400)
        if source_account == "investment" and user.investment < amount:
            return Response({"error": "Insufficient investment balance."}, status=400)
        if source_account == "wallet" and user.wallet < amount:
            return Response({"error": "Insufficient wallet balance."}, status=400)

        try:
            target_bank_account = BankAccount.objects.get(
                id=target_bank_account_id,
                user=user,
            )
        except BankAccount.DoesNotExist:
            return Response({"error": "Target bank account not found."}, status=400)

        from .utils import calculate_withdrawal_charges

        rate, service_charge, withdrawal_amount = calculate_withdrawal_charges(
            amount, source_account
        )

        reference_code = generate_reference()
        transaction_id = f"withdrawal-{reference_code}"

        try:
            if source_account == "savings":
                previous_balance = user.savings
                new_balance = user.savings - amount
                source_choice = "SAVINGS"
            elif source_account == "investment":
                previous_balance = user.investment
                new_balance = user.investment - amount
                source_choice = "INVESTMENT"
            else:
                previous_balance = user.wallet
                new_balance = user.wallet - amount
                source_choice = "WALLET"

            transaction_details = Transaction.objects.create(
                user=user,
                transaction_type="debit",
                status="pending",
                amount=withdrawal_amount,
                service_charge=service_charge,
                total_amount=amount,
                source=source_choice,
                description=f"{source_account.capitalize()} > Bank . . .",
                transaction_id=transaction_id,
            )

            paystack_response = make_withdrawal_through_paystack(
                user,
                target_bank_account,
                withdrawal_amount,
                transaction_id,
            )
            print("Paystack API Response:", paystack_response)

            if paystack_response.get("status"):
                if source_account == "savings":
                    user.savings = new_balance
                    user.save(update_fields=["savings"])
                elif source_account == "investment":
                    user.investment = new_balance
                    user.save(update_fields=["investment"])
                else:
                    user.wallet = new_balance
                    user.save(update_fields=["wallet"])

                transaction_details.status = "confirmed"
                transaction_details.balance_before = previous_balance
                transaction_details.balance_after = new_balance
                transaction_details.save(
                    update_fields=[
                        "status",
                        "balance_before",
                        "balance_after",
                    ]
                )

                _bg(
                    send_generic_email,
                    subject=f"Withdrawal Successful: ₦{amount:,.2f}",
                    message=(
                        f"Hi {user.first_name},<br><br>"
                        f"Your withdrawal request of <strong>₦{amount:,.2f}</strong> from your "
                        f"{source_account.capitalize()} account has been processed successfully.<br><br>"
                        f"<strong>Amount credited to your bank account:</strong> ₦{withdrawal_amount:,.2f}<br>"
                        f"<strong>Charge deducted:</strong> ₦{service_charge:,.2f}<br>"
                        f"<strong>Bank:</strong> {target_bank_account.bank_name}<br>"
                        f"<strong>Account:</strong> {target_bank_account.account_name} - {target_bank_account.account_number}<br><br>"
                        "Thank you for using MyFund! 🥂<br><br>"
                    ),
<<<<<<< HEAD
                    from_email="MyFund <info@myfundmobile.com>",
=======
                    from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                    recipient_list=[user.email],
                )

                _bg(
                    send_push_notification,
                    user=user,
                    title="Withdrawal Successful ✅",
                    message=(
                        f"Your withdrawal request of ₦{amount:,.2f} has been processed. "
                        f"₦{withdrawal_amount:,.2f} was credited to your bank account after "
                        f"₦{service_charge:,.2f} charge."
                    ),
                    data={
                        "amount": str(amount),
                        "net_amount": str(withdrawal_amount),
                        "charge_amount": str(service_charge),
                        "transaction_id": transaction_id,
                        "source_account": source_account,
                        "type": "Withdrawal",
                        "status": "confirmed",
                    },
                    notif_type="SUCCESS",
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

            if source_account == "savings":
                user.savings = new_balance
                user.save(update_fields=["savings"])
            elif source_account == "investment":
                user.investment = new_balance
                user.save(update_fields=["investment"])
            else:
                user.wallet = new_balance
                user.save(update_fields=["wallet"])

            transaction_details.status = "pending"
            transaction_details.balance_before = previous_balance
            transaction_details.balance_after = new_balance
            transaction_details.save(
                update_fields=[
                    "status",
                    "balance_before",
                    "balance_after",
                ]
            )

            charge_percentage_display = f"{rate * 100}%" if rate > 0 else "0%"

<<<<<<< HEAD
            WithdrawalsRequestToAdmin.objects.create(
=======
            withdrawal_request = WithdrawalsRequestToAdmin.objects.create(
>>>>>>> staging
                user=user,
                amount=withdrawal_amount,
                total_amount=amount,
                charge_percentage=rate * 100,
                charge_amount=service_charge,
                transaction_id=transaction_id,
                source_account=source_account,
                target_bank=target_bank_account.bank_name,
                target_account_number=target_bank_account.account_number,
                withdrawal_type="immediate",
                is_approved=False,
            )

            _bg(
                send_push_notification,
                user=user,
                title="Withdrawal Processing... ⏳",
                message=(
                    f"Your withdrawal request of ₦{amount:,.2f} has been received. "
                    f"₦{withdrawal_amount:,.2f} will be sent to your bank account after "
                    f"₦{service_charge:,.2f} charge."
                ),
                data={
                    "amount": str(amount),
                    "net_amount": str(withdrawal_amount),
                    "charge_amount": str(service_charge),
                    "transaction_id": transaction_id,
                    "source_account": source_account,
                    "type": "Withdrawal",
                    "status": "pending_manual",
                },
                notif_type="PENDING",
            )

            _bg(
                send_generic_email,
                subject=f"Withdrawal of ₦{amount:,.2f} Processing...",
                message=(
                    f"Hi {user.first_name},<br><br>"
                    f"We've received your withdrawal request of <strong>₦{amount:,.2f}</strong>.<br><br>"
                    f"<strong>Amount to be credited to your bank account:</strong> ₦{withdrawal_amount:,.2f}<br>"
                    f"<strong>Charge deducted:</strong> ₦{service_charge:,.2f}<br>"
                    f"<strong>Bank:</strong> {target_bank_account.bank_name}<br>"
                    f"<strong>Account:</strong> {target_bank_account.account_name} - {target_bank_account.account_number}<br><br>"
                    "It'll be processed within the hour.<br><br>"
                    "Thank you for using MyFund!<br><br>"
                ),
<<<<<<< HEAD
                from_email="MyFund <info@myfundmobile.com>",
=======
                from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                recipient_list=[user.email],
            )

            _bg(
                send_generic_email,
                subject=f"[CHECK] {user.first_name} Wants to Withdraw ₦{amount:,.2f}",
                message=(
                    f"User: {user.first_name} {user.last_name}<br>"
                    f"Requested Amount: ₦{amount:,.2f}<br>"
                    f"Charge Amount: ₦{service_charge:,.2f}<br>"
                    f"Amount to Send: ₦{withdrawal_amount:,.2f}<br>"
                    f"Bank: {target_bank_account.bank_name} ({target_bank_account.account_number})<br>"
                    f"Transaction ID: {transaction_id}<br>"
                    "Reason: automatic Paystack withdrawal failed; manual processing required.<br>"
                ),
<<<<<<< HEAD
                from_email="MyFund <info@myfundmobile.com>",
                recipient_list=["admin@myfundmobile.com"],
            )

            admin_emails = [
                "tolulopeahmed@gmail.com",
                "ceo@myfundmobile.com",
                "janet.adegbenro@gmail.com",
            ]
            admin_users = CustomUser.objects.filter(email__in=admin_emails)
=======
                from_email="MyFund <info@mg.myfundmobile.com>",
                recipient_list=["admin@myfundmobile.com"],
            )

            admin_users = CustomUser.objects.filter(is_staff=True, is_active=True)
>>>>>>> staging

            admin_push_message = (
                f"{user.first_name} {user.last_name} wants to withdraw ₦{amount:,.2f} "
                f"from {source_account.capitalize()}\n"
                f"Charge: {charge_percentage_display}. Send ₦{withdrawal_amount:,.2f} to "
                f"{target_bank_account.bank_name} ({target_bank_account.account_number})"
            )

            for admin_user in admin_users:
                if (
                    hasattr(admin_user, "expo_push_tokens")
                    and admin_user.expo_push_tokens
                ):
                    _bg(
                        send_push_notification,
                        user=admin_user,
                        title="⚠️ Withdrawal Request (immediate)",
                        message=admin_push_message,
                        data={
                            "transaction_id": transaction_id,
                            "user_email": user.email,
                            "amount": str(amount),
                            "net_amount": str(withdrawal_amount),
                            "source_account": source_account,
                            "bank_name": target_bank_account.bank_name,
                            "withdrawal_type": "immediate",
                            "type": "admin_withdrawal_alert",
<<<<<<< HEAD
=======
                            **dl.admin_withdrawal(withdrawal_request.id),  # fixed
>>>>>>> staging
                        },
                        notif_type="ADMIN_ALERT",
                    )
                    print(f"✅ Admin push notification queued for {admin_user.email}")
                else:
                    print(f"⚠️ No push tokens for admin {admin_user.email}")

            return Response(
                {
                    "success": True,
                    "message": "Withdrawal submitted successfully.",
                    "transaction_id": transaction_id,
                },
                status=200,
            )

        except IntegrityError:
            return Response(
                {"error": "Transaction conflict, please retry."},
                status=400,
            )
        except Exception as e:
            print("Error in withdraw_to_local_bank:", e)
            return Response(
                {"error": "Server error, please try again later."},
                status=500,
            )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def process_withdrawal_to_local_bank(request):
    user = request.user
    data = request.data

    print("✅ STEP 1: Received withdrawal request:", data)

    source_account = data.get("source_account", "").strip().lower()
    target_bank_account_id = data.get("target_bank_account_id")
    amount = data.get("amount")
    withdrawal_type = data.get("withdrawal_type", "immediate").strip().lower()

    if not source_account:
        return Response(
            {"error": '"source_account" was NOT provided.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    VALID_SOURCES = ["savings", "investment", "wallet"]
    if source_account not in VALID_SOURCES:
        return Response(
            {"error": "Invalid source account."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    VALID_WITHDRAWAL_TYPES = ["immediate", "scheduled"]
    if withdrawal_type not in VALID_WITHDRAWAL_TYPES:
        return Response(
            {"error": "Invalid withdrawal type."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if withdrawal_type == "scheduled" and source_account == "wallet":
        return Response(
            {"error": "Wallet withdrawals cannot be scheduled."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if withdrawal_type == "immediate" and target_bank_account_id in [None, "", "null"]:
        return Response(
            {
                "error": '"target_bank_account_id" is required for immediate withdrawals.'
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        if withdrawal_type == "immediate":
            target_bank_account_id = int(target_bank_account_id)
        else:
            target_bank_account_id = None

        amount = Decimal(str(amount)).quantize(
            Decimal("0.00"), rounding=ROUND_HALF_EVEN
        )
        print("✅ STEP 2: Parsed withdrawal input successfully.")
    except (ValueError, TypeError, InvalidOperation) as e:
        print(f"❌ STEP 2 ERROR: {e}")
        return Response(
            {"error": '"amount" or "target_bank_account_id" is invalid.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if amount <= 0:
        return Response(
            {"error": "Invalid withdrawal amount."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if source_account == "savings":
        if not hasattr(user, "savings") or user.savings < amount:
            return Response(
                {"error": "Insufficient savings balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    elif source_account == "investment":
        if not hasattr(user, "investment") or user.investment < amount:
            return Response(
                {"error": "Insufficient investment balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    elif source_account == "wallet":
        if not hasattr(user, "wallet") or user.wallet < amount:
            return Response(
                {"error": "Insufficient wallet balance."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    target_bank_account = None
    if withdrawal_type == "immediate":
        try:
            target_bank_account = BankAccount.objects.get(
                id=target_bank_account_id,
                user=user,
            )
            print("✅ STEP 3: Target bank account validated.")
        except BankAccount.DoesNotExist:
            return Response(
                {"error": "Target bank account not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    else:
        print("✅ STEP 3: Scheduled withdrawal selected. No bank account required.")

    transaction_id = "".join(
        random.choices(string.ascii_uppercase + string.digits, k=20)
    )
    print("✅ STEP 4: Generated transaction_id")

    current_datetime = datetime.now()
    processing_date = None
    if withdrawal_type == "scheduled":
        if source_account == "savings":
            processing_date = current_datetime + timedelta(days=30)
        elif source_account == "investment":
            processing_date = current_datetime + timedelta(days=90)

    try:
        with transaction.atomic():
            from .utils import calculate_withdrawal_charges

            if withdrawal_type == "scheduled":
                rate = Decimal("0.00")
                charge_amount = Decimal("0.00")
                net_amount = amount
            else:
                rate, charge_amount, net_amount = calculate_withdrawal_charges(
                    amount,
                    source_account,
                )

            user_locked = type(user).objects.select_for_update().get(id=user.id)

            if source_account == "savings":
                if not hasattr(user_locked, "savings") or user_locked.savings < amount:
                    return Response(
                        {"error": "Insufficient savings balance."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                previous_balance = user_locked.savings
                new_balance = user_locked.savings - amount
                source_choice = "SAVINGS"

            elif source_account == "investment":
                if (
                    not hasattr(user_locked, "investment")
                    or user_locked.investment < amount
                ):
                    return Response(
                        {"error": "Insufficient investment balance."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                previous_balance = user_locked.investment
                new_balance = user_locked.investment - amount
                source_choice = "INVESTMENT"

            elif source_account == "wallet":
                if not hasattr(user_locked, "wallet") or user_locked.wallet < amount:
                    return Response(
                        {"error": "Insufficient wallet balance."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                previous_balance = user_locked.wallet
                new_balance = user_locked.wallet - amount
                source_choice = "WALLET"

            else:
                return Response(
                    {"error": "Invalid source account."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if source_account == "savings":
                user_locked.savings = new_balance
                user_locked.save(update_fields=["savings"])
            elif source_account == "investment":
                user_locked.investment = new_balance
                user_locked.save(update_fields=["investment"])
            else:
                user_locked.wallet = new_balance
                user_locked.save(update_fields=["wallet"])

            print(
                f"✅ STEP 5: Amount {amount} deducted from user's {source_account} balance."
            )
            print(
                f"✅ Charge Rate: {rate * 100}%, Charge Amount: ₦{charge_amount}, Net Amount: ₦{net_amount}"
            )

            withdrawal = WithdrawalsRequestToAdmin.objects.create(
                user=user_locked,
                amount=net_amount,
                charge_percentage=rate * 100,
                charge_amount=charge_amount,
                total_amount=amount,
                transaction_id=transaction_id,
                source_account=source_account,
                target_bank=(
                    target_bank_account.bank_name if target_bank_account else ""
                ),
                target_account_number=(
                    target_bank_account.account_number if target_bank_account else ""
                ),
                withdrawal_type=withdrawal_type,
                scheduled_processing_date=(
                    processing_date.date() if processing_date else None
                ),
                is_approved=False,
            )

            print("✅ STEP 6: Withdrawal record created.")

            Transaction.objects.create(
                user=user_locked,
                transaction_id=transaction_id,
                transaction_type="debit",
                status="pending",
                amount=amount,
                service_charge=charge_amount,
                total_amount=amount,
                source=source_choice,
                balance_before=previous_balance,
                balance_after=new_balance,
                description=(
                    f"{source_account.capitalize()} > Wallet . . ."
                    if withdrawal_type == "scheduled"
                    else f"{source_account.capitalize()} > Bank . . ."
                ),
                scheduled_date=processing_date.date() if processing_date else None,
            )
            print("✅ STEP 7: Transaction record created.")

        charge_percentage_display = f"{rate * 100}%" if rate > 0 else "0%"

        if withdrawal_type == "scheduled" and processing_date:
            user_message_body = (
                f"Your withdrawal has been successfully scheduled.<br><br>"
                f"<strong>Requested Amount:</strong> ₦{amount:,.2f}<br>"
                f"<strong>No charges apply</strong> to scheduled withdrawals.<br><br>"
                f"The funds will be automatically credited to your MyFund wallet on "
                f"<strong>{processing_date.strftime('%A, %B %d, %Y')}</strong>.<br><br>"
                f"You do not need to add a bank account for a scheduled withdrawal. "
                f"When the due date arrives, the money will first land in your wallet."
            )
        elif withdrawal_type == "immediate" and source_account == "wallet":
            user_message_body = (
                f"Your withdrawal request of <strong>₦{amount:,.2f}</strong> from your Wallet to "
                f"{target_bank_account.bank_name} "
                f"({target_bank_account.account_name} - {target_bank_account.account_number}) "
                f"has been successfully submitted.<br><br>"
                f"<strong>Amount to be credited to your bank account:</strong> ₦{net_amount:,.2f}<br>"
                f"<strong>Charge deducted:</strong> ₦{charge_amount:,.2f}<br><br>"
                f"The funds will be processed to your bank account shortly."
            )
        elif withdrawal_type == "immediate":
            user_message_body = (
                f"Your immediate withdrawal request of <strong>₦{amount:,.2f}</strong> from your "
                f"{source_account.capitalize()} account to "
                f"{target_bank_account.bank_name} "
                f"({target_bank_account.account_name} - {target_bank_account.account_number}) "
                f"has been successfully submitted and will be processed shortly.<br><br>"
                f"<strong>Amount to be credited to your bank account:</strong> ₦{net_amount:,.2f}<br>"
                f"<strong>Charge deducted:</strong> ₦{charge_amount:,.2f}"
            )
        else:
            user_message_body = f"Your withdrawal request of ₦{amount:,.2f} has been received successfully."

        _bg(
            send_generic_email,
            subject="Withdrawal Request Received",
            message=(
                f"Hi {user_locked.first_name},<br><br>"
                f"{user_message_body}<br><br>"
                "Thank you for using MyFund.<br><br>"
            ),
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[user_locked.email],
        )

        if withdrawal_type == "scheduled" and processing_date:
            push_title = "Withdrawal Scheduled 📅"
            push_message = (
                f"Hi {user_locked.first_name}, your withdrawal of ₦{amount:,.2f} has been scheduled successfully. "
                f"No charges apply. Your wallet will be credited on "
                f"{processing_date.strftime('%A, %B %d, %Y')}."
            )
            notif_status = "scheduled"
            notif_type_name = "SCHEDULED"

        elif withdrawal_type == "immediate" and source_account == "wallet":
            push_title = "Withdrawal Submitted 💸"
            push_message = (
                f"Your withdrawal request of ₦{amount:,.2f} has been submitted successfully. "
                f"₦{net_amount:,.2f} will be credited to your bank account after "
                f"₦{charge_amount:,.2f} charge."
            )
            notif_status = "pending"
            notif_type_name = "PENDING"

        elif withdrawal_type == "immediate":
            push_title = "Withdrawal Request Received ⏳"
            push_message = (
                f"Your withdrawal request of ₦{amount:,.2f} from your {source_account.capitalize()} "
                f"account has been received. ₦{net_amount:,.2f} will be credited to your bank account "
                f"after ₦{charge_amount:,.2f} charge."
            )
            notif_status = "pending"
            notif_type_name = "PENDING"

        else:
            push_title = "Withdrawal Update"
            push_message = (
                f"Your withdrawal request of ₦{amount:,.2f} has been received."
            )
            notif_status = "pending"
            notif_type_name = "INFO"

        _bg(
            send_push_notification,
            user=user_locked,
            title=push_title,
            message=push_message,
            data={
                "total_amount": str(amount),
                "charge_percentage": str(rate * 100),
                "charge_amount": str(charge_amount),
                "net_amount": str(net_amount),
                "transaction_id": transaction_id,
                "source_account": source_account,
                "type": "Withdrawal",
                "status": notif_status,
                "processing_date": (
                    processing_date.strftime("%Y-%m-%d") if processing_date else None
                ),
            },
            notif_type=notif_type_name,
        )
        print("✅ STEP 8: User push notification queued.")

        admin_message = f"""
        Hi Admin,<br><br>
        A new withdrawal request has been submitted. The user's account has already been debited.
        Please review and process the request.<br><br>

        User: {user_locked.first_name} {user_locked.last_name}<br>
        Email: {user_locked.email}<br>
        Transaction ID: {transaction_id}<br><br>

        💰 CHARGE DETAILS:<br>
        • Requested Amount: ₦{amount:,.2f}<br>
        • Source Account: {source_account.capitalize()}<br>
        • Charge Rate: {charge_percentage_display}<br>
        • Charge Amount: ₦{charge_amount:,.2f}<br>
        • Amount to Send: ₦{net_amount:,.2f}<br><br>

        📋 REQUEST DETAILS:<br>
        • Withdrawal Type: {withdrawal_type.capitalize()}<br>
        • Request Date: {withdrawal.created_at.strftime('%Y-%m-%d %H:%M:%S')}<br>
        """

        if withdrawal_type == "scheduled" and processing_date:
            admin_message += (
                f"• Scheduled Processing Date: "
                f"{processing_date.strftime('%A, %B %d, %Y')}<br>"
                f"<br>⚠️ This is a scheduled withdrawal. No bank transfer is required now. "
                f"Funds should be credited to the user's wallet on the due date."
            )
        else:
            admin_message += f"""
            🏦 BANK DETAILS:<br>
            • Target Bank: {target_bank_account.bank_name}<br>
            • Account Name: {target_bank_account.account_name}<br>
            • Account Number: {target_bank_account.account_number}<br><br>

            ⚠️ Please send exactly ₦{net_amount:,.2f} to the bank account above.
            """

        _bg(
            send_generic_email,
            subject=f"[CHECK] {user_locked.first_name} Wants to Withdraw ₦{amount:,.2f} ({withdrawal_type.capitalize()})",
            message=admin_message,
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[
                "company@myfundmobile.com",
                "tolulopeahmed@gmail.com",
                "janet.adegbenro@gmail.com",
            ],
        )

<<<<<<< HEAD
        admin_emails = [
            "tolulopeahmed@gmail.com",
            "ceo@myfundmobile.com",
            "janet.adegbenro@gmail.com",
        ]
        admin_users = CustomUser.objects.filter(email__in=admin_emails)
=======
        admin_users = CustomUser.objects.filter(is_staff=True, is_active=True)
>>>>>>> staging

        for admin_user in admin_users:
            if hasattr(admin_user, "expo_push_tokens") and admin_user.expo_push_tokens:
                admin_push_message = (
                    f"{user_locked.first_name} {user_locked.last_name} wants to withdraw "
                    f"₦{amount:,.2f} from {source_account.capitalize()}.\n"
                )

                if withdrawal_type == "scheduled" and processing_date:
                    admin_push_message += (
                        f"Scheduled for {processing_date.strftime('%A, %B %d, %Y')}. "
                        f"Credit to wallet on due date."
                    )
                else:
                    admin_push_message += (
                        f"Charge: {charge_percentage_display}. Send ₦{net_amount:,.2f} to "
                        f"{target_bank_account.account_name} ({target_bank_account.account_number})."
                    )

                _bg(
                    send_push_notification,
                    user=admin_user,
                    title=(
                        f"⚠️ Withdrawal Request ({withdrawal_type})"
                        if withdrawal_type == "immediate"
                        else "📅 Scheduled Withdrawal"
                    ),
                    message=admin_push_message,
                    data={
                        "transaction_id": transaction_id,
                        "user_email": user_locked.email,
                        "amount": str(amount),
                        "net_amount": str(net_amount),
                        "source_account": source_account,
                        "bank_name": (
                            target_bank_account.bank_name if target_bank_account else ""
                        ),
                        "withdrawal_type": withdrawal_type,
                        "type": "admin_withdrawal_alert",
                    },
                    notif_type="ADMIN_ALERT",
                )
                print(f"✅ Admin push notification queued for {admin_user.email}")
            else:
                print(f"⚠️ No push tokens for admin {admin_user.email}")

        return Response(
            {
                "message": (
                    f"Withdrawal scheduled successfully. ₦{amount:,.2f} will be credited to your wallet on "
                    f"{processing_date.strftime('%A, %B %d, %Y')}."
                    if withdrawal_type == "scheduled" and processing_date
                    else f"Withdrawal successful. Requested amount: ₦{amount:,.2f}. Amount to be credited to bank: ₦{net_amount:,.2f}."
                ),
                "transaction_id": transaction_id,
                "scheduled_date": (
                    processing_date.strftime("%Y-%m-%d") if processing_date else None
                ),
                "charge_details": {
                    "charge_percentage": f"{rate * 100}%",
                    "charge_amount": float(charge_amount),
                    "net_amount": float(net_amount),
                    "total_amount": float(amount),
                },
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        print("❌ Exception during withdrawal processing.")
        print(f"❌ ERROR: {str(e)}")
        import traceback

        traceback.print_exc()
        return Response(
            {"error": f"An error occurred while processing your request: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def cancel_scheduled_withdrawal(request):
    user = request.user
    transaction_id = request.data.get("transaction_id")

    if not transaction_id:
        return Response(
            {"error": "Transaction ID is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
            # 1) Lock pending transaction
            pending_transaction = Transaction.objects.select_for_update().get(
                transaction_id=transaction_id,
                user=user,
                status="pending",
            )

            if not pending_transaction.scheduled_date:
                return Response(
                    {"error": "This is not a scheduled withdrawal."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_locked = type(user).objects.select_for_update().get(id=user.id)

            # 2) Calculate refund + charge
            original_amount = (
                pending_transaction.total_amount or pending_transaction.amount
            )

            refund_amount = (original_amount * Decimal("0.99")).quantize(
                Decimal("0.01")
            )
            service_charge = (original_amount - refund_amount).quantize(Decimal("0.01"))

            # 3) Cancel withdrawal request
            withdrawal_request = (
                WithdrawalsRequestToAdmin.objects.select_for_update()
                .filter(
                    transaction_id=transaction_id,
                    user=user,
                    withdrawal_type="scheduled",
                    is_approved=False,
                )
                .first()
            )

            if withdrawal_request:
<<<<<<< HEAD
                if hasattr(withdrawal_request, "is_cancelled"):
                    withdrawal_request.is_cancelled = True
                    withdrawal_request.save(update_fields=["is_cancelled"])
                elif hasattr(withdrawal_request, "status"):
                    withdrawal_request.status = "cancelled"
                    withdrawal_request.save(update_fields=["status"])
                else:
                    withdrawal_request.is_approved = True
                    withdrawal_request.save(update_fields=["is_approved"])
=======
                # 🔴 CRITICAL: must also set is_processed=True here. The
                # automated Celery task and the "Force credit wallet" admin
                # action both select on `is_processed=False` (and don't
                # look at `status` at all) to decide what's still due for
                # automated crediting. Without this, a cancelled-and-
                # refunded withdrawal was still "scheduled" with
                # is_processed still False, so once its
                # scheduled_processing_date arrived it got auto-credited to
                # user.wallet a second time - on top of the 99% refund
                # already paid into savings here. Also clearing
                # scheduled_processing_date so it can never match that
                # "due" query at all, belt-and-suspenders.
                withdrawal_request.is_processed = True
                withdrawal_request.scheduled_processing_date = None
                update_fields = ["is_processed", "scheduled_processing_date"]
                if hasattr(withdrawal_request, "is_cancelled"):
                    withdrawal_request.is_cancelled = True
                    update_fields.append("is_cancelled")
                if hasattr(withdrawal_request, "status"):
                    withdrawal_request.status = "cancelled"
                    update_fields.append("status")
                withdrawal_request.save(update_fields=update_fields)
>>>>>>> staging

            # 4) Delete pending transaction
            pending_transaction.delete()

            # 5) SINGLE ledger transaction (correct way)
            refund_transaction_id = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )

            refund_tx = create_transaction(
                user=user_locked,
                amount=refund_amount,  # what user actually gets
                transaction_type="credit",
                status="confirmed",
                credited_to="SAVINGS",
                description="Cancelled Withdrawal",
                service_charge=service_charge,  # 👈 important
                reference=refund_transaction_id,
            )

            # refresh balance
            user_locked.refresh_from_db(fields=["savings"])

            # 6) Notify user
            subject = "Scheduled Withdrawal Cancelled"
            user_message = (
                f"Hi {user_locked.first_name},<br><br>"
                f"Your scheduled withdrawal of ₦{original_amount:,.2f} has been cancelled.<br>"
                f"₦{refund_amount:,.2f} has been refunded to your Savings account "
                f"(₦{service_charge:,.2f} service charge applied).<br><br>"
                f"Thank you for using MyFund."
            )

            send_generic_email(
                subject=subject,
                message=user_message,
<<<<<<< HEAD
                from_email="MyFund <info@myfundmobile.com>",
=======
                from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                recipient_list=[user_locked.email],
            )

            send_push_notification(
                user=user_locked,
                title="Scheduled Withdrawal Cancelled ✅",
                message=(
                    f"₦{refund_amount:,.2f} refunded to your Savings "
                    f"(₦{service_charge:,.2f} charge applied)."
                ),
                data={
                    "refund_amount": str(refund_amount),
                    "original_amount": str(original_amount),
                    "service_charge": str(service_charge),
                    "transaction_id": refund_tx.transaction_id,
                    "type": "Withdrawal_Cancellation",
                    "status": "completed",
                },
                notif_type="SUCCESS",
            )

        return Response(
            {
                "message": "Scheduled withdrawal cancelled successfully.",
                "refund_amount": float(refund_amount),
                "service_charge": float(service_charge),
                "original_amount": float(original_amount),
                "new_savings_balance": float(user_locked.savings),
            },
            status=status.HTTP_200_OK,
        )

    except Transaction.DoesNotExist:
        return Response(
            {"error": "Scheduled withdrawal not found or already processed."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except Exception as e:
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
<<<<<<< HEAD
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@myfundmobile.com",
=======
        from_email = "MyFund <info@mg.myfundmobile.com>"
        recipient_list = [
            "company@myfundmobile.com",
            "info@mg.myfundmobile.com",
>>>>>>> staging
            "cto@myfundmobile.com",
        ]

        send_generic_email(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
        )

        # Send a pending quicksave email to the user
        user_subject = "Withdrawal Pending..."
        user_message = f"Hi {user.first_name},<br><br>Your withdrawal of ₦{amount} is pending approval. We will notify you once it's processed. <br><br>Thank you for using MyFund."
        user_email = [user.email]

        send_generic_email(
            subject=user_subject,
            message=user_message,
            from_email=from_email,
            recipient_list=user_email,
        )

        return {"message": "Withdrawal request created and pending admin approval"}

    except Exception as e:
        # print error
        print(f"\n(Error) make_withdrawal_through_admin():  {e}\n")


<<<<<<< HEAD
from decimal import Decimal

from decimal import Decimal, InvalidOperation
from django.core.mail import send_mail
=======
from decimal import Decimal, InvalidOperation
import uuid

from django.db import transaction as db_transaction
>>>>>>> staging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
<<<<<<< HEAD
import uuid
=======

from authentication.models import CustomUser
from authentication.utils import (
    create_transaction,
    send_generic_email,
    send_push_notification,
)
>>>>>>> staging


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def wallet_transfer_view(request):
<<<<<<< HEAD
    from .utils import create_transaction

    sender = request.user
    data = request.data
    target_email = data.get("recipient_email")
=======
    sender = request.user
    data = request.data

    target_email = (data.get("recipient_email") or "").strip().lower()

    if not target_email:
        return Response(
            {"error": "Recipient email is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if sender.email.lower() == target_email:
        return Response(
            {"error": "You cannot send money to yourself."},
            status=status.HTTP_400_BAD_REQUEST,
        )
>>>>>>> staging

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

<<<<<<< HEAD
    # Check sender balance
    if sender.wallet < amount:
=======
    sender_wallet = Decimal(str(sender.wallet or 0))

    if sender_wallet < amount:
>>>>>>> staging
        return Response(
            {"error": "Insufficient balance in the wallet."},
            status=status.HTTP_400_BAD_REQUEST,
        )

<<<<<<< HEAD
    # Find recipient
    try:
        target_user = CustomUser.objects.get(email=target_email)
=======
    try:
        target_user = CustomUser.objects.get(email__iexact=target_email)
>>>>>>> staging
    except CustomUser.DoesNotExist:
        return Response(
            {"error": "Target user not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

<<<<<<< HEAD
    # 🔥 SINGLE TRANSACTION BLOCK (atomic consistency)
    with transaction.atomic():
=======
    # 🔥 FIX: generate transaction reference (THIS was your error)
    transfer_reference = f"WALLET-{uuid.uuid4().hex[:12].upper()}"

    with db_transaction.atomic():
>>>>>>> staging
        # debit sender
        create_transaction(
            user=sender,
            amount=amount,
            transaction_type="debit",
            source="WALLET",
<<<<<<< HEAD
            description=f"Sent to {target_user.first_name}",
=======
            description=f"Sent to {target_user.first_name or target_user.email}",
            reference=f"{transfer_reference}-D",
>>>>>>> staging
        )

        # credit receiver
        create_transaction(
            user=target_user,
            amount=amount,
            transaction_type="credit",
            credited_to="WALLET",
<<<<<<< HEAD
            description=f"Received from {sender.first_name}",
        )

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

    # Email to sender
    send_generic_email(
        subject=f"You Sent ₦{amount} to {target_user.first_name}",
        message=(
            f"Hi {sender.first_name},<br><br>"
            f"You have successfully transferred ₦{amount} to {target_user.first_name} ({target_user.email}).<br><br>"
            f"Thank you for using MyFund!"
        ),
        from_email="MyFund <info@myfundmobile.com>",
        recipient_list=[sender.email],
    )

    # Email to receiver
    send_generic_email(
        subject=f"You Received ₦{amount} from {sender.first_name}",
        message=(
            f"Hi {target_user.first_name},<br><br>"
            f"You have received ₦{amount} from {sender.first_name} ({sender.email}).<br><br>"
            f"Thank you for using MyFund!"
        ),
        from_email="MyFund <info@myfundmobile.com>",
        recipient_list=[target_user.email],
    )

    return Response({"success": True})
=======
            description=f"Received from {sender.first_name or sender.email}",
            reference=f"{transfer_reference}-C",
        )

    # Push notifications
    try:
        send_push_notification(
            user=target_user,
            title=f"You've Received ₦{amount:,.2f}",
            message=f"{sender.first_name or 'Someone'} just sent you ₦{amount:,.2f}. Check your Wallet.",
            data={"amount": str(amount), "from": sender.email},
            notif_type="CREDIT",
        )
    except Exception:
        pass

    try:
        send_push_notification(
            user=sender,
            title=f"You Sent ₦{amount:,.2f}",
            message=f"You successfully sent ₦{amount:,.2f} to {target_user.first_name or target_user.email}.",
            data={"amount": str(amount), "to": target_user.email},
            notif_type="DEBIT",
        )
    except Exception:
        pass

    # Emails
    send_generic_email(
        subject=f"You Sent ₦{amount:,.2f} to {target_user.first_name or target_user.email}",
        message=(
            f"Hi {sender.first_name or 'there'},<br><br>"
            f"You have successfully transferred ₦{amount:,.2f} to "
            f"{target_user.first_name or target_user.email} ({target_user.email}).<br><br>"
            f"Thank you for using MyFund!"
        ),
        recipient_list=[sender.email],
    )

    send_generic_email(
        subject=f"You Received ₦{amount:,.2f} from {sender.first_name or 'a MyFund user'}",
        message=(
            f"Hi {target_user.first_name or 'there'},<br><br>"
            f"You have received ₦{amount:,.2f} from "
            f"{sender.first_name or sender.email} ({sender.email}).<br><br>"
            f"Thank you for using MyFund!"
        ),
        recipient_list=[target_user.email],
    )

    return Response(
        {
            "success": True,
            "message": "Wallet transfer successful.",
        },
        status=status.HTTP_200_OK,
    )
>>>>>>> staging


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
<<<<<<< HEAD
    # from_email = "MyFund <info@myfundmobile.com>"
=======
    # from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
    # recipient_list = [user.email]

    # send_generic_email(subject=subject, message=message, from_email=from_email, recipient_list=recipient_list)


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
<<<<<<< HEAD
            from_email = "MyFund <info@myfundmobile.com>"
=======
            from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
            recipient_list = [user.email]

            send_generic_email(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
            )

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
<<<<<<< HEAD
                    from_email = "MyFund <info@myfundmobile.com>"
=======
                    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                    recipient_list = [user.email]

                    send_generic_email(
                        subject=subject,
                        message=message,
                        from_email=from_email,
                        recipient_list=recipient_list,
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
            subject=subject,
            message=email_message,
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[user.email],
        )


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from django.core.cache import cache


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_top_savers(request):
    now = timezone.now()
    current_month = now.month
    current_year = now.year

    cache_key = f"top_savers_update_{current_year}_{current_month}"
    lock_key = f"top_savers_lock_{current_year}_{current_month}"

    is_updating = cache.get(lock_key)
    last_update = cache.get(cache_key)

    logger.info(
        "get_top_savers called | month=%s year=%s last_update=%s is_updating=%s user=%s",
        current_month,
        current_year,
        last_update,
        bool(is_updating),
        request.user.email,
    )

    if not last_update and not is_updating:
        cache.set(lock_key, True, timeout=60)

        logger.info(
            "No cached top savers data found. Starting background update for %s/%s",
            current_month,
            current_year,
        )

        update_top_savers()
        cache.set(cache_key, now.isoformat(), timeout=180)

        logger.info("Started background top savers update")

    else:
        logger.info(
            "Skipping background top savers update | reason=%s",
            "already_updating" if is_updating else "cached_recent_data_exists",
        )

    top_savers = (
        TopSaverHistory.objects.filter(month=current_month, year=current_year)
        .select_related("user")
        .order_by("rank")[:50]
    )

    logger.info(
        "Fetched %s TopSaverHistory rows for %s/%s",
        len(top_savers),
        current_month,
        current_year,
    )

    if not top_savers:
        logger.warning(
            "No TopSaverHistory rows found for %s/%s",
            current_month,
            current_year,
        )
        return Response(
            {
                "top_savers": [],
                "current_user": {},
                "updating": bool(is_updating),
            }
        )

    top_amount = top_savers[0].total_savings or 1
    current_user_history = next(
        (tsh for tsh in top_savers if tsh.user_id == request.user.id), None
    )

    current_percentage = (
        round((current_user_history.total_savings / top_amount) * 100, 1)
        if current_user_history
        else 0
    )

    logger.info(
        "Returning top savers response | top_amount=%s current_user_in_board=%s current_user_percentage=%s",
        top_amount,
        bool(current_user_history),
        current_percentage,
    )

    return Response(
        {
            "top_savers": [
                {
                    "id": tsh.user.id,
                    "first_name": tsh.user.first_name or "",
                    "email": tsh.user.email or "",
                    "profile_picture": tsh.user.profile_picture or "",
                    "amount": float(tsh.total_savings),
                    "percentage": (
                        round((tsh.total_savings / top_amount) * 100, 1)
                        if top_amount > 0
                        else 0
                    ),
                    "rank": tsh.rank,
                }
                for tsh in top_savers
            ],
            "current_user": {
                "id": request.user.id,
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
                "email": request.user.email,
                "profile_picture": getattr(request.user.profile_picture, "url", ""),
                "percentage": current_percentage,
            },
            "updating": bool(is_updating),
            "last_update": last_update,
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
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # If not yet approved, mark as pending and notify user by email
        # Mark KYC as submitted (pending review)
        if user.kyc_status != "approved":
            user.kyc_status = "submitted"
            user.kyc_updated = False
            user.save(update_fields=["kyc_status", "kyc_updated"])

            # 1️⃣ Email to user
            user_subject = "KYC Update Received... 🕒"
            user_message = (
                f"Hi {user.first_name},<br><br>"
                "We’ve received your updated KYC details. "
                "Our team will review them shortly, and we’ll let you know once it’s approved.<br><br>"
                "Thank you for using MyFund.<br><br>"
            )
<<<<<<< HEAD
            from_email = "MyFund <info@myfundmobile.com>"
=======
            from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
            recipient_list = [user.email]

            send_generic_email(
                subject=user_subject,
                message=user_message,
                from_email=from_email,
                recipient_list=recipient_list,
            )

        # 2️⃣ Push notification to user
        send_push_notification(
            user=user,
            title="KYC Update Submitted... 🕒",
            message="Thanks for updating your KYC details. We’ll notify you once it’s approved. Thank you for using MyFund.",
            data={"kyc_status": user.kyc_status},
            notif_type="SYSTEM",
        )

        # 3️⃣ Notify admin
<<<<<<< HEAD
        admin_email = ["info@myfundmobile.com", "company@myfundmobile.com"]
=======
        admin_email = ["info@mg.myfundmobile.com", "company@myfundmobile.com"]
>>>>>>> staging
        admin_subject = f"KYC Update for {user.first_name} Pending Approval"
        admin_message = (
            f"Hello Admin,<br><br>"
            f"{user.first_name} {user.last_name} ({user.email}) has submitted a KYC update. "
            "Please review it in the admin panel:<br>"
            "https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/.<br><br>"
        )
        send_generic_email(
            subject=admin_subject,
            message=admin_message,
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=admin_email,
        )

        # 4️⃣ Push notification to admin (KYC alert)
<<<<<<< HEAD
        admin_emails = [
            "tolulopeahmed@gmail.com",
            "ceo@myfundmobile.com",
            "janet.adegbenro@gmail.com",
        ]

        admin_users = CustomUser.objects.filter(email__in=admin_emails)
=======
        admin_users = CustomUser.objects.filter(is_staff=True, is_active=True)
>>>>>>> staging

        for admin_user in admin_users:
            if hasattr(admin_user, "expo_push_tokens") and admin_user.expo_push_tokens:
                send_push_notification(
                    user=admin_user,
                    title=f"🪪 {user.first_name} Submitted KYC",
                    message=(
                        f"{user.first_name} {user.last_name} has submitted KYC details.\n"
                        f"Please check Django admin to review."
                    ),
                    data={
                        "user_email": user.email,
                        "kyc_status": "pending",
                        "type": "admin_kyc_alert",
                    },
                    notif_type="ADMIN_ALERT",
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
        elif kyc_status == "submitted":
            message = "Your KYC is pending review."
        elif kyc_status == "approved":
            message = "Your KYC has been approved."
        elif kyc_status == "rejected":
            message = "Your KYC was rejected."

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


import threading
<<<<<<< HEAD
=======
from .push_deep_links import dl
>>>>>>> staging


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_bank_transfer(request):
    transaction_id = None

    try:
        user = request.user
        amount_raw = request.data.get("amount")

        # Validate and convert amount to Decimal
        if not amount_raw:
            return Response(
                {"error": "Amount is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            amount = Decimal(str(amount_raw))
        except (InvalidOperation, ValueError, TypeError):
            return Response(
                {"error": "Invalid amount format. Please enter a valid number."},
                status=status.HTTP_400_BAD_REQUEST,
            )

<<<<<<< HEAD
        if amount < 100:
            return Response(
                {"error": "Amount must be greater than ₦100"},
=======
        if amount < 500:
            return Response(
                {"error": "Amount must be greater than ₦500"},
>>>>>>> staging
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Generate a unique transaction ID
        transaction_id = str(uuid.uuid4())[:10]

        # Create a BankTransferRequest record
        bank_transfer_request = BankTransferRequest.objects.create(
            user=user,
            amount=amount,
            transaction_id=transaction_id,
        )

        # Create a pending transaction for the user
        current_datetime = timezone.now()
        referral_email = user.referral.email if user.referral else None

        transaction = Transaction.objects.create(
            user=user,
            referral_email=referral_email,
            transaction_type="credit",
            status="pending",
            amount=amount,
            description="QuickSave . . .",
<<<<<<< HEAD
=======
            source_channel="BANK_TRANSFER",
>>>>>>> staging
            transaction_id=transaction_id,
            balance_before=user.savings,
            balance_after=user.savings + amount,
        )

        # Return immediately after DB saves
        response = Response(
            {
                "message": "Bank transfer request created and pending admin approval",
                "amount": str(amount),
                "transaction_id": transaction_id,
            },
            status=status.HTTP_201_CREATED,
        )

        # Notifications in background thread
        def background_tasks():
            try:
                # 1. Push notification to user
                send_push_notification(
                    user=user,
                    title="QuickSave Pending ⏳",
                    message=(
                        "Your transfer of ₦{:,.2f} is pending approval. "
                        "We'll notify you once it's confirmed. "
                        "Thank you for using MyFund."
                    ).format(float(amount)),
                    data={
                        "amount": str(amount),
                        "transaction_id": transaction_id,
                        "type": "QuickSave",
                        "status": "pending",
                    },
                    notif_type="PENDING",
                )

                # 2. Email to user
                user_subject = "QuickSave Pending..."
                user_message = (
                    f"Hi {user.first_name},<br><br>"
                    f"Your bank transfer request of ₦{amount} is pending approval. "
                    f"We'll notify you once it's processed.<br><br>"
                    f"Thank you for using MyFund.<br><br>"
                )

                send_generic_email(
                    subject=user_subject,
                    message=user_message,
<<<<<<< HEAD
                    from_email="info@myfundmobile.com",
=======
                    from_email="info@mg.myfundmobile.com",
>>>>>>> staging
                    recipient_list=[user.email],
                    use_celery_threshold=30,
                    template="email/email.html",
                )

                # 3. Email to admin
                admin_subject = f"[CHECK] {user.first_name} Made A QuickSave Request"
                admin_message = (
                    f"Hi Admin,<br><br>"
                    f"A bank transfer request of ₦{amount} has been initiated by "
                    f"{user.first_name} {user.last_name} ({user.email}).<br><br>"
                    f"Review here: "
                    f"https://myfundapi-myfund-07ce351a.koyeb.app/admin/<br><br>"
                    f"MyFund Team"
                )

                send_generic_email(
                    subject=admin_subject,
                    message=admin_message,
<<<<<<< HEAD
                    from_email="info@myfundmobile.com",
                    recipient_list=[
                        "company@myfundmobile.com",
                        "info@myfundmobile.com",
=======
                    from_email="info@mg.myfundmobile.com",
                    recipient_list=[
                        "company@myfundmobile.com",
                        "info@mg.myfundmobile.com",
>>>>>>> staging
                    ],
                    use_celery_threshold=30,
                    template="email/email.html",
                )

                # 4. Push notification to admins
<<<<<<< HEAD
                admin_emails = [
                    "tolulopeahmed@gmail.com",
                    "ceo@myfundmobile.com",
                    "janet.adegbenro@gmail.com",
                ]
                admin_users = CustomUser.objects.filter(email__in=admin_emails)
=======
                admin_users = CustomUser.objects.filter(is_staff=True, is_active=True)
>>>>>>> staging

                for admin_user in admin_users:
                    if (
                        hasattr(admin_user, "expo_push_tokens")
                        and admin_user.expo_push_tokens
                    ):
                        admin_push_title = (
                            f"{user.first_name} initiated a New QuickSave"
                        )
                        admin_push_message = (
                            f"{user.first_name} {user.last_name} ({user.email}) "
                            f"has initiated ₦{amount:,.2f} to Savings Account.\n"
                            f"Please check to confirm."
                        )

                        send_push_notification(
                            user=admin_user,
                            title=admin_push_title,
                            message=admin_push_message,
                            data={
<<<<<<< HEAD
                                "transaction_id": transaction_id,
                                "user_email": user.email,
                                "amount": str(amount),
                                "type": "QuickSave",
                                "status": "pending",
                                "source": "admin_quicksave_alert",
                            },
                            notif_type="ADMIN_ALERT",
=======
                                "type": "admin_bank_transfer",
                                "transaction_id": transaction_id,
                                **dl.admin_bank_transfer(transaction_id),  # ← add this
                            },
                            notif_type="ADMIN",
>>>>>>> staging
                        )
                        print(
                            f"✅ Admin QuickSave push notification sent to {admin_user.email}"
                        )
                    else:
                        print(f"⚠️ No push tokens for admin {admin_user.email}")

            except Exception as e:
                print(f"Background task error: {e}")

        threading.Thread(target=background_tasks, daemon=True).start()

        return response

    except Exception as e:
        return Response(
            {"error": str(e), "transaction_id": transaction_id},
            status=status.HTTP_400_BAD_REQUEST,
        )


import threading
from decimal import Decimal, InvalidOperation
from uuid import uuid4
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CustomUser, Transaction, InvestTransferRequest
from .utils import send_push_notification, send_generic_email


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_invest_transfer(request):
    transaction_id = None

    try:
        user = request.user
        amount_raw = request.data.get("amount")

        # Validate input
        if not amount_raw:
            return Response(
                {"error": "Amount is required"},
                status=400,
            )

        try:
            amount = Decimal(str(amount_raw))
<<<<<<< HEAD
=======
            if amount < 100000:
                return Response(
                    {"error": "Amount must at least ₦100,000"},
                    status=400,
                )
>>>>>>> staging
        except (InvalidOperation, ValueError, TypeError):
            return Response(
                {"error": "Invalid amount format"},
                status=400,
            )

<<<<<<< HEAD
        # Minimum investment validation
        if amount < MINIMUM_INVESTMENT:
            return Response(
                {
                    "error": "Minimum investment amount is ₦100,000."
                },
                status=400,
            )

=======
>>>>>>> staging
        # Generate transaction ID
        transaction_id = str(uuid4())[:10]

        # Create InvestTransferRequest
        InvestTransferRequest.objects.create(
            user=user,
            amount=amount,
            transaction_id=transaction_id,
        )

        # Create Transaction record
<<<<<<< HEAD
=======
        current_datetime = timezone.now()
>>>>>>> staging
        referral_email = user.referral.email if user.referral else None

        Transaction.objects.create(
            user=user,
            referral_email=referral_email,
            transaction_type="credit",
            status="pending",
            amount=amount,
            description="QuickInvest . . .",
            transaction_id=transaction_id,
            balance_before=user.investment,
            balance_after=user.investment + amount,
<<<<<<< HEAD
=======
            source_channel="BANK_TRANSFER",
>>>>>>> staging
        )

        # 🔔 USER PUSH
        send_push_notification(
            user=user,
            title="QuickInvest Pending ⏳",
            message=f"Your investment of ₦{amount:,.2f} is pending approval.",
            data={
                "transaction_id": transaction_id,
                "amount": str(amount),
                "type": "QuickInvest",
                "status": "pending",
            },
            notif_type="PENDING",
        )

        # 📧 USER EMAIL — THREADING
        user_subject = "QuickInvest Pending..."
        user_message = (
            f"Hi {user.first_name},<br><br>"
            f"Your investment transfer of ₦{amount:,.2f} is pending approval.<br><br>"
            "Thank you for using MyFund."
        )
<<<<<<< HEAD

        threading.Thread(
            target=send_generic_email,
            args=(user_subject, user_message, "info@myfundmobile.com", [user.email]),
            kwargs={
                "use_celery_threshold": 30,
                "template": "email/email.html",
            },
=======
        threading.Thread(
            target=send_generic_email,
            args=(user_subject, user_message, "info@mg.myfundmobile.com", [user.email]),
            kwargs={"use_celery_threshold": 30, "template": "email/email.html"},
>>>>>>> staging
            daemon=True,
        ).start()

        # 📧 ADMIN EMAIL — THREADING
        admin_subject = f"[CHECK] {user.first_name} Made A QuickInvest Request"
        admin_message = (
            f"Hi Admin,<br><br>"
            f"{user.first_name} {user.last_name} ({user.email}) initiated "
            f"₦{amount:,.2f} QuickInvest.<br><br>"
            f"Review here: https://myfundapi-myfund-07ce351a.koyeb.app/admin/<br><br>"
            "MyFund Team"
        )
<<<<<<< HEAD

=======
>>>>>>> staging
        threading.Thread(
            target=send_generic_email,
            args=(
                admin_subject,
                admin_message,
<<<<<<< HEAD
                "info@myfundmobile.com",
                ["company@myfundmobile.com", "info@myfundmobile.com"],
            ),
            kwargs={
                "use_celery_threshold": 30,
                "template": "email/email.html",
            },
=======
                "info@mg.myfundmobile.com",
                ["company@myfundmobile.com", "info@mg.myfundmobile.com"],
            ),
            kwargs={"use_celery_threshold": 30, "template": "email/email.html"},
>>>>>>> staging
            daemon=True,
        ).start()

        # 🔔 ADMIN PUSH
<<<<<<< HEAD
        admin_emails = [
            "tolulopeahmed@gmail.com",
            "ceo@myfundmobile.com",
            "janet.adegbenro@gmail.com",
        ]

        admin_users = CustomUser.objects.filter(email__in=admin_emails)

        for admin in admin_users:
            if hasattr(admin, "expo_push_tokens") and admin.expo_push_tokens:
                send_push_notification(
                    user=admin,
                    title=f"{user.first_name} initiated a New QuickInvest",
                    message=(
                        f"{user.first_name} {user.last_name} ({user.email}) "
                        f"initiated ₦{amount:,.2f} to Investment Account.\n"
                        "Please check to confirm."
                    ),
=======
        admin_users = CustomUser.objects.filter(is_staff=True, is_active=True)

        for admin in admin_users:
            if hasattr(admin, "expo_push_tokens") and admin.expo_push_tokens:
                admin_push_title = f"{user.first_name} initiated a New QuickInvest"
                admin_push_message = (
                    f"{user.first_name} {user.last_name} ({user.email}) initiated "
                    f"₦{amount:,.2f} to Investment Account.\nPlease check to confirm."
                )
                send_push_notification(
                    user=admin,
                    title=admin_push_title,
                    message=admin_push_message,
>>>>>>> staging
                    data={
                        "transaction_id": transaction_id,
                        "user_email": user.email,
                        "type": "QuickInvest",
                        "status": "pending",
                        "source": "admin_quickinvest_alert",
<<<<<<< HEAD
=======
                        # Was missing entirely - this is what actually
                        # attaches the "Approve"/"Mark Abandoned" action
                        # buttons (category) and the admin_url, mirroring
                        # what QuickSave's admin push already sends via
                        # dl.admin_bank_transfer().
                        **dl.admin_invest_transfer(transaction_id),
>>>>>>> staging
                    },
                    notif_type="ADMIN_ALERT",
                )

<<<<<<< HEAD
=======
        # ✅ RETURN RESPONSE
>>>>>>> staging
        return Response(
            {
                "message": "QuickInvest request created and pending approval",
                "amount": str(amount),
            },
            status=201,
        )

    except Exception as e:
        return Response(
<<<<<<< HEAD
            {
                "error": str(e),
                "transaction_id": transaction_id,
            },
=======
            {"error": str(e), "transaction_id": transaction_id},
>>>>>>> staging
            status=400,
        )


import threading
import uuid
from decimal import Decimal, InvalidOperation
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import (
    CustomUser,
    Transaction,
    DvaDepositIntent,
)
from .utils import (
    send_generic_email,
    send_push_notification,
    create_paystack_customer,
    identify_paystack_customer,
    create_dedicated_account,
)


def _create_dva_intent(user, amount, purpose):
    transaction_id = str(uuid.uuid4())[:10]
    current_datetime = timezone.now()
    referral_email = user.referral.email if user.referral else None

    intent = DvaDepositIntent.objects.create(
        user=user,
        amount=amount,
        purpose=purpose,
        status="pending",
        transaction_id=transaction_id,
    )

<<<<<<< HEAD
    description = "QuickSave . . ." if purpose == "SAVINGS" else "QuickInvest . . ."
=======
    description = "QuickSave" if purpose == "SAVINGS" else "QuickInvest"
>>>>>>> staging

    transaction = Transaction.objects.create(
        user=user,
        referral_email=referral_email,
        transaction_type="credit",
        status="pending",
        amount=amount,
        description=description,
        transaction_id=transaction_id,
<<<<<<< HEAD
=======
        source_channel="DVA",
>>>>>>> staging
    )

    return intent, transaction


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def get_or_create_dva_account(request):
    """
    First-time DVA setup endpoint.
    Requires BVN + bank_code + account_number only if user has no DVA yet.
    """
    try:
        user = request.user

        if user.dva_account_number:
            return Response(
                {
                    "message": "DVA already exists",
                    "has_dva": True,
                    "account_number": user.dva_account_number,
                    "bank_name": user.dva_bank_name,
                    "account_name": user.dva_account_name,
                },
                status=status.HTTP_200_OK,
            )

        bvn = request.data.get("bvn")
        bank_code = request.data.get("bank_code")
        account_number = request.data.get("account_number")
        preferred_bank = request.data.get("preferred_bank", "wema-bank")

        if not bvn:
            return Response(
                {"error": "BVN is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not bank_code:
            return Response(
                {"error": "Bank code is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not account_number:
            return Response(
                {"error": "Account number is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok, result = create_paystack_customer(user)
        if not ok:
            return Response(
                {"error": "Failed to create Paystack customer", "details": result},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok, result = identify_paystack_customer(user, bvn, bank_code, account_number)
        if not ok:
            return Response(
                {"error": "Customer identification failed", "details": result},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok, result = create_dedicated_account(user, preferred_bank=preferred_bank)
        if not ok:
            return Response(
                {"error": "DVA creation failed", "details": result},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "message": "DVA created successfully",
                "has_dva": True,
                "account_number": result["account_number"],
                "bank_name": result["bank_name"],
                "account_name": result["account_name"],
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_dva_quicksave(request):
    try:
        user = request.user
        print("INITIATING DVA QUICKSAVE")
        print("PAYSTACK SECRET PREFIX:", settings.PAYSTACK_SECRET_KEY[:10])
        print("USER DVA:", user.dva_account_number, user.dva_bank_name)

        amount_raw = request.data.get("amount")

        if not amount_raw:
            return Response(
                {"error": "Amount is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            amount = Decimal(str(amount_raw))
<<<<<<< HEAD
            if amount < 100:
                return Response(
                    {"error": "Amount must be greater than ₦100"},
=======
            if amount < settings.MIN_DEPOSIT_AMOUNT:
                return Response(
                    {
                        "error": f"Amount cannot be less than ₦{settings.MIN_DEPOSIT_AMOUNT}"
                    },
>>>>>>> staging
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (InvalidOperation, ValueError, TypeError):
            return Response(
                {"error": "Invalid amount format. Please enter a valid number."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not user.dva_account_number:
            return Response(
                {"error": "No DVA found. Please create your transfer account first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        intent, transaction = _create_dva_intent(user, amount, "SAVINGS")

        return Response(
            {
                "message": "DVA QuickSave initiated successfully",
                "transaction_id": intent.transaction_id,
                "intent_id": intent.id,
                "amount": str(amount),
                "account_number": user.dva_account_number,
                "bank_name": user.dva_bank_name,
                "account_name": user.dva_account_name,
                "purpose": "SAVINGS",
                "status": "pending_confirmation",
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        return Response(
            {"error": str(e)},
            status=status.HTTP_400_BAD_REQUEST,
        )


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .utils import requery_paystack_dva


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def requery_my_dva_payments(request):
    try:
        user = request.user

        if not user.dva_account_number:
            return Response(
                {"error": "No DVA found for this user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        status_code, result = requery_paystack_dva(user.dva_account_number)

        return Response(
            {
                "message": "DVA requery triggered.",
                "paystack_status_code": status_code,
                "details": result,
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        return Response(
            {"error": str(e)},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_dva_quickinvest(request):
    try:
        user = request.user
        amount_raw = request.data.get("amount")

        if not amount_raw:
            return Response(
                {"error": "Amount is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            amount = Decimal(str(amount_raw))
<<<<<<< HEAD
            if amount < 100:
                return Response(
                    {"error": "Amount must be greater than ₦100"},
=======
            if amount < settings.MIN_DEPOSIT_AMOUNT:
                return Response(
                    {
                        "error": f"Amount cannot be less than ₦{settings.MIN_DEPOSIT_AMOUNT}"
                    },
>>>>>>> staging
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (InvalidOperation, ValueError, TypeError):
            return Response(
                {"error": "Invalid amount format. Please enter a valid number."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not user.dva_account_number:
            return Response(
                {"error": "No DVA found. Please create your transfer account first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        intent, transaction = _create_dva_intent(user, amount, "INVESTMENT")

        def background_tasks():
            try:
                send_push_notification(
                    user=user,
                    title="QuickInvest Transfer Pending ⏳",
                    message=(
                        f"Transfer exactly ₦{amount:,.2f} to your MyFund DVA. "
                        f"Your Investment account will be credited automatically once confirmed."
                    ),
                    data={
                        "amount": str(amount),
                        "transaction_id": intent.transaction_id,
                        "type": "QuickInvest",
                        "status": "pending",
                    },
                    notif_type="PENDING",
                )

                send_generic_email(
                    "QuickInvest Transfer Created",
                    (
                        f"Hi {user.first_name},<br><br>"
                        f"Your QuickInvest transfer request for ₦{amount:,.2f} has been created."
                        f"<br><br>Transfer exactly this amount to:"
                        f"<br><b>{user.dva_account_number}</b> ({user.dva_bank_name})"
                        f"<br><b>{user.dva_account_name}</b>"
                        f"<br><br>We will credit your investment automatically once confirmed."
                    ),
                    [user.email],
<<<<<<< HEAD
                    "MyFund <info@myfundmobile.com>",
=======
                    "MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                )
            except Exception as e:
                print(f"DVA QuickInvest background task error: {e}")

        threading.Thread(target=background_tasks, daemon=True).start()

        return Response(
            {
                "message": "DVA QuickInvest initiated successfully",
                "transaction_id": intent.transaction_id,
                "amount": str(amount),
                "account_number": user.dva_account_number,
                "bank_name": user.dva_bank_name,
                "account_name": user.dva_account_name,
                "purpose": "INVESTMENT",
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


<<<<<<< HEAD
=======
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def remove_dva_account(request):
    """
    Allows a user to remove their own DVA from the app.
    Clears local DVA fields only (does not call Paystack to deactivate).
    """
    user = request.user

    if not user.dva_account_number:
        return Response(
            {"error": "You don't have a DVA account to remove."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Clear all DVA-related fields
    user.dva_account_number = None
    user.dva_account_name = None
    user.dva_bank_name = None
    user.dva_account_id = None
    user.dva_assigned_at = None
    user.paystack_identified = False
    user.paystack_identification_status = None
    user.paystack_identification_reason = None
    user.save(
        update_fields=[
            "dva_account_number",
            "dva_account_name",
            "dva_bank_name",
            "dva_account_id",
            "dva_assigned_at",
            "paystack_identified",
            "paystack_identification_status",
            "paystack_identification_reason",
        ]
    )

    return Response(
        {"message": "Your virtual account has been removed successfully."},
        status=status.HTTP_200_OK,
    )


>>>>>>> staging
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_by_email(request):
    email = request.query_params.get("email", "")
    try:
        user = CustomUser.objects.get(email=email)
<<<<<<< HEAD
=======
        pic = user.profile_picture
        if hasattr(pic, "url"):
            pic = pic.url
        elif not isinstance(pic, str):
            pic = None

>>>>>>> staging
        user_data = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
<<<<<<< HEAD
            # Add any other user details you want to include
=======
            "profile_picture": pic or None,
            "phone_number": user.phone_number or None,
>>>>>>> staging
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
<<<<<<< HEAD
        from_email = "info@myfundmobile.com"
=======
        from_email = "info@mg.myfundmobile.com"
>>>>>>> staging

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
            subject=subject,
            message=message,
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[user.email],
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
            subject=subject,
            message=message,
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[user.email],
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
<<<<<<< HEAD
                from_email = "MyFund <info@myfundmobile.com>"
=======
                from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                recipient_list = [user.email]

                send_generic_email(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=recipient_list,
                )

            if description[0] == "QuickSave":
                user.savings += int(amount)

                # Send a confirmation email
                subject = "QuickSave Successful!"
                message = f"Well done {user.first_name},<br><br>Your QwickSave was successful and ₦{amount} has been successfully added to your SAVINGS account. <br><br>Keep growing your funds.🥂"
<<<<<<< HEAD
                from_email = "MyFund <info@myfundmobile.com>"
=======
                from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                recipient_list = [user.email]

                send_generic_email(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=recipient_list,
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
from decimal import Decimal
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework import status

from .models import (
    CustomUser,
    Transaction,
    AutoSave,
    AutoInvest,
    BankAccount,
    WithdrawalsRequestToAdmin,
    DvaDepositIntent,
)
from .utils import (
    send_generic_email,
    send_push_notification,
    approve_quicksave_credit,
    create_dedicated_account,
)

<<<<<<< HEAD

=======
>>>>>>> staging
paystack_ips = ["52.31.139.75", "52.49.173.169", "52.214.14.220"]


def is_paystack_name_mismatch_reason(reason_text):
    text = (reason_text or "").strip().lower()

    mismatch_phrases = [
        "name mismatch",
        "account name or bvn is incorrect",
        "account name is incorrect",
        "bvn is incorrect",
        "name does not match",
        "does not match your bvn",
        "does not match bvn",
        "mismatch",
    ]

    return any(phrase in text for phrase in mismatch_phrases)


import json
import hmac
import hashlib

<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.permissions import AllowAny


@csrf_exempt
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def paystack_webhook(request):
    try:
        raw_body = request.body or b""
        signature = request.headers.get("x-paystack-signature", "")

        if not raw_body:
            return JsonResponse(
                {"status": False, "message": "Empty webhook body"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not signature:
            return JsonResponse(
                {"status": False, "message": "Missing Paystack signature"},
                status=status.HTTP_403_FORBIDDEN,
            )

        computed_signature = hmac.new(
            settings.PAYSTACK_SECRET_KEY.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha512,
        ).hexdigest()

        if not hmac.compare_digest(signature, computed_signature):
            return JsonResponse(
                {"status": False, "message": "Invalid Paystack signature"},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            event = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            return JsonResponse(
                {"status": False, "message": "Invalid JSON payload"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        header_data = dict(request.headers)

        ip_address = (
            request.headers.get("Cf-Connecting-Ip")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.META.get("REMOTE_ADDR")
        )

        event_status = event.get("event")
        print("========== PAYSTACK WEBHOOK HIT ==========")
        print("paystack event status:", event_status)
        print("ip_address:", ip_address)
        print("signature verified: True")

        paystack_webhook_processing(event, ip_address, True, header_data)

        return JsonResponse({"status": True}, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"\nPaystack Webhook(Internal Server Error): {e}\n")

        send_generic_email(
            subject="Paystack Webhook Error!",
            message=f"Paystack Webhook Internal Server Error: {e}",
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
            recipient_list=["info@myfundmobile.com", "sammy@myfundmobile.com"],
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
            recipient_list=["info@mg.myfundmobile.com", "sammy@myfundmobile.com"],
>>>>>>> staging
        )

        return JsonResponse(
            {"status": False, "error": str(e)},
            status=status.HTTP_200_OK,
        )


<<<<<<< HEAD
=======
def process_dva_credit_from_paystack_event(event):
    data = event.get("data", {}) or {}

    reference = data.get("reference") or data.get("id")
    payment_channel = data.get("channel")
    email = (data.get("customer", {}) or {}).get("email")
    amount = Decimal(data.get("amount", 0)) / 100

    authorization = data.get("authorization", {}) or {}
    receiver_account_number = authorization.get("receiver_bank_account_number")

    if not reference or amount <= 0:
        print("Invalid DVA webhook payload")
        return False

    # Prevent duplicate credit
    existing = Transaction.objects.filter(
        paystack_reference=reference,
        status="confirmed",
    ).exists()

    if existing:
        print("Duplicate DVA payment ignored")
        return True

    user = None

    if receiver_account_number:
        user = CustomUser.objects.filter(
            dva_account_number=receiver_account_number
        ).first()

    if not user and email:
        user = CustomUser.objects.filter(email=email).first()

    if not user:
        print(f"DVA user not found. Email={email}, Account={receiver_account_number}")
        return False

    intent = (
        DvaDepositIntent.objects.filter(
            user=user,
            amount=amount,
            status="pending",
        )
        .order_by("-created_at")
        .first()
    )

    purpose = intent.purpose if intent else "SAVINGS"

    transaction = None

    if intent:
        transaction = Transaction.objects.filter(
            user=user,
            transaction_id=intent.transaction_id,
            status="pending",
        ).first()

    # If user paid without an active intent, create confirmed transaction anyway
    if not transaction:
        transaction = create_transaction(
            user=user,
            amount=amount,
            transaction_type="credit",
            status="confirmed",
            source="DVA",
            credited_to="INVESTMENT" if purpose == "INVESTMENT" else "SAVINGS",
            description=(
                "QuickInvest (Transfer)"
                if purpose == "INVESTMENT"
                else "QuickSave (Transfer)"
            ),
            service_charge=0,
            reference=reference,
        )

        transaction.paystack_reference = reference
        transaction.paystack_auth_code = authorization.get("authorization_code")
        transaction.save(update_fields=["paystack_reference", "paystack_auth_code"])

    else:
        if purpose == "SAVINGS":
            ok, msg = approve_quicksave_credit(
                user=user,
                amount=amount,
                transaction_id=transaction.transaction_id,
                description="QuickSave (Transfer)",
                source="DVA",
                paystack_reference=reference,
                paystack_auth_code=authorization.get("authorization_code"),
            )

            if not ok:
                print(f"QuickSave DVA approval failed: {msg}")
                return False

        else:
            user.refresh_from_db()
            balance_before = user.investment or Decimal("0.00")
            balance_after = balance_before + amount

            transaction.transaction_type = "credit"
            transaction.status = "confirmed"
            transaction.source = "DVA"
            transaction.credited_to = "INVESTMENT"
            transaction.description = "QuickInvest (Transfer)"
            transaction.paystack_reference = reference
            transaction.paystack_auth_code = authorization.get("authorization_code")
            transaction.balance_before = balance_before
            transaction.balance_after = balance_after
            transaction.save()

            user.investment = balance_after
            user.update_total_savings_and_investment_this_month()
            user.save()

    if intent:
        intent.status = "confirmed"
        intent.paystack_reference = reference
        intent.matched_account_number = receiver_account_number
        intent.confirmed_at = timezone.now()
        intent.save(
            update_fields=[
                "status",
                "paystack_reference",
                "matched_account_number",
                "confirmed_at",
            ]
        )

    send_push_notification(
        user=user,
        title=(
            "QuickInvest Successful ✅"
            if purpose == "INVESTMENT"
            else "QuickSave Successful ✅"
        ),
        message=(
            f"Hi {user.first_name}, your transfer of ₦{amount:,.2f} "
            f"has been added to your {'Investment' if purpose == 'INVESTMENT' else 'Savings'} account."
        ),
        data={
            "amount": str(amount),
            "transaction_id": transaction.transaction_id,
            "type": "QuickInvest" if purpose == "INVESTMENT" else "QuickSave",
            "status": "confirmed",
        },
        notif_type="CREDIT",
    )

    user.confirm_referral_rewards(is_referrer=True)
    print(f"✅ DVA {purpose} credited successfully for {user.email}")
    return True


>>>>>>> staging
from .utils import create_transaction


def paystack_webhook_processing(event, ip_address, ip_is_paystack, header_data):
    print("========== PAYSTACK WEBHOOK HIT ==========")
    print("WEBHOOK EVENT RECEIVED:", event.get("event"))
    print("WEBHOOK FULL DATA:", event)
    print("PAYSTACK SECRET PREFIX:", settings.PAYSTACK_SECRET_KEY[:10])
    print("WEBHOOK URL HIT LOCALLY")

    try:
        subject = "Paystack Webhook Received!"
        message = (
            str(event)
            + " ip Address:"
            + str(ip_address)
            + " verified:"
            + str(ip_is_paystack)
            + " headers:"
            + str(header_data)
        )
<<<<<<< HEAD
        from_email = "MyFund <info@myfundmobile.com>"
=======
        from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
        recipient_list = ["webhook@myfundmobile.com", "sammy@myfundmobile.com"]

        send_generic_email(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
        )

        match event.get("event"):

            case "charge.success":
                reference = event["data"]["reference"]
                payment_channel = event["data"]["channel"]
                email = event["data"]["customer"]["email"]
                amount = Decimal(event["data"]["amount"]) / 100

                authorization = event["data"].get("authorization", {}) or {}
                receiver_account_number = authorization.get(
                    "receiver_bank_account_number"
                )

                print("CHANNEL:", payment_channel)
                print("RECEIVER ACCOUNT:", receiver_account_number)
                print("FULL PAYSTACK EVENT:", event)

                # --------------------------------------------------
<<<<<<< HEAD
                # DVA / bank transfer intent-based handling
                # --------------------------------------------------
                if payment_channel in ["dedicated_nuban", "bank_transfer", "bank"]:
                    user = None

                    if receiver_account_number:
                        user = CustomUser.objects.filter(
                            dva_account_number=receiver_account_number
                        ).first()

                    if not user and email:
                        user = CustomUser.objects.filter(email=email).first()

                    if not user:
                        print(
                            f"User not found for DVA transfer. Email={email}, "
                            f"Account={receiver_account_number}"
                        )
                        return

                    existing = (
                        Transaction.objects.filter(transaction_id=reference).first()
                        or Transaction.objects.filter(
                            paystack_reference=reference
                        ).first()
                    )
                    if existing and existing.status == "confirmed":
                        print("Duplicate DVA transfer ignored")
                        return

                    intent = (
                        DvaDepositIntent.objects.filter(
                            user=user,
                            amount=amount,
                            status="pending",
                        )
                        .order_by("-created_at")
                        .first()
                    )

                    if not intent:
                        print(
                            f"No pending DVA intent found for {user.email} amount {amount}"
                        )
                        return

                    transaction = Transaction.objects.filter(
                        user=user,
                        transaction_id=intent.transaction_id,
                        status="pending",
                    ).first()

                    if not transaction:
                        print(
                            f"No pending transaction found for intent {intent.transaction_id}"
                        )
                        return

                    if intent.purpose != "SAVINGS":
                        # Snapshot investment balance before crediting
                        user.refresh_from_db()
                        balance_before = user.investment
                        balance_after = balance_before + amount

                        transaction.status = "confirmed"
                        transaction.paystack_reference = reference
                        transaction.paystack_auth_code = authorization.get(
                            "authorization_code"
                        )
                        transaction.description = "QuickInvest (Transfer)"
                        transaction.balance_before = balance_before
                        transaction.balance_after = balance_after
                        transaction.save(
                            update_fields=[
                                "status",
                                "paystack_reference",
                                "paystack_auth_code",
                                "description",
                                "balance_before",
                                "balance_after",
                            ]
                        )

                    intent.status = "confirmed"
                    intent.paystack_reference = reference
                    intent.matched_account_number = receiver_account_number
                    intent.confirmed_at = timezone.now()
                    intent.save(
                        update_fields=[
                            "status",
                            "paystack_reference",
                            "matched_account_number",
                            "confirmed_at",
                        ]
                    )

                    if intent.purpose == "SAVINGS":
                        ok, msg = approve_quicksave_credit(
                            user=user,
                            amount=amount,
                            transaction_id=transaction.transaction_id,
                            description="QuickSave (Transfer)",
                            source="DVA",
                            paystack_reference=reference,
                            paystack_auth_code=authorization.get("authorization_code"),
                        )

                        if not ok:
                            print(f"QuickSave DVA approval failed: {msg}")
                            return

                    else:
                        user.investment += amount

                        send_push_notification(
                            user=user,
                            title="QuickInvest Approved ✅",
                            message=(
                                f"Hi {user.first_name}, your transfer of ₦{amount:,.2f} "
                                f"has been added to your Investment account."
                            ),
                            data={
                                "amount": str(amount),
                                "transaction_id": transaction.transaction_id,
                                "type": "QuickInvest",
                            },
                            notif_type="CREDIT",
                        )

                        send_generic_email(
                            subject="QuickInvest Updated! ✅",
                            message=(
                                f"Hi {user.first_name},<br><br>"
                                f"Your bank transfer of ₦{amount:,.2f} has been processed "
                                f"successfully and added to your Investment account."
                            ),
                            from_email="MyFund <info@myfundmobile.com>",
                            recipient_list=[user.email],
                        )

                    if intent.purpose != "SAVINGS":
                        if user.referral:
                            user.confirm_referral_rewards(is_referrer=False)

                        user.update_total_savings_and_investment_this_month()
                        user.save()

                    print(
                        f"✅ DVA {intent.purpose} credited successfully for {user.email}"
                    )
=======
                # DVA / bank transfer handling
                # --------------------------------------------------
                if payment_channel in ["dedicated_nuban", "bank_transfer", "bank"]:
                    process_dva_credit_from_paystack_event(event)
>>>>>>> staging
                    return

                # --------------------------------------------------
                # Existing card / autosave / autoinvest flow
                # --------------------------------------------------
                paystack_auth_code = authorization.get("authorization_code")
                plan = event["data"].get("plan") or {}
                plan_code = plan.get("plan_code")

                try:
                    user = CustomUser.objects.get(email=email)
                except CustomUser.DoesNotExist:
                    subject = "[Webhook Error] User NOT Found in DB"
                    message = f"No user found with email {email}."
<<<<<<< HEAD
                    from_email = "MyFund <info@myfundmobile.com>"
                    recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]
=======
                    from_email = "MyFund <info@mg.myfundmobile.com>"
                    recipient_list = [
                        "info@mg.myfundmobile.com",
                        "sammy@myfundmobile.com",
                    ]
>>>>>>> staging

                    send_generic_email(
                        subject=subject,
                        message=message,
                        from_email=from_email,
                        recipient_list=recipient_list,
                    )
<<<<<<< HEAD
=======

>>>>>>> staging
                    return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                saved_card = None

                if user and authorization:
                    try:
                        print("========== CARD SAVE DEBUG ==========")
                        print("email:", email)
                        print("authorization payload:", authorization)

                        saved_card = save_or_update_card_from_paystack_auth(
                            user, authorization
                        )

                        if saved_card:
                            print(
                                f"✅ CARD SAVED/UPDATED: id={saved_card.id}, auth={saved_card.authorization_code}, last4={saved_card.card_last4_digits}, reusable={saved_card.reusable}, active={saved_card.is_active}"
                            )
                        else:
                            print(
                                "⚠️ Card save helper returned None. authorization_code may be missing."
                            )

                    except Exception as e:
                        print(f"❌ Error saving card: {str(e)}", flush=True)
                        try:
                            subject = "[Webhook Warning] Card Save Failed"
                            message = (
                                f"Failed to save/update card for user {email}: {str(e)}<br><br>"
                                f"Authorization payload: {authorization}"
                            )
                            send_generic_email(
                                subject=subject,
                                message=message,
<<<<<<< HEAD
                                from_email="MyFund <info@myfundmobile.com>",
                                recipient_list=[
                                    "info@myfundmobile.com",
=======
                                from_email="MyFund <info@mg.myfundmobile.com>",
                                recipient_list=[
                                    "info@mg.myfundmobile.com",
>>>>>>> staging
                                    "sammy@myfundmobile.com",
                                ],
                            )
                        except Exception:
                            pass

                try:
                    transaction = Transaction.objects.get(
                        transaction_id=reference,
                        amount=amount,
                    )
                except Transaction.DoesNotExist:
                    transaction = None

                if plan_code:
                    autosave = AutoSave.objects.filter(
                        user=user,
                        paystack_plan_code=plan_code,
                        active=True,
                    ).first()

                    autoinvest = None
                    if not autosave:
                        autoinvest = AutoInvest.objects.filter(
                            user=user,
                            paystack_plan_code=plan_code,
                            active=True,
                        ).first()

                    target = autosave if autosave else autoinvest

                    if not target:
                        subject = "[Webhook Error] Plan Code NOT Found in DB"
                        message = (
                            f"No AutoSave/AutoInvest found with reference {reference}, "
                            f"amount {amount}, and plan_code {plan_code}."
                        )
<<<<<<< HEAD
                        from_email = "MyFund <info@myfundmobile.com>"
                        recipient_list = [
                            "info@myfundmobile.com",
=======
                        from_email = "MyFund <info@mg.myfundmobile.com>"
                        recipient_list = [
                            "info@mg.myfundmobile.com",
>>>>>>> staging
                            "sammy@myfundmobile.com",
                        ]

                        send_generic_email(
                            subject=subject,
                            message=message,
                            from_email=from_email,
                            recipient_list=recipient_list,
                        )
                        return

                    if autosave:
                        if not transaction:
                            # create_transaction handles balance snapshot + user.savings update atomically
                            transaction = create_transaction(
                                user=user,
                                amount=amount,
                                transaction_type="credit",
                                status="confirmed",
                                source="CARD",
                                credited_to="SAVINGS",
                                description=f"AutoSave ({autosave.frequency.capitalize()})",
                                service_charge=0,
                                reference=reference,
                            )
                            transaction.paystack_auth_code = paystack_auth_code
                            transaction.paystack_reference = reference
                            transaction.save(
                                update_fields=[
                                    "paystack_auth_code",
                                    "paystack_reference",
                                ]
                            )
                        else:
                            # Existing transaction — stamp balances and update refs
                            user.refresh_from_db()
                            balance_before = user.savings
                            balance_after = balance_before + amount
                            transaction.balance_before = balance_before
                            transaction.balance_after = balance_after
                            transaction.paystack_auth_code = paystack_auth_code
                            transaction.paystack_reference = reference
                            transaction.save(
                                update_fields=[
                                    "balance_before",
                                    "balance_after",
                                    "paystack_auth_code",
                                    "paystack_reference",
                                ]
                            )
                            user.savings += amount
                            user.update_total_savings_and_investment_this_month()
                            user.save(
                                update_fields=[
                                    "savings",
                                    "total_savings_and_investments_this_month",
                                    "updated_at",
                                ]
                            )

                        user.refresh_from_db()
                        user.update_total_savings_and_investment_this_month()
                        user.save(
                            update_fields=[
                                "total_savings_and_investments_this_month",
                                "updated_at",
                            ]
                        )

                        subject = f"AutoSave ({autosave.frequency.capitalize()}) Successful! ✅"
                        message = (
                            f"Well done {user.first_name},<br><br>"
                            f"Your AutoSave was successful and ₦{amount:,.2f} "
                            f"has been added to your SAVINGS account."
                        )
<<<<<<< HEAD
                        from_email = "MyFund <info@myfundmobile.com>"
=======
                        from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                        recipient_list = [user.email]

                        send_generic_email(
                            subject=subject,
                            message=message,
                            from_email=from_email,
                            recipient_list=recipient_list,
                        )

                        send_push_notification(
                            user=user,
                            title="AutoSave Successful! ✅",
                            message=(
                                f"Hi {user.first_name}, your scheduled AutoSave of "
                                f"₦{amount:,.2f} ({autosave.frequency.capitalize()}) "
                                f"has just been deposited into your savings."
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

<<<<<<< HEAD
=======
                        user.confirm_referral_rewards(is_referrer=True)
>>>>>>> staging
                        print("AutoSave Successfully Credited your Account.")
                        return

                    if autoinvest:
                        if not transaction:
                            # create_transaction handles balance snapshot + user.investment update atomically
                            transaction = create_transaction(
                                user=user,
                                amount=amount,
                                transaction_type="credit",
                                status="confirmed",
                                source="CARD",
                                credited_to="INVESTMENT",
                                description=f"AutoInvest ({autoinvest.frequency.capitalize()})",
                                service_charge=0,
                                reference=reference,
                            )
                            transaction.paystack_auth_code = paystack_auth_code
                            transaction.paystack_reference = reference
                            transaction.save(
                                update_fields=[
                                    "paystack_auth_code",
                                    "paystack_reference",
                                ]
                            )
                        else:
                            # Existing transaction — stamp balances and update refs
                            user.refresh_from_db()
                            balance_before = user.investment
                            balance_after = balance_before + amount
                            transaction.transaction_type = "credit"
                            transaction.status = "confirmed"
                            transaction.paystack_auth_code = paystack_auth_code
                            transaction.paystack_reference = reference
                            transaction.credited_to = "INVESTMENT"
                            transaction.balance_before = balance_before
                            transaction.balance_after = balance_after
                            transaction.save(
                                update_fields=[
                                    "transaction_type",
                                    "status",
                                    "paystack_auth_code",
                                    "paystack_reference",
                                    "credited_to",
                                    "balance_before",
                                    "balance_after",
                                ]
                            )
                            user.investment += amount
                            user.update_total_savings_and_investment_this_month()
                            user.save()

                        user.refresh_from_db()
                        user.update_total_savings_and_investment_this_month()
                        user.save(
                            update_fields=[
                                "total_savings_and_investments_this_month",
                                "updated_at",
                            ]
                        )

                        subject = f"AutoInvest ({autoinvest.frequency.capitalize()}) Successful! 🎉"
                        message = (
                            f"Well done {user.first_name},<br><br>"
                            f"Your AutoInvest was successful and ₦{amount:,.2f} "
                            f"has been added to your INVESTMENT account."
                        )
<<<<<<< HEAD
                        from_email = "MyFund <info@myfundmobile.com>"
=======
                        from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                        recipient_list = [user.email]

                        send_generic_email(
                            subject=subject,
                            message=message,
                            from_email=from_email,
                            recipient_list=recipient_list,
                        )

                        send_push_notification(
                            user=user,
                            title="AutoInvest Successful! 🎉",
                            message=(
                                f"Your scheduled AutoInvest of ₦{amount:,.2f} "
                                f"({autoinvest.frequency.capitalize()}) has just been "
                                f"deposited into your investments."
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

<<<<<<< HEAD
=======
                        user.confirm_referral_rewards(is_referrer=True)
>>>>>>> staging
                        print("AutoInvest Successfully Credited your Account.")
                        return

                elif transaction and transaction.description.lower().startswith(
                    "quicksave"
                ):
                    # Snapshot savings balance before crediting
                    user.refresh_from_db()
                    balance_before = user.savings
                    balance_after = balance_before + amount

                    if saved_card:
                        transaction.description = "QuickSave (Card)"
                        transaction.paystack_auth_code = saved_card.authorization_code
                    else:
                        transaction.description = "QuickSave (Transfer)"
                        transaction.paystack_auth_code = paystack_auth_code

                    transaction.status = "confirmed"
                    transaction.paystack_reference = reference
                    transaction.balance_before = balance_before
                    transaction.balance_after = balance_after
                    transaction.save()

                    user.savings += amount
                    user.update_total_savings_and_investment_this_month()
                    user.save()

                    subject = "QuickSave Successful!"
                    message = (
                        f"Well done {user.first_name},<br><br>"
                        f"Your <b>QuickSave</b> was successful and <b>₦{amount:,.2f}</b> "
                        f"has been successfully added to your SAVINGS account."
                        f"<br><br>Keep growing your funds.🥂<br><br>"
                    )
<<<<<<< HEAD
                    from_email = "MyFund <info@myfundmobile.com>"
=======
                    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                    recipient_list = [user.email]

                    send_generic_email(
                        subject=subject,
                        message=message,
                        from_email=from_email,
                        recipient_list=recipient_list,
                    )

<<<<<<< HEAD
=======
                    user.confirm_referral_rewards(is_referrer=True)
>>>>>>> staging
                    return JsonResponse({"status": True}, status=status.HTTP_200_OK)

                elif transaction and transaction.description.lower().startswith(
                    "quickinvest"
                ):
                    # Snapshot investment balance before crediting
                    user.refresh_from_db()
                    balance_before = user.investment
                    balance_after = balance_before + amount

                    transaction.description = f"QuickInvest ({payment_channel})"
                    transaction.status = "confirmed"
                    transaction.paystack_auth_code = paystack_auth_code
                    transaction.paystack_reference = reference
                    transaction.balance_before = balance_before
                    transaction.balance_after = balance_after
                    transaction.save()

                    user.investment += amount
                    user.update_total_savings_and_investment_this_month()
                    user.save()

                    subject = "QuickInvest Successful!"
                    message = (
                        f"Well done {user.first_name},<br><br>"
                        f"Your QuickInvest was successful and ₦{amount:,.2f} "
                        f"has been successfully added to your INVESTMENTS account."
                        f"<br><br>Keep growing your funds.🥂<br><br>"
                    )
<<<<<<< HEAD
                    from_email = "MyFund <info@myfundmobile.com>"
=======
                    from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                    recipient_list = [user.email]

                    send_generic_email(
                        subject=subject,
                        message=message,
                        from_email=from_email,
                        recipient_list=recipient_list,
                    )

<<<<<<< HEAD
=======
                    user.confirm_referral_rewards(is_referrer=True)
>>>>>>> staging
                    print("QuickInvest Successfully Credited your Account.")
                    return

                else:
                    trans_description = []
                    plan_name = plan.get("name", "")

                    if transaction is None and plan_name:
                        trans_description = plan_name.split(" ")
                        trans_desc_label = (
                            trans_description[1]
                            if len(trans_description) > 1
                            else "Deposit"
                        )

                        # Determine credited_to from description label
                        if "autosave" in trans_desc_label.lower():
                            _credited_to = "SAVINGS"
                        else:
                            _credited_to = "INVESTMENT"

                        # create_transaction handles snapshot + balance update atomically
                        transaction = create_transaction(
                            user=user,
                            amount=amount,
                            transaction_type="credit",
                            status="confirmed",
                            credited_to=_credited_to,
                            description=trans_desc_label,
                            reference=reference,
                        )
                        transaction.paystack_reference = reference
                        transaction.save(update_fields=["paystack_reference"])

                    trans_type = (
                        trans_description[1] if len(trans_description) > 1 else ""
                    )

                    if (
                        trans_type == "AutoInvest"
                        or AutoInvest.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                    ):
                        # create_transaction handles snapshot + user.investment update atomically
                        transaction = create_transaction(
                            user=user,
                            amount=amount,
                            transaction_type="credit",
                            status="confirmed",
                            credited_to="INVESTMENT",
                            description=f"{trans_type}" if trans_type else "AutoInvest",
                            reference=reference,
                        )
                        transaction.paystack_reference = reference
                        transaction.save(update_fields=["paystack_reference"])

                print(f"transaction before update: {transaction}")

                if transaction and transaction.description.lower().startswith(
                    "autosave"
                ):
                    if transaction.status != "confirmed":
                        autosave_rec = AutoSave.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                        freq = (
                            autosave_rec.frequency.capitalize()
                            if autosave_rec and autosave_rec.frequency
                            else event["data"].get("frequency", "").capitalize()
                        )

                        # Snapshot savings balance before crediting
                        user.refresh_from_db()
                        balance_before = user.savings
                        balance_after = balance_before + amount

                        transaction.transaction_type = "credit"
                        transaction.status = "confirmed"
                        transaction.description = f"AutoSave ({freq})"
                        transaction.credited_to = "SAVINGS"
                        transaction.balance_before = balance_before
                        transaction.balance_after = balance_after
                        transaction.save(
                            update_fields=[
                                "transaction_type",
                                "status",
                                "description",
                                "credited_to",
                                "balance_before",
                                "balance_after",
                            ]
                        )

                        user.savings += amount
                        user.update_total_savings_and_investment_this_month()
                        user.save()
                    else:
                        autosave_rec = AutoSave.objects.filter(
                            paystack_trans_ref=reference
                        ).first()
                        freq = (
                            autosave_rec.frequency.capitalize()
                            if autosave_rec and autosave_rec.frequency
                            else "Confirmed"
                        )
                        transaction.description = f"AutoSave ({freq})"
                        transaction.save(update_fields=["description"])
                else:
                    if transaction:
                        if event["data"]["status"] != "success":
                            base_desc = transaction.description.split(" ")[0]
                            transaction.status = "failed"
                            transaction.description = f"{base_desc} (Failed)"
                            transaction.save(update_fields=["status", "description"])
                        else:
                            base_desc = transaction.description.split(" ")[0]

                            # Snapshot the correct balance before crediting
                            user.refresh_from_db()
                            if base_desc.lower().startswith("autosave"):
                                balance_before = user.savings
                                balance_after = balance_before + amount
                                _credited_to = "SAVINGS"
                            elif base_desc.lower().startswith("autoinvest"):
                                balance_before = user.investment
                                balance_after = balance_before + amount
                                _credited_to = "INVESTMENT"
                            else:
                                balance_before = user.savings
                                balance_after = balance_before + amount
                                _credited_to = "SAVINGS"

                            transaction.transaction_type = "credit"
                            transaction.status = "confirmed"
                            transaction.description = f"{base_desc} (Card)"
                            transaction.credited_to = _credited_to
                            transaction.balance_before = balance_before
                            transaction.balance_after = balance_after
                            transaction.save(
                                update_fields=[
                                    "transaction_type",
                                    "status",
                                    "description",
                                    "credited_to",
                                    "balance_before",
                                    "balance_after",
                                ]
                            )

                        amount = transaction.amount
                        description = transaction.description

                        if description.startswith("AutoSave"):
                            user.savings += amount

                            subject = "AutoSave Successful!"
                            message = (
                                f"Well done {user.first_name},<br><br>"
                                f"Your AutoSave was successful and ₦{amount:,.2f} "
                                f"has been successfully added to your SAVINGS account."
                                f"<br><br>Keep growing your funds.🥂"
                            )
<<<<<<< HEAD
                            from_email = "MyFund <info@myfundmobile.com>"
=======
                            from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                            recipient_list = [user.email]

                            send_generic_email(
                                subject=subject,
                                message=message,
                                from_email=from_email,
                                recipient_list=recipient_list,
                            )

                        if description.startswith("AutoInvest"):
                            user.investment += amount

                            subject = "AutoInvest Successful!"
                            message = (
                                f"Well done {user.first_name},<br><br>"
                                f"Your AutoInvest was successful and ₦{amount:,.2f} "
                                f"has been successfully added to your INVESTMENT account."
                                f"<br><br>Keep growing your funds.🥂<br><br>"
                            )
<<<<<<< HEAD
                            from_email = "MyFund <info@myfundmobile.com>"
=======
                            from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                            recipient_list = [user.email]

                            send_generic_email(
                                subject=subject,
                                message=message,
                                from_email=from_email,
                                recipient_list=recipient_list,
                            )

                        user.confirm_referral_rewards(is_referrer=True)
                        user.update_total_savings_and_investment_this_month()
                        user.save()

                print(f"transaction after update: {transaction}")
                return

            case "invoice.create":
                return

            case "invoice.payment_failed":
                event_data = event["data"]

                subject = "Paystack Webhook(Payment Failed)"
                message = f"Invoice Data: <br><br>{event_data}"
<<<<<<< HEAD
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]
=======
                from_email = "MyFund <info@mg.myfundmobile.com>"
                recipient_list = ["info@mg.myfundmobile.com", "sammy@myfundmobile.com"]
>>>>>>> staging

                send_generic_email(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=recipient_list,
                )
                return

            case "transfer.failed":
                amount = int(event["data"]["amount"] / 100)
                reason = event["data"]["reason"]
                transaction_id = event["data"]["transfer_code"]
                account_number = event["data"]["recipient"]["details"]["account_number"]

                user = None
                try:
                    user = BankAccount.objects.get(account_number=account_number).user
                except Exception:
                    print("User does not exist")

                request = WithdrawalsRequestToAdmin(
                    user=user,
                    amount=amount,
                    transaction_id=transaction_id,
                )
                request.save()

                subject = f"[CHECK] {user.first_name} Withdrawal Request FAILED!"
                message = (
                    f"Hi Admin, <br><br>A withdrawal request of ₦{amount} that was initiated "
                    f"by {user.first_name} {user.last_name} ({user.email}) has just FAILED!"
                    f"<br><br>Reason for failure: {reason}<br><br>Please log in to the admin "
                    f"panel for review: "
                    f"https://myfundapi-myfund-07ce351a.koyeb.app/admin/login/?next=/admin/<br><br>"
                )
<<<<<<< HEAD
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [
                    "company@myfundmobile.com",
                    "info@myfundmobile.com",
=======
                from_email = "MyFund <info@mg.myfundmobile.com>"
                recipient_list = [
                    "company@myfundmobile.com",
                    "info@mg.myfundmobile.com",
>>>>>>> staging
                    "sammy@myfundmobile.com",
                ]

                send_generic_email(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=recipient_list,
                )

                return

            case "dedicated_account.credit":
                print("Received dedicated_account.credit webhook")
<<<<<<< HEAD
=======
                print("DEDICATED ACCOUNT CREDIT PAYLOAD:", event)
>>>>>>> staging
                return

            case "customeridentification.success":
                customer_code = event["data"]["customer_code"]

                user = CustomUser.objects.filter(
                    paystack_customer_code=customer_code
                ).first()

                if not user:
                    print(f"User not found for customer code {customer_code}")
                    return

                user.paystack_identified = True
                user.paystack_identification_status = "success"
                user.paystack_identification_reason = None
                user.save(
                    update_fields=[
                        "paystack_identified",
                        "paystack_identification_status",
                        "paystack_identification_reason",
                    ]
                )

                print(f"✅ Customer identification successful for {user.email}")

                if not user.dva_account_number:
                    success, result = create_dedicated_account(
                        user,
                        preferred_bank="wema-bank",
                        force_create=True,
                    )
                    print(
                        f"DVA creation attempt after KYC for {user.email}: {success}, {result}"
                    )

                    if success:
                        send_push_notification(
                            user=user,
                            title="Deposit Account Ready ✅",
                            message=(
                                f"Hi {user.first_name}, your MyFund Dedicated Virtual Account is now ready. "
                                f"You can now do QuickSaves with {result.get('account_name')} "
                                f"({result.get('account_number')} - {result.get('bank_name')})."
                            ),
                            data={
                                "type": "DVA_READY",
                                "account_number": result.get("account_number"),
                                "bank_name": result.get("bank_name"),
                                "account_name": result.get("account_name"),
                            },
                            notif_type="SYSTEM",
                        )

                        send_generic_email(
                            subject="Your MyFund deposit account is ready ✅",
                            message=(
                                f"Hi {user.first_name},<br><br>"
                                f"Your dedicated MyFund deposit account has been created successfully.<br><br>"
                                f"<b>Bank:</b> {result.get('bank_name')}<br>"
                                f"<b>Account Number:</b> {result.get('account_number')}<br>"
                                f"<b>Account Name:</b> {result.get('account_name')}<br><br>"
                                f"You can now fund your QuickSave by bank transfer."
                            ),
<<<<<<< HEAD
                            from_email="MyFund <info@myfundmobile.com>",
=======
                            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                            recipient_list=[user.email],
                        )

                    else:
                        send_generic_email(
                            subject="[Paystack DVA Creation Failed After KYC]",
                            message=(
                                f"User: {user.email}<br>"
                                f"Customer code: {customer_code}<br>"
                                f"Result: {result}"
                            ),
<<<<<<< HEAD
                            from_email="MyFund <info@myfundmobile.com>",
                            recipient_list=[
                                "info@myfundmobile.com",
=======
                            from_email="MyFund <info@mg.myfundmobile.com>",
                            recipient_list=[
                                "info@mg.myfundmobile.com",
>>>>>>> staging
                                "sammy@myfundmobile.com",
                            ],
                        )

                else:
                    send_push_notification(
                        user=user,
                        title="Deposit Account Ready ✅",
                        message=(
                            f"Hi {user.first_name}, your MyFund deposit account is already ready. "
                            f"You can now do QuickSaves with {user.dva_account_name} "
                            f"({user.dva_account_number} - {user.dva_bank_name})."
                        ),
                        data={
                            "type": "DVA_READY",
                            "account_number": user.dva_account_number,
                            "bank_name": user.dva_bank_name,
                            "account_name": user.dva_account_name,
                        },
                        notif_type="SYSTEM",
                    )

                    send_generic_email(
                        subject="Your MyFund deposit account is ready ✅",
                        message=(
                            f"Hi {user.first_name},<br><br>"
                            f"Your dedicated MyFund deposit account is ready.<br><br>"
                            f"<b>Bank:</b> {user.dva_bank_name}<br>"
                            f"<b>Account Number:</b> {user.dva_account_number}<br>"
                            f"<b>Account Name:</b> {user.dva_account_name}<br><br>"
                            f"You can now fund your QuickSave by bank transfer."
                        ),
<<<<<<< HEAD
                        from_email="MyFund <info@myfundmobile.com>",
=======
                        from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                        recipient_list=[user.email],
                    )

                return

            case "customeridentification.failed":
                customer_code = event["data"]["customer_code"]
                reason = event["data"].get("reason", "Identification failed")

                user = CustomUser.objects.filter(
                    paystack_customer_code=customer_code
                ).first()

                if not user:
                    print(f"User not found for failed customer code {customer_code}")
                    return

                is_name_mismatch = is_paystack_name_mismatch_reason(reason)

                user.paystack_identified = False
                user.paystack_identification_status = "failed"
                user.paystack_identification_reason = (
                    "NAME_MISMATCH" if is_name_mismatch else reason
                )
                user.save(
                    update_fields=[
                        "paystack_identified",
                        "paystack_identification_status",
                        "paystack_identification_reason",
                    ]
                )

                print(f"❌ Customer identification failed for {user.email}: {reason}")

                if is_name_mismatch:
                    push_title = "Name Mismatch Detected"
                    push_message = (
                        f"Hi {user.first_name}, your profile name does not match your BVN/bank details. "
                        f"Please update your profile name and try again."
                    )
                    email_subject = "Action needed: update your name details"
                    email_message = (
                        f"Hi {user.first_name},<br><br>"
                        f"We could not verify your details because your profile name does not match "
                        f"your BVN/bank details.<br><br>"
                        f"<b>Reason:</b> {reason}<br><br>"
                        f"Please update your profile name and try again."
                    )
                    push_data = {
                        "type": "DVA_KYC_FAILED",
                        "reason": reason,
                        "code": "NAME_MISMATCH",
                        "openProfileEditModal": True,
                    }
                else:
                    push_title = "Verification Failed"
                    push_message = (
                        f"Hi {user.first_name}, we could not verify your details for "
                        f"your MyFund deposit account setup. Please update your details and try again."
                    )
                    email_subject = "Action needed: verification failed"
                    email_message = (
                        f"Hi {user.first_name},<br><br>"
                        f"We could not verify your details for your MyFund deposit account setup.<br><br>"
                        f"<b>Reason:</b> {reason}<br><br>"
                        f"Please update your details and try again."
                    )
                    push_data = {
                        "type": "DVA_KYC_FAILED",
                        "reason": reason,
                    }

                send_push_notification(
                    user=user,
                    title=push_title,
                    message=push_message,
                    data=push_data,
                    notif_type="SYSTEM",
                )

                send_generic_email(
                    subject=email_subject,
                    message=email_message,
<<<<<<< HEAD
                    from_email="MyFund <info@myfundmobile.com>",
=======
                    from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                    recipient_list=[user.email],
                )

                return

            case "dedicatedaccount.assign.success":
                data = event["data"]
                customer = data.get("customer", {}) or {}
                dedicated_account = data.get("dedicated_account", {}) or {}

                customer_code = customer.get("customer_code")
                user = CustomUser.objects.filter(
                    paystack_customer_code=customer_code
                ).first()

                if not user:
                    print(f"User not found for DVA assignment success: {customer_code}")
                    return

                user.dva_account_number = dedicated_account.get("account_number")
                user.dva_account_name = dedicated_account.get("account_name")
                user.dva_bank_name = (dedicated_account.get("bank", {}) or {}).get(
                    "name"
                )
                user.dva_account_id = str(dedicated_account.get("id"))
                user.dva_assigned_at = timezone.now()
                user.save(
                    update_fields=[
                        "dva_account_number",
                        "dva_account_name",
                        "dva_bank_name",
                        "dva_account_id",
                        "dva_assigned_at",
                    ]
                )

                print(f"✅ DVA assigned successfully for {user.email}")

                already_notified = False

                if not already_notified:
                    send_push_notification(
                        user=user,
                        title="Deposit Account Ready ✅",
                        message=(
                            f"Hi {user.first_name}, your MyFund deposit account is now ready. "
                            f"You can now fund your QuickSave by bank transfer."
                        ),
                        data={
                            "type": "DVA_READY",
                            "account_number": user.dva_account_number,
                            "bank_name": user.dva_bank_name,
                            "account_name": user.dva_account_name,
                        },
                        notif_type="SYSTEM",
                    )

                    send_generic_email(
                        subject="Your MyFund deposit account is ready ✅",
                        message=(
                            f"Hi {user.first_name},<br><br>"
                            f"Your dedicated MyFund deposit account has been created successfully.<br><br>"
                            f"<b>Bank:</b> {user.dva_bank_name}<br>"
                            f"<b>Account Number:</b> {user.dva_account_number}<br>"
                            f"<b>Account Name:</b> {user.dva_account_name}<br><br>"
                            f"You can now fund your QuickSave by bank transfer."
                        ),
<<<<<<< HEAD
                        from_email="MyFund <info@myfundmobile.com>",
=======
                        from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                        recipient_list=[user.email],
                    )

                return

            case "dedicatedaccount.assign.failed":
                data = event["data"]
                customer = data.get("customer", {}) or {}
                reason = data.get("reason", "Dedicated account assignment failed")

                customer_code = customer.get("customer_code")
                user = CustomUser.objects.filter(
                    paystack_customer_code=customer_code
                ).first()

                if user:
                    print(f"❌ DVA assignment failed for {user.email}: {reason}")

                    send_push_notification(
                        user=user,
                        title="Deposit Account Setup Failed",
                        message=(
                            f"Hi {user.first_name}, we could not complete your "
                            f"MyFund deposit account setup. Please try again later or contact support."
                        ),
                        data={
                            "type": "DVA_ASSIGN_FAILED",
                            "reason": reason,
                        },
                        notif_type="SYSTEM",
                    )

                    send_generic_email(
                        subject="Deposit account setup failed",
                        message=(
                            f"Hi {user.first_name},<br><br>"
                            f"We could not complete your MyFund deposit account setup.<br><br>"
                            f"<b>Reason:</b> {reason}<br><br>"
                            f"Please try again later or contact support."
                        ),
<<<<<<< HEAD
                        from_email="MyFund <info@myfundmobile.com>",
=======
                        from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                        recipient_list=[user.email],
                    )

                    send_generic_email(
                        subject="[Paystack DVA Failed]",
                        message=f"User: {user.email}<br>Reason: {reason}",
<<<<<<< HEAD
                        from_email="MyFund <info@myfundmobile.com>",
                        recipient_list=[
                            "info@myfundmobile.com",
=======
                        from_email="MyFund <info@mg.myfundmobile.com>",
                        recipient_list=[
                            "info@mg.myfundmobile.com",
>>>>>>> staging
                            "sammy@myfundmobile.com",
                        ],
                    )

                return

            case _:
                print(f"Unhandled Paystack event: {event.get('event')}")
                return

    except Exception as e:
        print(f"\nPaystack Webhook(Internal Server Error): {e}\n")

        subject = "Paystack Webhook Error!"
        message = f"Paystack Webhook Internal Server Error: {e}"
<<<<<<< HEAD
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = ["info@myfundmobile.com", "sammy@myfundmobile.com"]
=======
        from_email = "MyFund <info@mg.myfundmobile.com>"
        recipient_list = ["info@mg.myfundmobile.com", "sammy@myfundmobile.com"]
>>>>>>> staging

        send_generic_email(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
        )
        return


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


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from .utils import send_generic_email
import logging

logger = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_email(request):
    """
    Admin sends email via Unlayer modal.
    """
    logger.info(f"📧 API send_email called by user: {request.user.email}")

    try:
        sender = settings.DEFAULT_FROM_EMAIL
        subject = request.data.get("subject", "").strip()
        body = request.data.get("body", "").strip()  # This is the HTML content
        recipients = request.data.get("recipients", [])

        logger.info(
            f"📧 Request data - Subject: '{subject}', Body length: {len(body)}, Recipients: {len(recipients)}"
        )

        # Validation
        if not subject or not body:
            logger.warning("Validation failed: Subject or body missing")
            return Response(
                {"message": "Subject and body are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not recipients or not isinstance(recipients, list):
            logger.warning("Validation failed: Recipients not a list or empty")
            return Response(
                {"message": "Recipients must be a non-empty list."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Clean recipients
        cleaned_recipients = []
        for email in recipients:
            if isinstance(email, str):
                email = email.strip().lower()
                if email:
                    cleaned_recipients.append(email)

        if not cleaned_recipients:
            logger.warning("Validation failed: No valid recipients after cleaning")
            return Response(
                {"message": "No valid recipients provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        logger.info(f"📧 Cleaned recipients: {cleaned_recipients}")

        # Use the smart email sender - FIXED PARAMETER NAME
        logger.info("📧 Calling send_generic_email...")
        result = send_generic_email(
            subject=subject,
            message=body,  # CHANGED FROM 'message' TO ''
            recipient_list=cleaned_recipients,
            from_email=sender,
            use_celery_threshold=0,
        )

        logger.info(f"📧 send_generic_email result: {result}")

        # Handle the result based on status
        if result["status"] == "completed":
            logger.info(f"✅ Email send completed: {result['sent']} sent")
            return Response(
                {
                    "status": "success",
                    "message": f"Email sent successfully to {result['sent']} recipients!",
                    "sent": result["sent"],
                    "total": len(cleaned_recipients),
                    "method": "inline",
                },
                status=status.HTTP_200_OK,
            )

        elif result["status"] == "partial":
            logger.warning(
                f"⚠️ Partial email send: {result['sent']} sent, {result['failed']} failed"
            )
            return Response(
                {
                    "status": "partial",
                    "message": f"Email sent to {result['sent']} recipients, {result['failed']} failed.",
                    "sent": result["sent"],
                    "failed": result["failed"],
                    "total": len(cleaned_recipients),
                    "failed_emails": result.get("failed_emails", []),
                    "method": "inline",
                },
                status=status.HTTP_207_MULTI_STATUS,
            )

        elif result["status"] == "queued":
            logger.info(f"📦 Email queued to Celery: {result['total']} recipients")
            return Response(
                {
                    "status": "queued",
                    "message": f"Emails queued for {result['total']} recipients. Processing in background.",
                    "total": result["total"],
                    "method": "celery_batch",
                },
                status=status.HTTP_202_ACCEPTED,
            )

        elif result["status"] == "error":
            logger.error(
                f"❌ Email send error: {result.get('reason', 'Unknown error')}"
            )
            return Response(
                {
                    "status": "error",
                    "message": result.get("reason", "Failed to process email request"),
                    "details": result,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        else:
            logger.error(f"❌ Unknown status from send_generic_email: {result}")
            return Response(
                {
                    "status": "error",
                    "message": "Unexpected response from email service",
                    "details": result,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    except Exception as e:
        logger.error(f"❌ UNHANDLED EXCEPTION in send_email API: {e}", exc_info=True)
        return Response(
            {
                "status": "error",
                "message": f"Internal server error: {str(e)}",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        template = EmailTemplate.objects.create(
            title=title,
            design_body=design_body,
            design_html=design_html,
            last_update=last_update,
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


@api_view(["GET"])
def get_template(request, template_id):
    try:
        template = EmailTemplate.objects.get(id=template_id)
        serializer = EmailTemplateSerializer(template)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except EmailTemplate.DoesNotExist:
        return Response(
            {"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND
        )


@csrf_exempt
@api_view(["PUT"])
def update_template(request, template_id):
    try:
        template = EmailTemplate.objects.get(id=template_id)

        template.title = request.data.get("title", template.title)
        template.design_body = request.data.get("designBody", template.design_body)
        template.design_html = request.data.get("designHTML", template.design_html)
        template.last_update = request.data.get("lastUpdate", template.last_update)

        template.save()

        return Response(
            EmailTemplateSerializer(template).data,
            status=status.HTTP_200_OK,
        )

    except EmailTemplate.DoesNotExist:
        return Response({"error": "Template not found"}, status=404)


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
from dateutil.relativedelta import relativedelta

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

        # Step 4: Validate minimum_contribution against property price
        try:
            minimum_contribution = float(data["minimum_contribution"])
        except (ValueError, TypeError):
            return JsonResponse(
                {"error": "Invalid minimum_contribution. Must be a valid number."},
                status=400,
            )

        if minimum_contribution > property_obj.price:
            return JsonResponse(
                {
                    "error": f"Minimum contribution (₦{minimum_contribution:,.2f}) cannot exceed the property price (₦{property_obj.price:,.2f})."
                },
                status=400,
            )

        if minimum_contribution <= 0:
            return JsonResponse(
                {"error": "Minimum contribution must be greater than zero."},
                status=400,
            )

        # Step 5: Check property availability
        if property_obj.units_available < 1:
            return JsonResponse(
                {"error": "The group limit for this property has already been reached"},
                status=400,
            )

        # Step 6: Handle deadline logic
        now = timezone.now()

        # Max deadline: exactly 3 months from now
        max_deadline = now + relativedelta(months=3)

        # Parse user-provided deadline (if any)
        if "deadline" in data and data["deadline"]:
            try:
                # Parse string to naive datetime first
                deadline_naive = datetime.strptime(data["deadline"], "%Y-%m-%d")
                # Make it timezone-aware
                deadline = timezone.make_aware(deadline_naive)
            except ValueError:
                return JsonResponse(
                    {"error": "Invalid deadline format. Use YYYY-MM-DD."}, status=400
                )

            if deadline < now:
                return JsonResponse(
                    {"error": "Deadline cannot be in the past."}, status=400
                )

            if deadline.date() < max_deadline.date():
                return JsonResponse(
                    {"error": "Deadline must be at least 3 months from today."},
                    status=400,
                )
        else:
            # Default deadline to exactly 3 months from now
            deadline = max_deadline

        # Step 7: Create the group
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

        # Step 8: Handle invited users (if group is private)
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

<<<<<<< HEAD
                        from_email = "MyFund <info@myfundmobile.com>"
=======
                        from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging
                        recipient_list = [user.email for user in invited_users]

                        try:
                            send_generic_email(
                                subject=subject,
                                message=message,
                                from_email=from_email,
                                recipient_list=recipient_list,
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

<<<<<<< HEAD
=======
        # Step 8b: Notify test users that a new public GroupBuy just went
        # live. Scoped to a hardcoded test list for now (not all users) -
        # a handful of Expo push calls is cheap regardless, but we only
        # want this actually landing on real devices during testing.
        if group_type == "public":
            TEST_NOTIFY_EMAILS = [
                "tolulopeahmed@gmail.com",
                "valueplusrecords@gmail.com",
                "valuepluspublishing@gmail.com",
            ]
            try:
                notify_users = get_user_model().objects.filter(
                    email__in=TEST_NOTIFY_EMAILS
                )
                for notify_user in notify_users:
                    send_push_notification(
                        user=notify_user,
                        title="New GroupBuy is Live! 🏠",
                        message=(
                            f"A new GroupBuy just opened for {property_obj.name}. "
                            f"Join now to start owning a share of this property."
                        ),
                        data={
                            "type": "groupbuy_live",
                            "group_id": str(group.id),
                            "property_id": str(property_obj.id),
                        },
                        notif_type="GROUP",
                    )
            except Exception as e:
                logger.warning(f"GroupBuy-live push failed: {e}")

>>>>>>> staging
        # Step 9: Return the serialized group
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


<<<<<<< HEAD
=======
# GET /groupbuy/detail/:groupId - Retrieve a single group buy by its own id
# (used e.g. by the mobile app's groupbuy invite deep link, which only has the
# Group.id, not the property_id that get_groupbuy_by_property needs)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_groupbuy_by_id(request, group_id):
    try:
        group_uuid = uuid.UUID(str(group_id))
    except ValueError:
        return Response(
            {"message": "Invalid group ID. It must be a valid UUID."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        group = Group.objects.get(id=group_uuid)
    except Group.DoesNotExist:
        return Response(
            {"message": "Group not found."}, status=status.HTTP_404_NOT_FOUND
        )

    return Response(GroupSerializer(group).data)


>>>>>>> staging
# GET /groupbuys/ - Retrieve group buy details for a specific property
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_active_public_groupbuys(request):
    try:
<<<<<<< HEAD
        groups = Group.objects.filter(
            status__in=["Active", "active"], group_type="public"
=======
        # Completed groups are included too (not just active) so a
        # fully-funded property still shows "Fully Funded" on the Properties
        # tab for everyone, instead of silently vanishing once its
        # units_available hits 0.
        groups = Group.objects.filter(
            status__in=["Active", "active", "Completed", "completed"],
            group_type="public",
>>>>>>> staging
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

<<<<<<< HEAD
            from_email = "MyFund <info@myfundmobile.com>"
=======
            from_email = "MyFund <info@mg.myfundmobile.com>"
>>>>>>> staging

            recipient_list = [invited_user.email for invited_user in invited_users]
            try:
                send_generic_email(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=recipient_list,
                )
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
            {"message": "GroupBuy not found."}, status=status.HTTP_404_NOT_FOUND
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

        # 3. Get reason from request data
        reason = request.data.get("reason")
        additional_details = request.data.get("additional_details", "")

        # Validate reason
        valid_reasons = [choice[0] for choice in GroupDeparture.REASON_CHOICES]
        if not reason or reason not in valid_reasons:
            return Response(
                {
                    "message": "Please provide a valid reason for leaving.",
                    "valid_reasons": valid_reasons,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 4. Get all confirmed contributions
        contributions = Contribution.objects.filter(
            group=group, user=user, payment_status="Confirmed"
        )

<<<<<<< HEAD
        total_refund = Decimal(0)
=======
        # Voluntary exit costs a 1% service charge - only 99% is returned to
        # the user - to discourage casually joining and exiting GroupBuys.
        # (Expiry refunds, in expire_overdue_groupbuys, apply the same rate
        # for the same reason; this is separate since exit is user-initiated
        # while expiry is a deadline-driven sweep.)
        from decimal import ROUND_HALF_UP

        SERVICE_CHARGE_RATE = Decimal("0.01")

        total_refund = Decimal(0)  # gross amount removed from the group's total_raised
        total_net_refund = Decimal(0)  # what the user actually receives, net of charge
        total_service_charge = Decimal(0)
>>>>>>> staging

        for contribution in contributions:
            amount = contribution.amount
            source = contribution.source
<<<<<<< HEAD

            # Refund to correct account
            if source == "Savings":
                user.savings += amount
            elif source == "Investment":
                user.investment += amount
            elif source == "Wallet":
                user.wallet += amount
=======
            service_charge = (amount * SERVICE_CHARGE_RATE).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            net_amount = amount - service_charge

            # Refund to the correct account and log it as a Transaction, same
            # as the debit created when the contribution was made - otherwise
            # the refund silently changes the balance with no record in the
            # user's transaction history / Notifications feed.
            create_transaction(
                user=user,
                amount=net_amount,
                transaction_type="credit",
                credited_to=source.upper(),
                status="confirmed",
                service_charge=service_charge,
                description=(
                    f"GroupBuy exit refund - {group.property.name} "
                    f"(1% service charge of ₦{service_charge} applied)"
                ),
            )
>>>>>>> staging

            # Mark contribution as refunded
            contribution.payment_status = "Refunded"
            contribution.save()

            total_refund += amount
<<<<<<< HEAD

        user.save()

        # 5. Update group total_raised
=======
            total_net_refund += net_amount
            total_service_charge += service_charge

        # 5. Update group total_raised (removes the full contributed amount,
        # not just the net-of-charge refund - the 1% is a penalty on the
        # user, it doesn't stay counted toward the group's funding goal)
>>>>>>> staging
        group.total_raised -= total_refund
        group.save()

        # 6. Remove user from contributors list
        group.contributors.remove(user)

        # 7. Remove or update GroupOwnership
        GroupOwnership.objects.filter(group=group, user=user).delete()

        # 8. Record the departure with reason
        GroupDeparture.objects.create(
            group=group,
            user=user,
            reason=reason,
            additional_details=additional_details,
<<<<<<< HEAD
            refunded_amount=total_refund,
        )

        return Response(
            {
                "message": "Successfully left the group. Contributions refunded.",
                "refunded_amount": float(total_refund),
=======
            refunded_amount=total_net_refund,
        )

        # 9. Starting a GroupBuy is what activates it; once the last
        # contributor exits, it shouldn't keep showing as active with 0
        # participants. Deactivate it and release the unit so the property
        # can be started fresh - same as an expired GroupBuy.
        if not group.contributors.exists() and group.status.lower() == "active":
            group.status = "failed"
            group.save()

            property_obj = group.property
            property_obj.units_available += 1
            property_obj.save()

        return Response(
            {
                "message": "Successfully left the group. Contributions refunded (1% service charge applied).",
                "refunded_amount": float(total_net_refund),
                "service_charge": float(total_service_charge),
>>>>>>> staging
            },
            status=status.HTTP_200_OK,
        )

    except Group.DoesNotExist:
        return Response(
            {"message": "GroupBuy not found."},
            status=status.HTTP_404_NOT_FOUND,
        )


# GET /users/:userId/groups - Retrieve all groups a user has joined
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_groupbuys(request):
    try:
        # Get the current user
        user = request.user

<<<<<<< HEAD
        # Get all groups the user created or contributed to
        groups = Group.objects.filter(
            Q(created_by=user) | Q(contributors=user)
        ).distinct()
=======
        # "My GroupBuys" = groups the user is currently a contributor of.
        # Deliberately NOT keyed off created_by too: the creator is always
        # added as a contributor at creation time (StartGroupBuyModal
        # immediately contributes after creating the group), so the only
        # time this would diverge is after the creator exits via
        # leave_groupbuy - and at that point the group should disappear
        # from their list, not linger just because they started it.
        groups = Group.objects.filter(contributors=user).distinct()
>>>>>>> staging

        groups_list = list(groups)

        # Serialize the group data
        serializer = GroupSerializer(groups_list, many=True)

        # Return the serialized data with a 200 OK status
        return Response(serializer.data, status=status.HTTP_200_OK)

    except get_user_model().DoesNotExist:
        return Response(
            {"message": "User not found."}, status=status.HTTP_404_NOT_FOUND
        )


<<<<<<< HEAD
=======
# GET /user/groupbuy/invited/ - Groups the current user has been invited to
# but hasn't joined yet. Exists so private-group invites are discoverable
# in-app, since the email invite's deep link isn't reliably wired up yet
# (no iOS/Android native link registration).
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_invited_groupbuys(request):
    try:
        user = request.user

        groups = Group.objects.filter(
            invited_users=user,
            status__in=["Active", "active"],
        ).exclude(contributors=user).distinct()

        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response(
            {"message": f"An error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# POST /admin/groupbuy/expire-sweep/ - Staff-only manual trigger for the
# overdue-GroupBuy refund sweep (same logic as `manage.py expire_groupbuys`
# / the Celery task). Exists so this can be tested/run without shell access
# to the deployment - pass {"dry_run": true} to preview without saving.
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def trigger_groupbuy_expiry_sweep(request):
    if not request.user.is_staff:
        return Response({"message": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

    from .utils import expire_overdue_groupbuys

    dry_run = bool(request.data.get("dry_run", False))
    result = expire_overdue_groupbuys(dry_run=dry_run)

    return Response(
        {
            "dry_run": dry_run,
            "expired_count": result["expired_count"],
            "total_refunded": float(result["total_refunded"]),
            "total_service_charge": float(result["total_service_charge"]),
            "groups": [
                {
                    "group_id": g["group_id"],
                    "property": g["property"],
                    "contributors": [
                        {
                            "email": c["email"],
                            "amount": float(c["amount"]),
                            "service_charge": float(c["service_charge"]),
                            "refund_amount": float(c["refund_amount"]),
                            "source": c["source"],
                        }
                        for c in g["contributors"]
                    ],
                }
                for g in result["groups"]
            ],
        },
        status=status.HTTP_200_OK,
    )


>>>>>>> staging
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

<<<<<<< HEAD
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
=======
        # 8. Cap contribution at the remaining amount needed (overfunding guard)
        total_after = group.total_raised + amount
        excess_amount = max(total_after - group.goal_amount, Decimal("0.00"))
        if excess_amount > 0:
            amount -= excess_amount

        # 9. Deduct the (possibly capped) amount and log it as a Transaction
        create_transaction(
            user=user,
            amount=amount,
            transaction_type="debit",
            source=source.upper(),
            status="confirmed",
            description=f"GroupBuy contribution to {group.property.name}",
        )
>>>>>>> staging

        # 10. Create contribution
        contribution = Contribution.objects.create(
            group=group,
            user=user,
            amount=amount,
            payment_status="Confirmed",
            source=source,
        )

<<<<<<< HEAD
        # 11. Update group total raised
        group.total_raised += amount
=======
        # 11. Update group total raised, and flip it to completed the moment
        # it's fully funded - otherwise it stays "active" forever even though
        # step 7 already blocks further contributions once the goal is hit,
        # which left the property showing as still-joinable indefinitely.
        group.total_raised += amount
        if group.total_raised >= group.goal_amount:
            group.status = "completed"
>>>>>>> staging
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
<<<<<<< HEAD
=======
            # "Date joined" = their first confirmed contribution to this
            # group - GroupOwnership itself has no timestamp of its own.
            first_contribution = (
                Contribution.objects.filter(
                    group=group, user=user, payment_status="Confirmed"
                )
                .order_by("created_at")
                .first()
            )
            date_joined = first_contribution.created_at if first_contribution else None

>>>>>>> staging
            contributions_list.append(
                {
                    "user_id": user.id,
                    "email": user.email,
<<<<<<< HEAD
=======
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "profile_picture": user.profile_picture,
>>>>>>> staging
                    "total_contributed": float(ownership.total_contributed),
                    "ownership_percentage": round(
                        float(ownership.ownership_percentage), 2
                    ),
<<<<<<< HEAD
                }
            )

=======
                    "date_joined": date_joined.isoformat() if date_joined else None,
                    "_date_joined_sort": date_joined,
                }
            )

        # Ranked by ownership % (highest first); ties broken by whoever
        # joined earliest.
        contributions_list.sort(
            key=lambda c: (
                -c["ownership_percentage"],
                c["_date_joined_sort"] or timezone.now(),
            )
        )
        for item in contributions_list:
            del item["_date_joined_sort"]

>>>>>>> staging
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


<<<<<<< HEAD
=======
# GET /user/groupbuy/income-history - Fetch all GroupBuy income payouts the
# currently authenticated user has received, most recent first.
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_groupbuy_income_history(request):
    from .models import GroupIncomeDistribution
    from .serializers import GroupIncomeDistributionSerializer

    distributions = GroupIncomeDistribution.objects.filter(
        user=request.user
    ).order_by("-created_at")
    serializer = GroupIncomeDistributionSerializer(distributions, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


>>>>>>> staging
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
    from .utils import create_transaction

    try:
        user = request.user

        amount = request.data.get("amount")
        source = request.data.get("source")

        if source:
            source = source.capitalize()
        else:
            return Response(
                {"message": "Source is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not amount:
            return Response(
                {"message": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        accepted_sources = ["Savings", "Wallet"]
        if source not in accepted_sources:
            return Response(
                {"message": "Invalid source. Accepted values are: Savings, Wallet."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            deposit_amount = Decimal(amount)
        except (ValueError, InvalidOperation):
            return Response(
                {"error": "Invalid deposit amount format."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if deposit_amount <= 0:
            return Response(
                {"error": "Deposit amount must be greater than zero."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            goal = SavingsGoal.objects.get(id=id)
        except SavingsGoal.DoesNotExist:
            return Response(
                {"error": "Target savings not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        remaining_balance = goal.target_amount - goal.saved_amount
        if deposit_amount > remaining_balance:
            return Response(
                {
                    "error": f"Deposit exceeds remaining goal balance ({remaining_balance})."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 🔥 SINGLE ATOMIC BLOCK
        with transaction.atomic():

            # 1️⃣ Debit source
            if source == "Savings":
                if user.savings < deposit_amount:
                    return Response(
                        {"error": "Insufficient savings balance."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                create_transaction(
                    user=user,
                    amount=deposit_amount,
                    transaction_type="debit",
                    source="SAVINGS",
                    description=f"Transfer to Target Savings ({goal.name})",
                )

            elif source == "Wallet":
                if user.wallet < deposit_amount:
                    return Response(
                        {"error": "Insufficient wallet balance."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                create_transaction(
                    user=user,
                    amount=deposit_amount,
                    transaction_type="debit",
                    source="WALLET",
                    description=f"Transfer to Target Savings ({goal.name})",
                )

            # 2️⃣ Credit target savings (goal is NOT wallet/savings/investment field)
            goal.saved_amount += deposit_amount
            goal.save(update_fields=["saved_amount"])

            # 3️⃣ Record mirror credit transaction for tracking (optional but correct UX)
            create_transaction(
                user=user,
                amount=deposit_amount,
                transaction_type="credit",
                credited_to="SAVINGS",
                description=f"Target Savings Deposit ({goal.name})",
            )

        # 📧 Email
        send_generic_email(
            subject=f"Deposit to Target Savings ({goal.name}) Successful!",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Your deposit of ₦{deposit_amount:,.2f} has been successfully added to "
                f"your Target Savings ({goal.name}).<br><br>"
                f"Keep going — you're getting closer to your goal. 🌟"
            ),
<<<<<<< HEAD
            from_email="MyFund <info@myfundmobile.com>",
=======
            from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
            recipient_list=[user.email],
        )

        return Response(
            {
                "message": f"₦{deposit_amount:,.2f} added successfully.",
                "remaining_balance": float(goal.target_amount - goal.saved_amount),
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
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

        amount_raw = data.get("amount")
        target_bank_account_id = data.get("target_bank_account_id")

        if not amount_raw:
            return Response(
                {"error": "'amount' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not target_bank_account_id:
            return Response(
                {"error": "'target_bank_account_id' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            amount = Decimal(str(amount_raw))
        except (InvalidOperation, TypeError, ValueError):
            return Response(
                {"error": "Invalid withdrawal amount."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if amount <= 0:
            return Response(
                {"error": "Withdrawal amount must be positive."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            goal = SavingsGoal.objects.get(id=id, user=user)
        except SavingsGoal.DoesNotExist:
            return Response(
                {"error": "Savings goal not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            target_bank_account = BankAccount.objects.get(
                id=target_bank_account_id,
                user=user,
            )
        except BankAccount.DoesNotExist:
            return Response(
                {"error": "Target bank account not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if goal.target_amount <= 0:
            return Response(
                {"error": "Invalid target savings goal configuration."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        completion_percentage = (goal.saved_amount / goal.target_amount) * 100
        if completion_percentage < 80:
            return Response(
                {"error": "You must reach at least 80% of your goal."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if amount > goal.saved_amount:
            return Response(
                {"error": "Insufficient funds."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        penalty = Decimal("0.00")

        if goal.deadline:
            goal_deadline_datetime = datetime.combine(
                goal.deadline,
                datetime.min.time(),
            )
            if datetime.now() < goal_deadline_datetime:
                penalty = Decimal(str(calculate_penalty(amount)))

        net_amount = amount - penalty

        if net_amount <= 0:
            return Response(
                {"error": "Withdrawal amount is too small after penalty."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reference_code = generate_reference()
        transaction_id = f"withdrawal-{reference_code}"

        with transaction.atomic():
            goal = SavingsGoal.objects.select_for_update().get(id=id, user=user)

            if amount > goal.saved_amount:
                return Response(
                    {"error": "Insufficient funds."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            previous_balance = goal.saved_amount
            new_balance = goal.saved_amount - amount

            goal.saved_amount = new_balance
            goal.save(update_fields=["saved_amount"])

            tx = Transaction.objects.create(
                user=user,
                transaction_type="debit",
                status="pending",
                amount=net_amount,
                service_charge=penalty,
                total_amount=amount,
                source="SAVINGS",
                description=f"Target Savings Withdrawal ({goal.name})",
                transaction_id=transaction_id,
                balance_before=previous_balance,
                balance_after=new_balance,
            )

        if amount < 500000:
            paystack_response = make_withdrawal_through_paystack(
                user,
                target_bank_account,
                net_amount,
                transaction_id,
            )

            if paystack_response.get("status"):
                tx.status = "confirmed"
                tx.description = f"Target Savings Withdrawal ({goal.name})"
                tx.save(update_fields=["status", "description"])

                send_generic_email(
                    subject="Withdrawal Successful!",
                    message=(
                        f"Hi {user.first_name},<br><br>"
                        f"₦{net_amount:,.2f} has been sent to your bank account successfully."
                    ),
<<<<<<< HEAD
                    from_email="MyFund <info@myfundmobile.com>",
=======
                    from_email="MyFund <info@mg.myfundmobile.com>",
>>>>>>> staging
                    recipient_list=[user.email],
                )

                return Response(
                    {
                        "success": True,
                        "message": paystack_response.get("message"),
                        "transaction_id": transaction_id,
                        "updated_balance": float(new_balance),
                    },
                    status=status.HTTP_200_OK,
                )

            tx.status = "failed"
            tx.description = f"Target Savings Withdrawal ({goal.name}) (Failed)"
            tx.save(update_fields=["status", "description"])

            with transaction.atomic():
                goal = SavingsGoal.objects.select_for_update().get(id=id, user=user)
                goal.saved_amount = goal.saved_amount + amount
                goal.save(update_fields=["saved_amount"])

            return Response(
                {"error": "Withdrawal failed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        WithdrawalsRequestToAdmin.objects.create(
            user=user,
            amount=net_amount,
            total_amount=amount,
            charge_amount=penalty,
            transaction_id=transaction_id,
            source_account="savings",
            target_bank=target_bank_account.bank_name,
            target_account_number=target_bank_account.account_number,
            withdrawal_type="immediate",
            is_approved=False,
        )

        send_push_notification(
            user=user,
            title="Withdrawal Processing...",
            message="Your withdrawal is being processed.",
            data={"transaction_id": transaction_id},
            notif_type="PENDING",
        )

        return Response(
            {
                "success": True,
                "message": "Withdrawal submitted for admin processing.",
                "transaction_id": transaction_id,
                "updated_balance": float(new_balance),
            },
            status=status.HTTP_200_OK,
        )

    except SavingsGoal.DoesNotExist:
        return Response(
            {"error": "Savings goal not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    except ValueError:
        return Response(
            {"error": "Invalid withdrawal amount."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as e:
        return Response(
            {"error": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Function to calculate penalties if the user withdraws early
def calculate_penalty(withdrawal_amount):
    penalty_percentage = Decimal("0.10")
    return Decimal(str(withdrawal_amount)) * penalty_percentage


# GET /savings/user/{user_id} - Fetch all savings goals of a user
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def fetch_user_savings_goals(request, user_id):
    try:
        goals = SavingsGoal.objects.filter(user_id=user_id)
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
        goal = SavingsGoal.objects.get(id=id)

        if goal.saved_amount > 0:
            return Response(
                {"error": "Cannot delete goal with active funds."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        goal.delete()
        return Response(
            {"message": "Savings goal deleted successfully."},
            status=status.HTTP_200_OK,
        )

    except SavingsGoal.DoesNotExist:
        return Response(
            {"error": "Savings goal not found."},
            status=status.HTTP_404_NOT_FOUND,
        )


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.utils import timezone
<<<<<<< HEAD
from django.conf import settings
=======
>>>>>>> staging
from django.db.models import Sum
from decimal import Decimal
import uuid
from .models import TargetSavings, Transaction, TargetSavingsCompletion
from .serializers import TargetSavingsSerializer
from .utils import send_generic_email, send_push_notification
from .permissions import IsNotBannedUser  # Add this import


class TargetSavingsListCreate(ListCreateAPIView):
    serializer_class = TargetSavingsSerializer
    permission_classes = [IsAuthenticated, IsNotBannedUser]

    def perform_create(self, serializer):
        logger = logging.getLogger(__name__)

        with transaction.atomic():
            user = CustomUser.objects.select_for_update().get(id=self.request.user.id)

            if user.is_banned:
                raise ValidationError(
                    {"detail": "Account is banned. Cannot create target savings."}
                )

            if not user.is_active:
                raise ValidationError(
                    {"detail": "Account is inactive. Cannot create target savings."}
                )

            data = serializer.validated_data
            frequency = data["frequency"].upper()

            if frequency not in dict(TargetSavings.FREQUENCY_CHOICES):
                raise ValidationError({"detail": "Invalid frequency"})

            amount = Decimal(str(data["monthly_payment"]))
            funding_source = data["funding_source"].upper()

            if funding_source not in ["SAVINGS", "INVESTMENT", "WALLET"]:
                raise ValidationError({"detail": "Invalid funding source"})

            balance = getattr(user, funding_source.lower())

            if balance < amount:
                raise ValidationError(
                    {"detail": "Insufficient confirmed balance to create target"}
                )

            # 1) Debit the user's real balance through ledger helper
            create_transaction(
                user=user,
                amount=amount,
                transaction_type="debit",
                source=funding_source,
                description=f"Target Savings Initial Funding ({data['name']})",
                service_charge=0,
                reference=f"TS-INIT-{uuid.uuid4().hex[:16]}",
            )

            # 2) Create the target and record the funded amount on the target itself
            instance = serializer.save(
                user=user,
                current_amount=amount,
                start_date=timezone.now().date(),
            )

            instance.next_deduction = instance.calculate_next_deduction_time()
            instance.save(update_fields=["next_deduction"])

            # 3) Optional target-linked mirror record for history on the target itself
            Transaction.objects.create(
                user=user,
                transaction_type="credit",
                status="confirmed",
                amount=amount,
                service_charge=0,
                total_amount=amount,
                target_savings=instance,
                source=funding_source,
                description=f"Target Savings Created ({instance.name})",
                transaction_id=f"[{instance.id}]-{uuid.uuid4().hex[:12]}_INITIAL",
            )

        progress = (instance.current_amount / instance.target_amount) * 100
        progress_str = f"{progress:.1f}%"

        try:
            subject = f"{instance.name} Target Savings is LIVE! 🚀"

            message = (
                f"Hi {user.first_name},\n\n"
                f'Your target savings plan "{instance.name}" has been successfully created.\n\n'
                f"Initial Amount: ₦{amount:,.2f}\n"
                f"Funding Frequency: {frequency.lower()}\n"
                f"Progress: {progress_str}\n\n"
                f"Consistency is key — you’re on the right path 💪"
            )

            send_generic_email(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                template="email/email.html",
            )

        except Exception as e:
            logger.error(f"Target savings email failed for {user.email}: {str(e)}")

        send_push_notification(
            user,
            title=f"🎉 {instance.name} Plan Created!",
            message=(
                f"Your {instance.name} Target Savings plan is live with ₦{amount:,.2f}. "
                f"You're {progress_str} closer to your goal 🚀"
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

<<<<<<< HEAD
=======
    def destroy(self, request, *args, **kwargs):
        # 🔴 SECURITY: a raw DELETE here would wipe out current_amount with
        # no refund and no Transaction record - the mobile app never calls
        # this (it uses POST .../cancel/, which refunds 99% through
        # create_transaction()). Force every cancellation through that
        # money-safe path instead of allowing silent fund loss here.
        return Response(
            {
                "detail": "Use POST /target-savings/<id>/cancel/ to close a target savings plan."
            },
            status=405,
        )

>>>>>>> staging

from django.db import transaction
from decimal import Decimal


from django.db import transaction
from decimal import Decimal


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def cancel_target_saving(request, pk):
    idempotency_key = request.headers.get("X-Idempotency-Key")

    if not idempotency_key:
        return Response({"detail": "Missing Idempotency Key"}, status=400)

    with transaction.atomic():
        target = TargetSavings.objects.select_for_update().get(pk=pk, user=request.user)
        user = CustomUser.objects.select_for_update().get(id=request.user.id)

        if Transaction.objects.filter(idempotency_key=idempotency_key).exists():
            return Response({"detail": "Cancellation already processed"}, status=200)

        if target.is_cancelled or not target.is_active:
            return Response({"detail": "Target already cancelled"}, status=400)

        refund_amount = (target.current_amount * Decimal("0.99")).quantize(
            Decimal("0.01")
        )
        charge = target.current_amount - refund_amount

        # Lock target state first
        target.current_amount = Decimal("0.00")
        target.is_active = False
        target.is_cancelled = True
        target.cancellation_charge = charge
        target.save(
            update_fields=[
                "current_amount",
                "is_active",
                "is_cancelled",
                "cancellation_charge",
            ]
        )

        # Refund to the original funding bucket through helper
        if target.funding_source == "SAVINGS":
            refund_tx = create_transaction(
                user=user,
                amount=refund_amount,
                transaction_type="credit",
                credited_to="SAVINGS",
                description=f"{target.name} Cancelled",
                service_charge=0,
                reference=idempotency_key,
            )
        elif target.funding_source == "INVESTMENT":
            refund_tx = create_transaction(
                user=user,
                amount=refund_amount,
                transaction_type="credit",
                credited_to="INVESTMENT",
                description=f"{target.name} Cancelled",
                service_charge=0,
                reference=idempotency_key,
            )
        elif target.funding_source == "WALLET":
            refund_tx = create_transaction(
                user=user,
                amount=refund_amount,
                transaction_type="credit",
                credited_to="WALLET",
                description=f"{target.name} Cancelled",
                service_charge=0,
                reference=idempotency_key,
            )
        else:
            raise ValidationError({"detail": "Invalid target funding source"})

        # Attach idempotency + target linkage to the created ledger row
        refund_tx.idempotency_key = idempotency_key
        refund_tx.target_savings = target
        refund_tx.service_charge = charge
        refund_tx.total_amount = refund_amount
        refund_tx.save(
            update_fields=[
                "idempotency_key",
                "target_savings",
                "service_charge",
                "total_amount",
            ]
        )

        TargetSavingsCompletion.objects.update_or_create(
            user=user,
            target_savings=target,
            defaults={
                "completed_amount": refund_amount,
                "bonus_amount": 0,
                "total_amount": refund_amount,
                "completed_date": timezone.now().date(),
                "was_on_time": False,
                "status": "CANCELLED",
            },
        )

    return Response(
        {
            "status": "cancelled",
            "refunded": float(refund_amount),
            "charge": float(charge),
        },
        status=200,
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


<<<<<<< HEAD
=======
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def remove_expo_push_token(request):
    """Counterpart to save_expo_push_token - called on logout. The mobile
    app (utils/PushNotififaction.js removePushToken) has been posting here
    since it was built, but this route was never registered, so logout was
    silently 404ing and stale tokens were never cleaned up.
    """
    user = request.user
    token = request.data.get("expo_push_token")

    if not token:
        return Response({"error": "No token provided"}, status=400)

    user.expo_push_tokens = [
        entry for entry in user.expo_push_tokens if entry.get("token") != token
    ]
    user.save(update_fields=["expo_push_tokens"])
    return Response({"message": "Token removed"})


>>>>>>> staging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Count, Q
<<<<<<< HEAD
from django.core.mail import send_mail
=======
>>>>>>> staging
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

    def get_user_monthly_attendance_count(self, user_obj, start_of_month):
        current_month = start_of_month.strftime("%Y-%m")
        return AmbassadorAttendanceSubmission.objects.filter(
            user=user_obj,
            month=current_month,
        ).count()

    def send_rank_notification(self, user, old_rank, new_rank):
<<<<<<< HEAD
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
=======
        """Push for all rank changes. Email only for Top 3 entry or reaching #1."""

        if new_rank < old_rank:
>>>>>>> staging
            push_title = f"🎉 Rank Improved! Now #{new_rank}"
            push_message = (
                f"Hi {user.first_name}, you moved up to #{new_rank} (from #{old_rank}). "
                "Keep referring to earn more referral rewards!"
            )
        else:
<<<<<<< HEAD
            subject = f"📉 Your MyFund Rank Changed to #{new_rank}"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"Your referral rank changed from #{old_rank} to #{new_rank}. "
                "Share your referral link to move back up and earn more referral bonus!<br><br>"
                "Thank you for using MyFund.<br><br>"
            )
=======
>>>>>>> staging
            push_title = f"📉 Referral Rank Changed to #{new_rank}"
            push_message = (
                f"Hi {user.first_name}, your rank is now #{new_rank} (was #{old_rank}). "
                "Refer more friends to climb higher and earn more referral bonus!"
            )

<<<<<<< HEAD
        send_generic_email(
            subject=subject,
            message=message,
            from_email="MyFund <info@myfundmobile.com>",
            recipient_list=[user.email],
        )

=======
        # Always send push
>>>>>>> staging
        send_push_notification(
            user=user,
            title=push_title,
            message=push_message,
            data={"old_rank": old_rank, "new_rank": new_rank, "type": "ReferralRank"},
            notif_type="SYSTEM",
        )

<<<<<<< HEAD
=======
        # Email only for meaningful milestones
        just_reached_number1 = new_rank == 1 and old_rank != 1
        just_entered_top3 = new_rank <= 3 and old_rank > 3

        if just_reached_number1:
            subject = f"🏆 You're #1 on MyFund This Month!"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"You've hit the top! You're now <strong>#1</strong> on the MyFund referral leaderboard. "
                "This is a huge deal — keep it up and finish the month strong!<br><br>"
                "Thank you for using MyFund.<br><br>"
                "MyFund"
            )
            send_generic_email(
                subject=subject,
                message=message,
                from_email="MyFund <info@mg.myfundmobile.com>",
                recipient_list=[user.email],
            )

        elif just_entered_top3:
            subject = f"🎉 Congrats! You're Now #{new_rank} on MyFund!"
            message = (
                f"Hi {user.first_name},<br><br>"
                f"Great news! You've entered the <strong>Top 3</strong> — your referral rank improved from #{old_rank} to #{new_rank}. "
                "Keep referring friends to stay in the top and earn more referral rewards!<br><br>"
                "Thank you for using MyFund.<br><br>"
                "MyFund"
            )
            send_generic_email(
                subject=subject,
                message=message,
                from_email="MyFund <info@mg.myfundmobile.com>",
                recipient_list=[user.email],
            )

>>>>>>> staging
    def get(self, request):
        user = request.user
        now = timezone.now()
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

<<<<<<< HEAD
        # If logged-in user is ambassador, show only ambassador rankings
        ambassador_view = getattr(user, "is_ambassador", False)

        # Get referral performance for the month
=======
        ambassador_view = getattr(user, "is_ambassador", False)

>>>>>>> staging
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

<<<<<<< HEAD
            # If ambassador is viewing, only include ambassadors
=======
>>>>>>> staging
            if ambassador_view and not getattr(ref_user, "is_ambassador", False):
                continue

            top_users.append(
                {
                    "id": ref_user.id,
                    "first_name": ref_user.first_name,
                    "last_name": ref_user.last_name,
                    "email": ref_user.email,
<<<<<<< HEAD
=======
                    "phone_number": ref_user.phone_number or "",
>>>>>>> staging
                    "profile_picture": self.get_profile_pic_url(ref_user),
                    "monthly_signups": stat["monthly_signups"],
                    "monthly_confirmed": stat["monthly_confirmed"],
                    "monthly_attendance": self.get_user_monthly_attendance_count(
                        ref_user, start_of_month
                    ),
                    "is_hired_referrer": ref_user.is_hired_referrer,
                    "is_ambassador": getattr(ref_user, "is_ambassador", False),
                }
            )

<<<<<<< HEAD
        # Sort final filtered list
        top_users.sort(key=lambda x: (-x["monthly_confirmed"], -x["monthly_signups"]))

        # Update rank only based on the correct leaderboard being viewed
=======
        top_users.sort(key=lambda x: (-x["monthly_confirmed"], -x["monthly_signups"]))

>>>>>>> staging
        rank_changes = {}
        for index, user_data in enumerate(top_users):
            ranked_user = CustomUser.objects.get(id=user_data["id"])
            new_rank = index + 1
            old_rank = ranked_user.last_referral_rank or 0

            if old_rank != new_rank:
                rank_changes[ranked_user] = (old_rank, new_rank)
                ranked_user.last_referral_rank = new_rank
                ranked_user.save(update_fields=["last_referral_rank"])

        for user_obj, (old_rank, new_rank) in rank_changes.items():
            self.send_rank_notification(user_obj, old_rank, new_rank)

<<<<<<< HEAD
        # Current user monthly stats
=======
>>>>>>> staging
        my_signups = CustomUser.objects.filter(
            referral=user,
            date_joined__gte=start_of_month,
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
            "monthly_attendance": self.get_user_monthly_attendance_count(
                user, start_of_month
            ),
            "is_ambassador": getattr(user, "is_ambassador", False),
            "rank": next(
                (
                    i + 1
                    for i, ranked_user in enumerate(top_users)
                    if ranked_user["email"] == user.email
                ),
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
<<<<<<< HEAD
    recent_roi = DailyROIAccrual.objects.filter(user=user).order_by("-date")[:30]
=======
    year_start = date(today.year, 1, 1)
    recent_roi = DailyROIAccrual.objects.filter(
        user=user, date__gte=year_start
    ).order_by("-date")
>>>>>>> staging
    roi_data = DailyROISerializer(recent_roi, many=True).data

    data = {
        "total_earnings": float(total_earnings),
        "quarterly_earnings": float(quarterly_earnings),
        "next_payout_date": next_payout.isoformat(),
        "daily_records": roi_data,
    }

    return Response(data)


from django.db import transaction
from rest_framework import generics, permissions, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AmbassadorMonthlyReport
from .serializers import AmbassadorMonthlyReportSerializer
from .tasks import send_ambassador_report_notifications_task


class AmbassadorMonthlyReportCreateView(generics.CreateAPIView):
    serializer_class = AmbassadorMonthlyReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            report = serializer.save()
            user = request.user

            transaction.on_commit(
                lambda: send_ambassador_report_notifications_task.delay(
                    report_id=report.id,
                    user_id=user.id,
                )
            )

        return Response(
            {
                "message": f"Your ambassador report for {report.month} has been submitted and is under review.",
                "report_id": report.id,
                "status": report.status,
                "month": report.month,
            },
            status=status.HTTP_201_CREATED,
        )


class AmbassadorMonthlyReportStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        latest_report = (
            AmbassadorMonthlyReport.objects.filter(user=request.user)
            .order_by("-submitted_at")
            .first()
        )

        if not latest_report:
            return Response(
                {"message": "No ambassador report found yet.", "report": None},
                status=status.HTTP_200_OK,
            )

        return Response(
            {
                "report": {
                    "id": latest_report.id,
                    "month": latest_report.month,
                    "status": latest_report.status,
                    "total_points_awarded": str(latest_report.total_points_awarded),
                    "stipend_amount": str(latest_report.stipend_amount),
                    "submitted_at": latest_report.submitted_at,
                    "approved_at": latest_report.approved_at,
                    "admin_note": latest_report.admin_note,
                }
            },
            status=status.HTTP_200_OK,
        )


from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone

from .models import AmbassadorAttendanceSubmission
from .serializers import AmbassadorAttendanceSubmissionSerializer


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def submit_ambassador_attendance(request):
    serializer = AmbassadorAttendanceSubmissionSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    submission = serializer.save()

    current_month = submission.attendance_date.strftime("%B %Y")
    current_month_key = submission.attendance_date.strftime("%Y-%m")

    monthly_count = AmbassadorAttendanceSubmission.objects.filter(
        user=submission.user,
        month=current_month_key,
    ).count()

    return Response(
        {
            "message": f"Attendance recorded successfully for {current_month}.",
            "attendance_count_this_month": monthly_count,
            "points_for_this_attendance": 0.5,
            "attendance_date": submission.attendance_date.strftime("%Y-%m-%d"),
            "weekly_submission_saved": True,
        },
        status=status.HTTP_201_CREATED,
    )
<<<<<<< HEAD
=======


from .models import FinanceMetricSnapshot
from .finance_metrics import calculate_finance_metrics


class AdminFinanceMetricsView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff:
            return Response({"detail": "Permission denied"}, status=403)

        period_type = request.query_params.get("period_type", "monthly")
        target_date = timezone.now().date()

        snapshot = calculate_finance_metrics(
            period_type=period_type,
            target_date=target_date,
            save=True,
        )

        return Response(
            {
                "period_type": snapshot.period_type,
                "period_start": snapshot.period_start,
                "period_end": snapshot.period_end,
                "abrupt_withdrawal_revenue": snapshot.abrupt_withdrawal_revenue,
                "float_gross_revenue": snapshot.float_gross_revenue,
                "roi_payable_to_users": snapshot.roi_payable_to_users,
                "float_net_profit": snapshot.float_net_profit,
                "property_sales_revenue": snapshot.property_sales_revenue,
                "rent_commission_revenue": snapshot.rent_commission_revenue,
                "total_revenue": snapshot.total_revenue,
                "total_expenses": snapshot.total_expenses,
                "net_profit": snapshot.net_profit,
                "profit_margin": snapshot.profit_margin,
                "total_savings_balance": snapshot.total_savings_balance,
                "total_investment_balance": snapshot.total_investment_balance,
            }
        )
>>>>>>> staging
