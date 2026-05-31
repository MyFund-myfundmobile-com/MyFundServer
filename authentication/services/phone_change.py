import random
import logging
import threading
from django.utils import timezone
from authentication.models import PhoneChangeRequest, CustomUser
from authentication.utils import (
    send_generic_email,
    send_push_notification,
    send_sms_via_payless,
    validate_phone_number,
)

logger = logging.getLogger(__name__)


def generate_otp():
    return str(random.randint(100000, 999999))


# --------------------------------------------------
# PHONE VALIDATION (STRICT)
# --------------------------------------------------
def safe_validate_phone(phone):
    if not phone:
        return {"valid": False, "error": "Phone number is required"}

    phone = str(phone).strip().replace(" ", "").replace("-", "")
    return validate_phone_number(phone)


# --------------------------------------------------
# BACKGROUND SMS WORKER (NON-BLOCKING)
# --------------------------------------------------
def _send_sms_async(phone, message):
    try:
        send_sms_via_payless(phone, message)
    except Exception as e:
        logger.error(f"SMS FAILED: {phone} | {str(e)}")


def _send_email_async(user, old_phone, new_phone):
    try:
        send_generic_email(
            subject="Phone Change Request Initiated",
            message=f"""
            <p><strong>Phone Change Request</strong></p>

            <p>Hello {user.first_name},</p>

            <p>
                Old: {old_phone}<br>
                New: {new_phone}
            </p>

            <p>OTP has been sent to both numbers.</p>
            """,
            recipient_list=[user.email],
        )
    except Exception as e:
        logger.error(f"EMAIL FAILED: {str(e)}")


def _send_push_async(user):
    try:
        send_push_notification(
            user=user,
            title="Phone Change Request",
            message="OTP sent to both numbers",
            data={"type": "phone_change_request"},
        )
    except Exception as e:
        logger.error(f"PUSH FAILED: {str(e)}")


# --------------------------------------------------
# MAIN FUNCTION (FAST RESPONSE VERSION)
# --------------------------------------------------
def create_phone_change_request(user, new_phone):

    logger.info("🔥 PHONE CHANGE FLOW STARTED")

    phone_check = safe_validate_phone(new_phone)

    if not phone_check.get("valid"):
        raise ValueError(phone_check.get("error") or "Invalid phone number")

    normalized_new_phone = phone_check["formatted"]

    if normalized_new_phone == user.phone_number:
        raise ValueError("New number must be different")

    if (
        CustomUser.objects.filter(phone_number=normalized_new_phone)
        .exclude(id=user.id)
        .exists()
    ):
        raise ValueError("Phone already in use")

    old_otp = generate_otp()
    new_otp = generate_otp()

    req = PhoneChangeRequest.objects.create(
        user=user,
        old_phone=user.phone_number,
        new_phone=normalized_new_phone,
        old_phone_otp=old_otp,
        new_phone_otp=new_otp,
    )

    # --------------------------------------------------
    # FIRE AND FORGET (THIS IS THE SPEED FIX)
    # --------------------------------------------------
    threading.Thread(
        target=_send_sms_async,
        args=(user.phone_number, f"Your OTP (old): {old_otp}. Do not share."),
        daemon=True,
    ).start()

    threading.Thread(
        target=_send_sms_async,
        args=(normalized_new_phone, f"Your OTP (new): {new_otp}. Do not share."),
        daemon=True,
    ).start()

    threading.Thread(
        target=_send_email_async,
        args=(user, user.phone_number, normalized_new_phone),
        daemon=True,
    ).start()

    threading.Thread(
        target=_send_push_async,
        args=(user,),
        daemon=True,
    ).start()

    return req


# --------------------------------------------------
# VERIFY OTP (UNCHANGED BUT CLEANED)
# --------------------------------------------------
def verify_phone_change_otp(request_id, old_otp=None, new_otp=None):

    req = PhoneChangeRequest.objects.get(id=request_id)

    if old_otp and str(old_otp).strip() == str(req.old_phone_otp).strip():
        req.old_phone_otp_verified = True
    elif old_otp:
        raise ValueError("Old OTP incorrect")

    if new_otp and str(new_otp).strip() == str(req.new_phone_otp).strip():
        req.new_phone_otp_verified = True
    elif new_otp:
        raise ValueError("New OTP incorrect")

    if req.old_phone_otp_verified and req.new_phone_otp_verified:
        req.status = "verified"
        req.verified_at = timezone.now()

    req.save()
    return req


# --------------------------------------------------
# APPROVAL (UNCHANGED)
# --------------------------------------------------
def approve_phone_change(request_id, admin_user):

    req = PhoneChangeRequest.objects.get(id=request_id)

    if req.status != "verified":
        raise Exception("Not verified")

    user = req.user
    user.phone_number = req.new_phone
    user.save(update_fields=["phone_number"])

    req.status = "approved"
    req.approved_at = timezone.now()
    req.save()

    send_push_notification(
        user=user,
        title="Phone Updated",
        message="Your phone number was updated",
        data={"type": "phone_update"},
    )

    return req
