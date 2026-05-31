import random
import logging
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
# SAFE PHONE NORMALIZER
# --------------------------------------------------
def safe_validate_phone(phone):
    if not phone:
        return {"valid": False, "error": "Phone number is required"}

    phone = str(phone).strip()

    # remove junk characters
    phone = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")

    return validate_phone_number(phone)


# --------------------------------------------------
# CREATE PHONE CHANGE REQUEST
# --------------------------------------------------
def create_phone_change_request(user, new_phone):

    logger.info("🔥 PHONE CHANGE FLOW STARTED")

    phone_check = safe_validate_phone(new_phone)

    if not phone_check.get("valid"):
        logger.error(f"❌ PHONE VALIDATION FAILED: {phone_check}")
        raise ValueError(phone_check.get("error") or "Invalid phone number")

    normalized_new_phone = phone_check["formatted"]

    # prevent same number
    if normalized_new_phone == user.phone_number:
        raise ValueError("New number must be different from current number")

    # prevent duplicates
    if (
        CustomUser.objects.filter(phone_number=normalized_new_phone)
        .exclude(id=user.id)
        .exists()
    ):
        raise ValueError("Phone already in use")

    # generate OTPs
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
    # SMS SEND (CRASH PROTECTED)
    # --------------------------------------------------
    try:
        logger.info(f"📲 Sending OTP to OLD: {user.phone_number}")
        send_sms_via_payless(
            user.phone_number,
            f"Your MyFund OTP (old number): {old_otp}. Do not share.",
        )
    except Exception as e:
        logger.error(f"❌ OLD SMS FAILED: {str(e)}")

    try:
        logger.info(f"📲 Sending OTP to NEW: {normalized_new_phone}")
        send_sms_via_payless(
            normalized_new_phone,
            f"Your MyFund OTP (new number): {new_otp}. Do not share.",
        )
    except Exception as e:
        logger.error(f"❌ NEW SMS FAILED: {str(e)}")

    # --------------------------------------------------
    # EMAIL (HTML FORMATTED)
    # --------------------------------------------------
    send_generic_email(
        subject="Phone Change Request Initiated",
        message=f"""
        <p><strong>Phone Change Request</strong></p>

        <p>Hello <strong>{user.first_name}</strong>,</p>

        <p>Your request to update your phone number has been initiated.</p>

        <p>
            <strong>Old Number:</strong> {user.phone_number}<br>
            <strong>New Number:</strong> {normalized_new_phone}
        </p>

        <p>
            <strong>OTP (Old):</strong> Sent to old number<br>
            <strong>OTP (New):</strong> Sent to new number
        </p>

        <p style="color:red;">
            If this wasn’t you, ignore this message immediately.
        </p>
        """,
        recipient_list=[user.email],
    )

    # --------------------------------------------------
    # PUSH NOTIFICATION
    # --------------------------------------------------
    send_push_notification(
        user=user,
        title="Phone Change Request",
        message="OTP sent to both numbers",
        data={"type": "phone_change_request"},
    )

    return req


# --------------------------------------------------
# VERIFY OTP
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
# ADMIN APPROVAL
# --------------------------------------------------
def approve_phone_change(request_id, admin_user):

    req = PhoneChangeRequest.objects.get(id=request_id)

    if req.status != "verified":
        raise Exception("Request not verified")

    user = req.user
    old_phone = user.phone_number

    user.phone_number = req.new_phone
    user.save(update_fields=["phone_number"])

    req.status = "approved"
    req.approved_at = timezone.now()
    req.save()

    send_generic_email(
        subject="Phone Number Updated Successfully",
        message=f"""
        <p><strong>Phone Update Successful</strong></p>

        <p>Your phone number has been updated.</p>

        <p>
            <strong>Old:</strong> {old_phone}<br>
            <strong>New:</strong> {req.new_phone}
        </p>
        """,
        recipient_list=[user.email],
    )

    send_push_notification(
        user=user,
        title="Phone Updated",
        message="Your phone number was updated",
        data={"type": "phone_update"},
    )

    return req
