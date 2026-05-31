import random
from django.utils import timezone
from authentication.models import PhoneChangeRequest, CustomUser
from authentication.utils import (
    send_generic_email,
    send_push_notification,
    send_sms_via_payless,
)
from authentication.utils import validate_phone_number


def generate_otp():
    return str(random.randint(100000, 999999))


# --------------------------------------------------
# SAFE PHONE NORMALIZER WRAPPER (NEW SAFETY LAYER)
# --------------------------------------------------
def safe_validate_phone(phone):
    if not phone:
        return {"valid": False, "error": "Phone number is required"}

    phone = str(phone).strip()

    # quick cleanup for frontend junk input
    phone = phone.replace(" ", "").replace("-", "")

    return validate_phone_number(phone)


# --------------------------------------------------
# CREATE REQUEST (ROBUST VERSION)
# --------------------------------------------------
def create_phone_change_request(user, new_phone):

    print("🔥 PHONE CHANGE FLOW TRIGGERED")

    # ----------------------------
    # VALIDATE PHONE (SAFE WRAP)
    # ----------------------------
    phone_check = safe_validate_phone(new_phone)

    if not phone_check.get("valid"):
        raise ValueError(phone_check.get("error") or "Invalid phone number")

    normalized_new_phone = phone_check["formatted"]

    # ----------------------------
    # SAME NUMBER CHECK
    # ----------------------------
    if normalized_new_phone == user.phone_number:
        raise ValueError("New number must be different from current number")

    # ----------------------------
    # DUPLICATE CHECK
    # ----------------------------
    if (
        CustomUser.objects.filter(phone_number=normalized_new_phone)
        .exclude(id=user.id)
        .exists()
    ):
        raise ValueError("Phone already in use")

    # ----------------------------
    # OTP GENERATION
    # ----------------------------
    old_otp = generate_otp()
    new_otp = generate_otp()

    req = PhoneChangeRequest.objects.create(
        user=user,
        old_phone=user.phone_number,
        new_phone=normalized_new_phone,
        old_phone_otp=old_otp,
        new_phone_otp=new_otp,
    )

    # ----------------------------
    # SMS SEND (GUARDED)
    # ----------------------------
    try:
        send_sms_via_payless(
            user.phone_number,
            f"Your MyFund OTP (old number): {old_otp}. Do not share.",
        )
    except Exception as e:
        print("❌ OLD PHONE SMS FAILED:", str(e))

    try:
        send_sms_via_payless(
            normalized_new_phone,
            f"Your MyFund OTP (new number): {new_otp}. Do not share.",
        )
    except Exception as e:
        print("❌ NEW PHONE SMS FAILED:", str(e))

    # ----------------------------
    # EMAIL (CLEAN + SAFE HTML)
    # ----------------------------
    send_generic_email(
        subject="Phone Change Request Initiated",
        message=f"""
        <p><strong>Phone Change Request Initiated</strong></p>

        <p>Hello <strong>{user.first_name}</strong>,</p>

        <p>A request was made to change your phone number on <strong>MyFund</strong>.</p>

        <p>
            <strong>Old Number:</strong> {user.phone_number}<br>
            <strong>New Number:</strong> {normalized_new_phone}
        </p>

        <p>
            OTPs have been sent to both numbers for verification.
        </p>

        <p style="color:red;">
            If this wasn’t you, ignore this message immediately.
        </p>
        """,
        recipient_list=[user.email],
    )

    # ----------------------------
    # PUSH NOTIFICATION
    # ----------------------------
    send_push_notification(
        user=user,
        title="Phone Change Request",
        message="OTP sent to both numbers",
        data={"type": "phone_change_request"},
    )

    return req


# --------------------------------------------------
# VERIFY OTP (UNCHANGED)
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
# ADMIN APPROVAL (UNCHANGED)
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

        <p>
            Old: {old_phone}<br>
            New: {req.new_phone}
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
