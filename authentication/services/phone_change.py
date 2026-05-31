import random
from django.utils import timezone
from authentication.models import PhoneChangeRequest, CustomUser
from authentication.utils import (
    send_generic_email,
    send_push_notification,
    send_sms_via_payless,
    validate_phone_number,
)


def generate_otp():
    return str(random.randint(100000, 999999))


# --------------------------------------------------
# CREATE REQUEST (FIXED SMS RELIABILITY)
# --------------------------------------------------
def create_phone_change_request(user, new_phone):

    phone_check = validate_phone_number(new_phone)

    if not phone_check.get("valid"):
        raise ValueError(phone_check.get("error"))

    normalized_new_phone = phone_check["formatted"]

    # prevent same
    if normalized_new_phone == user.phone_number:
        raise ValueError("New number must be different")

    # prevent duplicates
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

    # -------------------------
    # SMS (FIXED FLOW)
    # -------------------------
    send_sms_via_payless(
        user.phone_number, f"Your MyFund OTP (old number): {old_otp}. Do not share."
    )

    send_sms_via_payless(
        normalized_new_phone, f"Your MyFund OTP (new number): {new_otp}. Do not share."
    )

    # -------------------------
    # EMAIL (CLEAN HTML)
    # -------------------------
    send_generic_email(
        subject="Phone Change Request Initiated",
        message=f"""
        <p><strong>Phone Change Request</strong></p>

        <p>Hello {user.first_name},</p>

        <p>A request was made to change your phone number.</p>

        <p>
            <strong>Old Number:</strong> {user.phone_number}<br>
            <strong>New Number:</strong> {normalized_new_phone}
        </p>

        <p>
            <strong>OTP sent to old:</strong> {user.phone_number}<br>
            <strong>OTP sent to new:</strong> {normalized_new_phone}
        </p>

        <p style="color:red;">
            If this wasn’t you, ignore this message immediately.
        </p>
        """,
        recipient_list=[user.email],
    )

    send_push_notification(
        user=user,
        title="Phone Change Request",
        message="OTP sent to both numbers",
        data={"type": "phone_change_request"},
    )

    return req


# --------------------------------------------------
# VERIFY OTP (UNCHANGED LOGIC)
# --------------------------------------------------
def verify_phone_change_otp(request_id, old_otp=None, new_otp=None):

    req = PhoneChangeRequest.objects.get(id=request_id)

    if old_otp and old_otp.strip() == req.old_phone_otp:
        req.old_phone_otp_verified = True
    elif old_otp:
        raise ValueError("Old OTP incorrect")

    if new_otp and new_otp.strip() == req.new_phone_otp:
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
        raise Exception("Not verified")

    user = req.user

    user.phone_number = req.new_phone
    user.save(update_fields=["phone_number"])

    req.status = "approved"
    req.approved_at = timezone.now()
    req.save()

    send_generic_email(
        subject="Phone Updated Successfully",
        message=f"""
        <p><strong>Phone Update Successful</strong></p>

        <p>Your phone number has been updated.</p>

        <p>
            <strong>Old:</strong> {req.old_phone}<br>
            <strong>New:</strong> {req.new_phone}
        </p>
        """,
        recipient_list=[user.email],
    )

    send_push_notification(
        user=user,
        title="Phone Updated",
        message="Your phone number has been changed",
        data={"type": "phone_update"},
    )

    return req
