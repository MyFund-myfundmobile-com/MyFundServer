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


def create_phone_change_request(user, new_phone):
    # ----------------------------
    # VALIDATE + NORMALIZE PHONE
    # ----------------------------
    phone_check = validate_phone_number(new_phone)
    if not phone_check.get("valid"):
        raise ValueError(phone_check.get("error", "Invalid new phone number"))

    normalized_new_phone = phone_check.get("formatted")  # +234...

    # ----------------------------
    # PREVENT SAME NUMBER CHANGE
    # ----------------------------
    if normalized_new_phone == user.phone_number:
        raise ValueError("New phone number cannot be the same as current number.")

    # ----------------------------
    # PREVENT DUPLICATE ACCOUNT PHONE
    # ----------------------------
    existing_user = (
        CustomUser.objects.filter(phone_number=normalized_new_phone)
        .exclude(id=user.id)
        .first()
    )

    if existing_user:
        raise ValueError("This phone number is already linked to another account.")

    # ----------------------------
    # GENERATE OTPs
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
    # SEND SMS OTPs
    # ----------------------------
    send_sms_via_payless(
        user.phone_number,
        f"Hi {user.first_name}, your MyFund phone change OTP is {old_otp}. "
        f"Enter this to confirm your old number. Do not share this code.",
    )

    send_sms_via_payless(
        normalized_new_phone,
        f"Hi {user.first_name}, your MyFund phone change OTP is {new_otp}. "
        f"Enter this to confirm your new number. Do not share this code.",
    )

    # ----------------------------
    # SEND EMAIL (FORMATTED HTML)
    # ----------------------------
    send_generic_email(
        subject="Phone Change Request Initiated",
        message=f"""
        <p><strong>Phone Change Request Initiated</strong></p>

        <p>A request was made to update your phone number on <strong>MyFund</strong>.</p>

        <p>
            <strong>Old Phone:</strong> {user.phone_number}<br>
            <strong>New Phone:</strong> {normalized_new_phone}
        </p>

        <p>
            <strong>Old OTP Sent To:</strong> {user.phone_number}<br>
            <strong>New OTP Sent To:</strong> {normalized_new_phone}
        </p>

        <p style="color:red;">
            If this was not you, please ignore this message immediately or contact support.
        </p>
        """,
        recipient_list=[user.email],
    )

    # ----------------------------
    # ADMIN PUSH NOTIFICATION
    # ----------------------------
    send_push_notification(
        user=user,
        title="New Phone Change Request",
        message=f"{user.email} requested phone change",
        data={"type": "phone_change_request"},
    )

    return req


def verify_phone_change_otp(request_id, old_otp=None, new_otp=None):
    req = PhoneChangeRequest.objects.get(id=request_id)

    if old_otp and str(old_otp).strip() == str(req.old_phone_otp).strip():
        req.old_phone_otp_verified = True
    elif old_otp:
        raise ValueError("Old phone OTP is incorrect.")

    if new_otp and str(new_otp).strip() == str(req.new_phone_otp).strip():
        req.new_phone_otp_verified = True
    elif new_otp:
        raise ValueError("New phone OTP is incorrect.")

    if req.old_phone_otp_verified and req.new_phone_otp_verified:
        req.status = "verified"
        req.verified_at = timezone.now()

    req.save()
    return req


def approve_phone_change(request_id, admin_user):
    req = PhoneChangeRequest.objects.get(id=request_id)

    if req.status != "verified":
        raise Exception("Request not verified yet")

    user = req.user
    old_phone = user.phone_number

    user.phone_number = req.new_phone
    user.save(update_fields=["phone_number"])

    req.status = "approved"
    req.approved_at = timezone.now()
    req.save()

    # ----------------------------
    # USER NOTIFICATION EMAIL
    # ----------------------------
    send_generic_email(
        subject="Phone Number Updated Successfully",
        message=f"""
        <p><strong>Phone Number Successfully Updated</strong></p>

        <p>
            Your phone number has been updated successfully on <strong>MyFund</strong>.
        </p>

        <p>
            <strong>Old Number:</strong> {old_phone}<br>
            <strong>New Number:</strong> {req.new_phone}
        </p>

        <p style="color:green;">
            If you did not request this change, please contact support immediately.
        </p>
        """,
        recipient_list=[user.email],
    )

    # ----------------------------
    # PUSH NOTIFICATION
    # ----------------------------
    send_push_notification(
        user=user,
        title="Phone Updated",
        message="Your phone number was successfully updated.",
        data={"type": "phone_update"},
    )

    return req
