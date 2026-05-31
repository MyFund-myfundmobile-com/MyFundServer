import random
from django.utils import timezone
from authentication.models import PhoneChangeRequest
from authentication.utils import (
    send_generic_email,
    send_push_notification,
    send_sms_via_payless,
)


def generate_otp():
    return str(random.randint(100000, 999999))


def create_phone_change_request(user, new_phone):

    old_otp = generate_otp()
    new_otp = generate_otp()

    req = PhoneChangeRequest.objects.create(
        user=user,
        old_phone=user.phone_number,
        new_phone=new_phone,
        old_phone_otp=old_otp,
        new_phone_otp=new_otp,
    )

    # TODO: send SMS OTPs
    send_sms_via_payless(
        user.phone_number,
        f"Hi {user.first_name}, your MyFund phone change OTP is {old_otp}. "
        f"Enter this to confirm your old number. Do not share this code.",
    )
    send_sms_via_payless(
        new_phone,
        f"Hi {user.first_name}, your MyFund phone change OTP is {new_otp}. "
        f"Enter this to confirm your new number. Do not share this code.",
    )

    send_generic_email(
        subject="Phone Change Request Initiated",
        message=f"""
        A request was made to change your phone number.

        Old OTP sent to: {user.phone_number}
        New OTP sent to: {new_phone}

        If this wasn't you, ignore this message.
        """,
        recipient_list=[user.email],
    )

    # notify admins
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

    # notify user
    send_generic_email(
        subject="Phone Number Updated Successfully",
        message=f"Your phone number changed from {old_phone} to {req.new_phone}",
        recipient_list=[user.email],
    )

    send_push_notification(
        user=user,
        title="Phone Updated",
        message="Your phone number was successfully updated.",
        data={"type": "phone_update"},
    )

    return req
