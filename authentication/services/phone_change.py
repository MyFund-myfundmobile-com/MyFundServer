"""Verified phone changes: provider acceptance, owner OTPs, then admin approval."""
import logging
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from django.db import transaction, IntegrityError
from django.utils import timezone
from authentication.models import PhoneChangeRequest, CustomUser
from authentication.utils import send_push_notification, send_sms_via_payless, validate_phone_number

logger = logging.getLogger(__name__)
OTP_LIFETIME = timedelta(minutes=10)
MAX_ATTEMPTS = 5


class SMSDeliveryError(Exception):
    pass


def generate_otp():
    return str(secrets.randbelow(900000) + 100000)


def safe_validate_phone(phone):
    if not phone:
        return {"valid": False, "error": "Phone number is required"}
    return validate_phone_number(str(phone).strip().replace(" ", "").replace("-", ""))


def _phone_in_use(number, user_id):
    # Existing accounts may store Nigerian numbers locally or with +234.
    variants = {number, "+" + number}
    if number.startswith("234"):
        variants.add("0" + number[3:])
    return CustomUser.objects.filter(phone_number__in=variants).exclude(pk=user_id).exists()


def _notify(user, title, message):
    try:
        send_push_notification(user=user, title=title, message=message, data={"type": "phone_update"})
    except Exception:
        logger.exception("Phone-change notification failed for user %s", user.pk)


def create_phone_change_request(user, new_phone):
    new = safe_validate_phone(new_phone)
    old = safe_validate_phone(user.phone_number)
    if not new.get("valid"):
        raise ValueError(new.get("error") or "Invalid phone number")
    if not old.get("valid"):
        raise ValueError("Your current phone number is invalid. Contact support.")
    if new["formatted"] == old["formatted"]:
        raise ValueError("New number must be different")
    with transaction.atomic():
        # Serialize requests for the same user, including concurrent retries.
        CustomUser.objects.select_for_update().get(pk=user.pk)
        if PhoneChangeRequest.objects.filter(user=user, status="verified").exists():
            raise ValueError("Your verified phone change is awaiting admin approval.")
        if PhoneChangeRequest.objects.filter(user=user, created_at__gte=timezone.now() - timedelta(seconds=60)).exists():
            raise ValueError("Please wait one minute before requesting new codes.")
        if _phone_in_use(new["formatted"], user.pk):
            raise ValueError("Phone already in use")
        PhoneChangeRequest.objects.filter(user=user, status="pending").update(status="rejected", old_phone_otp=None, new_phone_otp=None)
        req = PhoneChangeRequest.objects.create(user=user, old_phone=user.phone_number, new_phone=new["formatted"], old_phone_otp=generate_otp(), new_phone_otp=generate_otp())
    # Wait for both provider responses; never claim success for a failed send.
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda pair: send_sms_via_payless(*pair), [
                (old["formatted"], f"MyFund phone change OTP (old): {req.old_phone_otp}. Expires in 10 minutes. Do not share."),
                (new["formatted"], f"MyFund phone change OTP (new): {req.new_phone_otp}. Expires in 10 minutes. Do not share."),
            ]))
        accepted = all(results)
    except Exception:
        accepted = False
    if not accepted:
        PhoneChangeRequest.objects.filter(pk=req.pk, status="pending").update(status="rejected", old_phone_otp=None, new_phone_otp=None)
        raise SMSDeliveryError("Could not send both verification codes. Please wait one minute and try again.")
    return req


def verify_phone_change_otp(request_id, old_otp=None, new_otp=None, user=None):
    failure = None
    with transaction.atomic():
        req = PhoneChangeRequest.objects.select_for_update().filter(pk=request_id, user=user).first()
        if not req:
            raise ValueError("Phone change request not found.")
        if req.status != "pending":
            raise ValueError("This request is no longer awaiting verification.")
        if timezone.now() >= req.created_at + OTP_LIFETIME or req.otp_attempts >= MAX_ATTEMPTS:
            failure = "Codes expired or attempt limit reached. Please request new codes."
        elif not (old_otp and new_otp and secrets.compare_digest(str(old_otp).strip(), req.old_phone_otp or "") and secrets.compare_digest(str(new_otp).strip(), req.new_phone_otp or "")):
            req.otp_attempts += 1
            failure = "Incorrect verification codes. Check both messages and try again."
        else:
            req.old_phone_otp_verified = req.new_phone_otp_verified = True
            req.status = "verified"
            req.verified_at = timezone.now()
        if failure and (req.otp_attempts >= MAX_ATTEMPTS or timezone.now() >= req.created_at + OTP_LIFETIME):
            req.status = "rejected"
        if req.status != "pending":
            req.old_phone_otp = req.new_phone_otp = None
        req.save()
    if failure:
        raise ValueError(failure)
    return req


def approve_phone_change(request_id, admin_user):
    from authentication.request_views import REQUEST_APPROVERS
    if not (admin_user.is_active and admin_user.is_staff and admin_user.email.lower() in REQUEST_APPROVERS):
        raise ValueError("You cannot approve phone changes.")
    with transaction.atomic():
        req = PhoneChangeRequest.objects.select_for_update().get(pk=request_id)
        if req.status != "verified" or not (req.old_phone_otp_verified and req.new_phone_otp_verified):
            raise ValueError("This request is not verified or has already been reviewed.")
        user = CustomUser.objects.select_for_update().get(pk=req.user_id)
        if safe_validate_phone(user.phone_number).get("formatted") != safe_validate_phone(req.old_phone).get("formatted"):
            raise ValueError("The current phone number has changed. Ask the user to submit a new request.")
        if _phone_in_use(req.new_phone, user.pk):
            raise ValueError("Phone already in use")
        user.phone_number = req.new_phone
        try:
            with transaction.atomic():
                user.save(update_fields=["phone_number"])
        except IntegrityError:
            raise ValueError("Phone already in use")
        req.status = "approved"
        req.approved_at = timezone.now()
        req.save(update_fields=["status", "approved_at"])
        transaction.on_commit(lambda: _notify(user, "Phone Updated", "Your phone number change was approved."))
    return req
