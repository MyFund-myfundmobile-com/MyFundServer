import logging
from email.utils import parseaddr

import sib_api_v3_sdk

from django.conf import settings
from django.utils import timezone
from django.db.models import Sum, Count

from authentication.models import CustomUser, Transaction

logger = logging.getLogger(__name__)


BREVO_LIST_ID = 4

# Brevo's free-tier daily sending cap. Bulk sends larger than this get
# chunked into same-day-safe batches, one calendar day apart - see
# tasks.send_bulk_email_task.
DAILY_EMAIL_LIMIT = 300


def get_brevo_client():

    configuration = sib_api_v3_sdk.Configuration()

    configuration.api_key["api-key"] = settings.BREVO_API_KEY

    return sib_api_v3_sdk.ApiClient(configuration)


# ==========================================
# TRANSACTIONAL EMAIL SENDING
# ==========================================


def send_email_via_brevo(to_email, subject, html_content, from_email=None):
    """
    Send a single transactional email through Brevo's Transactional Emails
    API. Raises on failure - callers decide how to log/track that.
    """
    from_email = from_email or settings.DEFAULT_FROM_EMAIL

    # from_email is often "Display Name <address@domain>" (Django's
    # convention) - Brevo wants name/email as separate fields.
    sender_name, sender_email = parseaddr(from_email)
    if not sender_email:
        sender_email = from_email
    if not sender_name:
        sender_name = "MyFund"

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(get_brevo_client())

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"name": sender_name, "email": sender_email},
        subject=subject,
        html_content=html_content,
    )

    return api_instance.send_transac_email(send_smtp_email)


# ==========================================
# ENGAGEMENT LOGIC USING TRANSACTIONS
# ==========================================


def get_user_transactions(user):

    return Transaction.objects.filter(user=user, status="confirmed")


def determine_engagement_status(user):

    today = timezone.now()

    last_transaction = get_user_transactions(user).order_by("-date").first()

    # New users
    days_since_signup = (today.date() - user.date_joined.date()).days

    if days_since_signup <= 30:
        return "NEW_USER"

    # Never transacted

    if not last_transaction:

        if days_since_signup >= 180:
            return "DORMANT"

        if days_since_signup >= 90:
            return "INACTIVE"

        return "ACTIVE"

    days_since_activity = (today.date() - last_transaction.date.date()).days

    if days_since_activity >= 180:
        return "DORMANT"

    if days_since_activity >= 90:
        return "INACTIVE"

    return "ACTIVE"


def determine_new_user_period(user):

    days = (timezone.now().date() - user.date_joined.date()).days

    if days <= 3:
        return "LAST_3_DAYS"

    if days <= 7:
        return "LAST_7_DAYS"

    if days <= 14:
        return "LAST_14_DAYS"

    if days <= 30:
        return "LAST_30_DAYS"

    return "OLDER_USER"


def determine_account_role(user):

    if user.is_staff:
        return "STAFF"

    if user.is_ambassador:
        return "AMBASSADOR"

    return "USER"


# ==========================================
# TRANSACTION METRICS
# ==========================================


def get_transaction_metrics(user):

    transactions = get_user_transactions(user)

    count = transactions.count()

    total_value = transactions.aggregate(total=Sum("amount"))["total"] or 0

    last_transaction = transactions.order_by("-date").first()

    return {
        "count": count,
        "total": float(total_value),
        "last_date": (
            last_transaction.date.date().isoformat() if last_transaction else None
        ),
        "last_type": (
            last_transaction.transaction_type.upper() if last_transaction else ""
        ),
        "last_source": (last_transaction.source if last_transaction else ""),
    }


def determine_user_category(user):

    categories = []

    if user.savings > 0:
        categories.append("SAVER")

    if user.investment > 0:
        categories.append("INVESTOR")

    if user.properties > 0:
        categories.append("PROPERTY_OWNER")

    if user.is_ambassador:
        categories.append("AMBASSADOR")

    if not categories:
        categories.append("NEW_USER")

    return ",".join(categories)


# ==========================================
# BREVO SYNC
# ==========================================


def sync_contact_to_brevo(user):

    if not user.email:
        return None

    try:

        api_instance = sib_api_v3_sdk.ContactsApi(get_brevo_client())

        metrics = get_transaction_metrics(user)

        total_assets = user.savings + user.investment + user.wallet

        attributes = {
            # BASIC
            "FIRSTNAME": user.first_name or "",
            "LASTNAME": user.last_name or "",
            "PHONE": user.phone_number or "",
            "USER_ID": user.id,
            # ENGAGEMENT
            "ENGAGEMENT_STATUS": determine_engagement_status(user),
            "NEW_USER_PERIOD": determine_new_user_period(user),
            "ACCOUNT_ROLE": determine_account_role(user),
            "IS_STAFF": user.is_staff,
            "LAST_TRANSACTION_DATE": metrics["last_date"],
            "TRANSACTION_COUNT": metrics["count"],
            "TOTAL_TRANSACTION_VALUE": metrics["total"],
            "LAST_TRANSACTION_TYPE": metrics["last_type"],
            "LAST_TRANSACTION_SOURCE": metrics["last_source"],
            # FINANCIAL
            "SAVINGS_BALANCE": float(user.savings or 0),
            "INVESTMENT_BALANCE": float(user.investment or 0),
            "WALLET_BALANCE": float(user.wallet or 0),
            "TOTAL_ASSETS": float(total_assets),
            # USER CATEGORY
            "USER_CATEGORY": determine_user_category(user),
            # PROFILE
            "GENDER": user.gender or "",
            "STATE": user.state or "",
            "EMPLOYMENT_STATUS": user.employment_status or "",
            # KYC
            "KYC_STATUS": getattr(user, "kyc_status", "NOT_STARTED"),
            # REFERRALS
            "REFERRAL_COUNT": CustomUser.objects.filter(referral=user).count(),
            # DATE
            "SIGNUP_DATE": user.date_joined.date().isoformat(),
        }

        print(attributes)

        contact = sib_api_v3_sdk.CreateContact(
            email=user.email,
            attributes=attributes,
            list_ids=[BREVO_LIST_ID],
            update_enabled=True,
        )

        response = api_instance.create_contact(contact)

        logger.info(f"Brevo synced {user.email}")

        return response

    except Exception as e:

        logger.exception(f"Brevo sync failed {user.email}: {e}")

        return None
