import logging
from email.utils import parseaddr

import resend

from django.conf import settings

logger = logging.getLogger(__name__)


# ==========================================
# TRANSACTIONAL EMAIL SENDING (OTP, password reset, security alerts)
# ==========================================
#
# Deliberately separate from brevo_service.py - Brevo is the bulk/campaign
# sender (admin broadcasts, segments), Resend is the transactional sender
# (OTP and other single-user, auth-critical emails). See
# utils.send_transactional_email for the Resend-first/Brevo-fallback
# wiring - this module only wraps the raw Resend API call.


def send_email_via_resend(to_email, subject, html_content, from_email=None):
    """
    Send a single transactional email through Resend. Raises on failure -
    callers decide how to log/track/fall back.
    """
    from_email = from_email or settings.DEFAULT_FROM_EMAIL

    # from_email is often "Display Name <address@domain>" (Django's
    # convention) - Resend accepts that combined form directly, but
    # parseaddr guards against a bare address with no display name.
    sender_name, sender_email = parseaddr(from_email)
    if not sender_email:
        sender_email = from_email
    sender = f"{sender_name} <{sender_email}>" if sender_name else sender_email

    resend.api_key = settings.RESEND_API_KEY

    return resend.Emails.send(
        {
            "from": sender,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        }
    )
