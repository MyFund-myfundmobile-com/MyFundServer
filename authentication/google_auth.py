# google_auth.py
#
# Thin wrapper around google-auth's own ID-token verification - kept
# separate from views.py (which already reuses its normal signup helpers
# for the completion step) so the one thing that actually matters for
# security - verifying the token server-side rather than trusting
# anything in the request body - is isolated and easy to audit on its
# own.

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from django.conf import settings


class GoogleTokenError(Exception):
    """Raised for any reason a Google ID token can't be trusted - bad
    signature, wrong audience, expired, or (see verify_google_id_token)
    an unverified email. Callers turn this into a 400, never a 500."""


def verify_google_id_token(token):
    """
    Verifies signature, issuer, expiry, and that `aud` matches our one
    Web client ID (GOOGLE_OAUTH_CLIENT_ID) - every platform's Google
    Sign-In (iOS/Android/web) is configured to mint ID tokens against
    that same Web client, so the backend only ever checks one value
    regardless of which platform the request came from.

    Also enforces email_verified=True - Google can return an ID token
    for an email it hasn't itself verified (some Workspace/G Suite
    configurations), and trusting an unverified address for account
    matching/creation is exactly the "wrong account" mismatch this whole
    flow is designed to avoid. Returns the verified claims dict on
    success (email/given_name/family_name/sub), never a client-supplied
    value - every caller must re-derive identity from THIS return value,
    not from anything else in the request.
    """
    if not settings.GOOGLE_OAUTH_CLIENT_ID:
        raise GoogleTokenError("Google Sign-In is not configured on this server.")

    try:
        claims = google_id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=settings.GOOGLE_OAUTH_CLIENT_ID,
        )
    except ValueError as e:
        raise GoogleTokenError(f"Invalid Google ID token: {e}")

    if not claims.get("email_verified", False):
        raise GoogleTokenError(
            "This Google account's email isn't verified by Google - can't "
            "safely use it to sign in."
        )

    email = (claims.get("email") or "").strip().lower()
    if not email:
        raise GoogleTokenError("Google did not return an email for this account.")

    return {
        "email": email,
        "first_name": (claims.get("given_name") or "").strip(),
        "last_name": (claims.get("family_name") or "").strip(),
        # Google's hosted avatar URL, present whenever the account has a
        # profile photo set (absent for accounts that never set one -
        # callers must treat it as optional, never assume a value).
        "picture": (claims.get("picture") or "").strip(),
        "sub": claims.get("sub"),
    }
