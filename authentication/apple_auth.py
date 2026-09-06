# apple_auth.py
#
# Sign in with Apple's native-SDK identity token verification - mirrors
# google_auth.py's shape (a thin, isolated, easy-to-audit verifier) but
# Apple has no server-side SDK equivalent to google-auth: identity
# tokens are RS256 JWTs signed by Apple's own rotating key set, fetched
# from https://appleid.apple.com/auth/keys and verified with PyJWT
# directly.
#
# Two things make this genuinely different from Google's flow, not just
# a renamed copy:
# - The audience is the app's BUNDLE ID directly (native Sign in with
#   Apple, not the web/Services-ID flow) - see APPLE_BUNDLE_ID.
# - Apple only ever returns the user's name ONCE, in the native SDK's
#   on-device response at the very first authorization - never again,
#   and never inside the identity token itself. Callers must capture
#   first_name/last_name from that first native response and pass them
#   straight through to apple_complete_signup; this module has no way
#   to recover them later and never claims to.
import requests
import jwt
from jwt import PyJWKClient
from django.conf import settings

APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys"
APPLE_ISSUER = "https://appleid.apple.com"

# PyJWKClient caches fetched keys in-process and refetches on an unknown
# kid (e.g. after Apple rotates), so no separate Django-cache bookkeeping
# is needed here.
_jwk_client = PyJWKClient(APPLE_KEYS_URL)


class AppleTokenError(Exception):
    """Raised for any reason an Apple identity token can't be trusted -
    bad signature, wrong audience/issuer, expired, or an unverified
    email. Callers turn this into a 400, never a 500."""


def verify_apple_identity_token(token):
    """
    Verifies signature (against Apple's published JWKS), issuer, expiry,
    and that `aud` matches our app's bundle ID - every caller must
    re-derive identity from THIS return value, not from anything else in
    the request, same rule as verify_google_id_token.

    Also enforces email_verified - Apple encodes this as the STRING
    "true"/"false" (sometimes a real bool depending on client/SDK
    version), so it's normalized before checking rather than compared
    directly.

    Returns {"email", "sub", "is_private_email"} on success. There is no
    first_name/last_name here by design - see module docstring.
    """
    if not settings.APPLE_BUNDLE_ID:
        raise AppleTokenError("Sign in with Apple is not configured on this server.")

    try:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.APPLE_BUNDLE_ID,
            issuer=APPLE_ISSUER,
        )
    except jwt.PyJWTError as e:
        raise AppleTokenError(f"Invalid Apple identity token: {e}")
    except requests.RequestException as e:
        raise AppleTokenError(f"Could not reach Apple to verify token: {e}")

    email_verified = str(claims.get("email_verified", "")).strip().lower() == "true"
    if not email_verified:
        raise AppleTokenError(
            "This Apple ID's email isn't verified by Apple - can't safely "
            "use it to sign in."
        )

    email = (claims.get("email") or "").strip().lower()
    if not email:
        raise AppleTokenError("Apple did not return an email for this account.")

    return {
        "email": email,
        "sub": claims.get("sub"),
        # Apple's "Hide My Email" relay address (ends in
        # @privaterelay.appleid.com) - a perfectly valid, stable,
        # per-app-per-user email as far as MyFund is concerned; callers
        # don't need to treat it differently, this is informational only.
        "is_private_email": str(claims.get("is_private_email", "")).strip().lower()
        == "true",
    }
