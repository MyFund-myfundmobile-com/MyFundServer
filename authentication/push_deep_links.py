# authentication/push_deep_links.py
#
# Single source of truth for every deep_link payload attached to push
# notifications. Import build_deep_link_data() anywhere you call
# send_push_notification() and merge the result into the `data` dict.
#
# Usage:
#   from .push_deep_links import dl
#
#   send_push_notification(
#       user=admin,
#       title="...",
#       message="...",
#       data={
#           **dl.admin_new_user(user.phone_number, user.email),
#           "type": "admin_signup_alert",
#           # ...other existing keys
#       },
#       notif_type="ADMIN",
#   )

import urllib.parse

ADMIN_BASE = "https://myfundapi-myfund-07ce351a.koyeb.app/admin"

WHATSAPP_WELCOME = (
    "Welcome to MyFund! 🎉\n"
    "Please feel free to reach out here if you encounter any challenge using MyFund.\n"
    "Jane."
)


def _wa_url(phone: str, message: str) -> str:
    """Build a wa.me deep link, normalising Nigerian 0xxx numbers to 234xxx."""
    digits = "".join(c for c in (phone or "") if c.isdigit())
    if digits.startswith("0") and len(digits) == 11:
        digits = "234" + digits[1:]
    return f"https://wa.me/{digits}?text={urllib.parse.quote(message)}"


def _mailto_url(email: str, subject: str = "", body: str = "") -> str:
    params = urllib.parse.urlencode({"subject": subject, "body": body})
    return f"mailto:{email}?{params}"


class DeepLinks:
    """
    Namespace for every deep_link payload used across MyFund push notifications.
    Each method returns a dict ready to be spread into send_push_notification's
    `data` argument.
    """

    # ── Admin: new user signed up ─────────────────────────────────────────
    def admin_new_user(self, phone: str, email: str) -> dict:
        """
        Tapping the notification opens WhatsApp with a welcome message.
        Fallback: mailto the new user.
        """
        return {
            "deep_link": {
                "url": _wa_url(phone, WHATSAPP_WELCOME),
                "fallback_url": _mailto_url(
                    email,
                    subject="Welcome to MyFund!",
                    body=WHATSAPP_WELCOME,
                ),
            }
        }

    # ── Admin: bank transfer / QuickSave initiated ────────────────────────
    def admin_bank_transfer(self, transaction_id: str) -> dict:
        """
        Approve button → calls approve_bank_transfer_action API.
        View button   → opens Django admin BankTransferRequest list.
        """
        return {
            "deep_link": {
                "action": "approve_bank_transfer",
                "action_params": {"transaction_id": str(transaction_id)},
                "action_url": f"{ADMIN_BASE}/authentication/banktransferrequest/",
            }
        }

    # ── Admin: invest transfer / QuickInvest initiated ───────────────────
    def admin_invest_transfer(self, transaction_id: str) -> dict:
        return {
            "deep_link": {
                "action": "approve_invest_transfer",
                "action_params": {"transaction_id": str(transaction_id)},
                "action_url": f"{ADMIN_BASE}/authentication/investtransferrequest/",
            }
        }

    # ── Admin: withdrawal request ─────────────────────────────────────────
    def admin_withdrawal(self, withdrawal_id) -> dict:
        return {
            "deep_link": {
                "action": "approve_withdrawal",
                "action_params": {"withdrawal_id": withdrawal_id},
                "action_url": (
                    f"{ADMIN_BASE}/authentication/withdrawalsrequesttoadmin/?o=1.-12"
                ),
            }
        }

    # ── Admin: KYC submitted ──────────────────────────────────────────────
    def admin_kyc_submitted(self) -> dict:
        return {
            "deep_link": {
                "url": (
                    f"{ADMIN_BASE}/authentication/customuser/"
                    "?q=&kyc_status__exact=submitted"
                ),
            }
        }

    # ── Admin: metrics report ─────────────────────────────────────────────
    def admin_metrics(self) -> dict:
        return {
            "deep_link": {
                "url": f"{ADMIN_BASE}/authentication/customuser/",
            }
        }

    # ── User: ROI / earnings updated ──────────────────────────────────────
    def user_earnings(self) -> dict:
        return {"deep_link": {"screen": "Earnings"}}

    # ── User: savings credited ────────────────────────────────────────────
    def user_savings(self) -> dict:
        return {"deep_link": {"screen": "MainTab", "screen_params": {"tab": "Save"}}}

    # ── User: investment credited ─────────────────────────────────────────
    def user_invest(self) -> dict:
        return {"deep_link": {"screen": "MainTab", "screen_params": {"tab": "Invest"}}}

    # ── User: wallet update ───────────────────────────────────────────────
    def user_wallet(self) -> dict:
        return {"deep_link": {"screen": "Wallet"}}

    # ── User: KYC approved ────────────────────────────────────────────────
    def user_kyc_approved(self) -> dict:
        return {"deep_link": {"screen": "KYC"}}

    # ── User: withdrawal processed ────────────────────────────────────────
    def user_withdrawal_done(self) -> dict:
        return {"deep_link": {"screen": "Wallet"}}

    # ── User: target savings deducted ─────────────────────────────────────
    def user_target_savings(self) -> dict:
        return {"deep_link": {"screen": "TargetSavings"}}


# Singleton — import `dl` everywhere
dl = DeepLinks()
