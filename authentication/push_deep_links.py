# authentication/push_deep_links.py
import urllib.parse

ADMIN_BASE = "https://myfundapi-myfund-07ce351a.koyeb.app/admin"

WHATSAPP_WELCOME = (
    "Welcome to MyFund! \n"
    "Please feel free to reach out here if you encounter any challenge using MyFund.\n"
    "Jane."
)


def _wa_url(phone, message):
    digits = "".join(c for c in (phone or "") if c.isdigit())
    if digits.startswith("0") and len(digits) == 11:
        digits = "234" + digits[1:]
    return "https://wa.me/" + digits + "?text=" + urllib.parse.quote(message)


def _mailto_url(email, subject="", body=""):
    params = urllib.parse.urlencode({"subject": subject, "body": body})
    return "mailto:" + email + "?" + params


class DeepLinks:

    def admin_new_user(self, phone, email):
        return {
            "deep_link": {
                "url": _wa_url(phone, WHATSAPP_WELCOME),
                "fallback_url": _mailto_url(
                    email, subject="Welcome to MyFund!", body=WHATSAPP_WELCOME
                ),
            },
            "category": "ADMIN_NEW_USER",
            "wa_url": _wa_url(phone, WHATSAPP_WELCOME),
            "email_url": _mailto_url(
                email, subject="Welcome to MyFund!", body=WHATSAPP_WELCOME
            ),
        }

    def admin_bank_transfer(self, transaction_id):
        return {
            "deep_link": {
                "action": "approve_bank_transfer",
                "action_params": {"transaction_id": str(transaction_id)},
                "action_url": ADMIN_BASE + "/authentication/banktransferrequest/",
            },
            "category": "ADMIN_BANK_TRANSFER",
            "transaction_id": str(transaction_id),
            "action_url": ADMIN_BASE + "/authentication/banktransferrequest/",
        }

    def admin_invest_transfer(self, transaction_id):
        return {
            "deep_link": {
                "action": "approve_invest_transfer",
                "action_params": {"transaction_id": str(transaction_id)},
                "action_url": ADMIN_BASE + "/authentication/investtransferrequest/",
            },
            "category": "ADMIN_INVEST_TRANSFER",
            "transaction_id": str(transaction_id),
            "action_url": ADMIN_BASE + "/authentication/investtransferrequest/",
        }

    def admin_withdrawal(self, withdrawal_id):
        return {
            "deep_link": {
                "action": "approve_withdrawal",
                "action_params": {"withdrawal_id": str(withdrawal_id)},
                "action_url": ADMIN_BASE
                + "/authentication/withdrawalsrequesttoadmin/?o=1.-12",
            },
            "category": "ADMIN_WITHDRAWAL",
            "withdrawal_id": str(withdrawal_id),
            "action_url": ADMIN_BASE
            + "/authentication/withdrawalsrequesttoadmin/?o=1.-12",
        }

    def admin_kyc_submitted(self):
        return {
            "deep_link": {
                "url": ADMIN_BASE
                + "/authentication/customuser/?q=&kyc_status__exact=submitted",
            },
            "category": "ADMIN_KYC",
            "action_url": ADMIN_BASE
            + "/authentication/customuser/?q=&kyc_status__exact=submitted",
        }

    def admin_metrics(self):
        return {
            "deep_link": {"url": ADMIN_BASE + "/authentication/customuser/"},
            "category": "ADMIN_METRICS",
        }

    def user_earnings(self):
        return {"deep_link": {"screen": "Earnings"}, "category": "USER_EARNINGS"}

    def user_savings(self):
        return {
            "deep_link": {"screen": "MainTab", "screen_params": {"tab": "Save"}},
            "category": "USER_SAVINGS",
        }

    def user_invest(self):
        return {
            "deep_link": {"screen": "MainTab", "screen_params": {"tab": "Invest"}},
            "category": "USER_INVEST",
        }

    def user_wallet(self):
        return {"deep_link": {"screen": "Wallet"}, "category": "USER_WALLET"}

    def user_kyc_approved(self):
        return {"deep_link": {"screen": "KYC"}, "category": "USER_KYC"}

    def user_withdrawal_done(self):
        return {"deep_link": {"screen": "Wallet"}, "category": "USER_WALLET"}

    def user_target_savings(self):
        return {"deep_link": {"screen": "TargetSavings"}, "category": "USER_TARGET"}


dl = DeepLinks()
