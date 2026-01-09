# december_savings_report.py

import os
import django
from decimal import Decimal
from datetime import datetime

# 🔹 Django setup MUST come first
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from django.utils import timezone
from authentication.models import CustomUser
from authentication.models import Transaction

# 🔹 Date range (December)
start_date = timezone.make_aware(datetime(2025, 12, 1, 0, 0, 0))
end_date = timezone.make_aware(datetime(2025, 12, 31, 23, 59, 59))

emails = [
    "iyinoluwaadedoyin@gmail.com",
    "martolu2006@gmail.com",
    "ofeimunjudith@gmail.com",
    "aregold44@gmail.com",
    "oyelakinakolade52@gmail.com",
    "simysola22@gmail.com",
    "olorunfemiprecious2109@gmail.com",
    "anniejhnson45@gmail.com",
    "danzydavid44@gmail.com",
    "godwinpraise372@gmail.com",
    "dikaiosunemay@gmail.com",
    "vancedmist@gmail.com",
    "okechukwusimone@gmail.com",
    "nyiayaanabariagara@gmail.com",
    "adequateugbong@gmail.com",
    "okohfaithehikis@gmail.com",
    "kamsiprince8@gmail.com",
    "tochirex7@gmail.com",
    "igbegbegracious6@gmail.com",
]

CREDIT_KEYWORDS = [
    "quicksave",
    "autosave",
    "quickinvest",
    "autoinvest",
    "wallet to savings",
    "wallet > savings",
]

DEBIT_KEYWORDS = [
    "savings to wallet",
    "investment to wallet",
    "savings to bank",
    "investment to bank",
    "withdraw",
]

print("\n📊 DECEMBER SAVINGS REPORT")
print("-" * 45)

for email in emails:
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        print(f"{email} ❌ USER NOT FOUND")
        continue

    txns = Transaction.objects.filter(
        user=user,
        status="confirmed",
        date__range=(start_date, end_date),
    )

    total_credit = Decimal("0.00")
    total_debit = Decimal("0.00")

    for t in txns:
        desc = (t.description or "").lower()

        if t.transaction_type == "credit":
            if any(k in desc for k in CREDIT_KEYWORDS) or t.source in [
                "SAVINGS",
                "INVESTMENT",
            ]:
                total_credit += t.amount

        elif t.transaction_type == "debit":
            if any(k in desc for k in DEBIT_KEYWORDS):
                total_debit += t.amount

    net = total_credit - total_debit

    print(
        f"""
{email}
  ➕ Credited: ₦{total_credit}
  ➖ Debited:  ₦{total_debit}
  ✅ Net Dec Savings: ₦{net}
"""
    )

print("✅ Done.\n")
