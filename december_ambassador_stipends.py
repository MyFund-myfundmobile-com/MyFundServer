# december_ambassador_stipends.py

import os
import django
from decimal import Decimal
from django.utils import timezone
import random

# ---- Django setup ----
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from authentication.models import CustomUser
from authentication.models import Transaction
from authentication.utils import send_generic_email, send_push_notification

# ------------------ CONFIG ------------------

# 🔹 TEST MODE
# True = only pay tolulopeahmed@gmail.com
# False = pay all ambassadors in the dictionary
TEST_MODE = False
TEST_EMAIL = "tolulopeahmed@gmail.com"

# Ambassador stipend amounts (in hundreds)
AMBASSADOR_PAYOUTS = {
    "iyinoluwaadedoyin@gmail.com": 129,
    "martolu2006@gmail.com": 62,
    "ofeimunjudith@gmail.com": 115,
    "aregold44@gmail.com": 22,
    "oyelakinakolade52@gmail.com": 23,
    "simysola22@gmail.com": 23,
    "olorunfemiprecious2109@gmail.com": 35,
    "anniejhnson45@gmail.com": 70,
    "danzydavid44@gmail.com": 10,
    "godwinpraise372@gmail.com": 150,
    "dikaiosunemay@gmail.com": 5,
    "vancedmist@gmail.com": 39,
    "okechukwusimone@gmail.com": 10,
    "nyiayaanabariagara@gmail.com": 0,
    "adequateugbong@gmail.com": 0,
    "okohfaithehikis@gmail.com": 0,
    "kamsiprince8@gmail.com": 0,
    "tochirex7@gmail.com": 0,
    "igbegbegracious6@gmail.com": 0,
}

if TEST_MODE:
    # Only run for test email
    AMBASSADOR_PAYOUTS = {TEST_EMAIL: 1}

# ------------------ PROCESS ------------------

print("\n💰 DECEMBER AMBASSADOR STIPENDS\n" + "-" * 45)

for email, units in AMBASSADOR_PAYOUTS.items():
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        print(f"{email} ❌ USER NOT FOUND")
        continue

    # Convert to Naira (units * 100)
    amount = Decimal(units) * Decimal("100")

    # --- ZERO PAYOUT (Encouragement Only) ---
    if amount <= 0:
        subject = "[Ambassador Stipends] Your effort matters"

        # Well-formatted HTML message with paragraphs and spacing
        html_message = f"""
        <p>Hi {user.first_name or 'there'},</p>

        <p>Happy New Year! 🎉</p>

        <p>I just want to say well done for all the effort you put in as a MyFund Ambassador so far.</p>

        <p>There’s no stipend this time, but I see your hustle. The new year and this month is another oppotunity to give your best and get more results.</p>

        <p><strong>My advice:</strong> This January, focus on getting more signups and keeping savers active. Keep an eye on the Savings Challenge page to track your progress and get even bigger rewards by monthend!</p>

        <p>Be the best! 💪</p>

        <p>Cheers,<br>
        Tolulope Ahmed (Dr Tee)<br>
        CEO, MyFund</p>
        """

        send_generic_email(
            subject=subject, message_or_context=html_message, recipient_list=[email]
        )

        send_push_notification(
            user=user,
            title="[December Stipends] Keep going 🚀",
            message=f"Hi {user.first_name or 'there'}, We see your effort even though you didn't earn a stipend this month. Let's make the next month count!",
            data={"type": "ambassador_encouragement"},
            notif_type="AMBASSADOR",
        )

        print(f"{email} 📨 Encouragement sent")
        continue

    # --- CREDIT WALLET ---
    user.wallet += amount
    user.save(update_fields=["wallet"])

    # --- CREATE TRANSACTION ---
    transaction_id = (
        f"AMB_{timezone.now().strftime('%Y%m%d')}_{random.randint(1000,9999)}"
    )

    Transaction.objects.create(
        user=user,
        transaction_type="credit",
        status="confirmed",
        amount=amount,
        source="WALLET",
        description="December Amb. Stipend",
        date=timezone.now().date(),
        time=timezone.now().time(),
        transaction_id=transaction_id,
    )

    # --- SEND NOTIFICATIONS ---
    subject = "December Ambassador Stipend 🎉"

    # Well-formatted HTML message with paragraphs and spacing
    html_message = f"""
    <p>Hi {user.first_name or 'there'},</p>
    
    <p>Your December Ambassador stipend of <strong>₦{amount:,.0f}</strong> has been credited to your wallet.</p>
    
    <p>Thank you for representing MyFund and pushing the mission forward! 🚀</p>
    
    <p><strong>Important Reminder:</strong> This January, focus on increasing your signups and active savers. Keep your eyes on the Savings Challenge page to track your progress and earn more rewards in the coming months!</p>
    
    <p>Your continued effort is what helps us grow the MyFund community and achieve financial freedom for everyone.</p>
    
    <p>More is expected of you this month as your cohort is gradually coming to an end 🥂</p>
    
    <p>Cheers,<br>
        <b>Tolulope Ahmed (Dr Tee)<br></b>
        CEO, MyFund</p>
    """

    send_generic_email(
        subject=subject, message_or_context=html_message, recipient_list=[email]
    )

    send_push_notification(
        user=user,
        title="December Stipend Credited 🎉",
        message=f"Hi {user.first_name or 'there'}, ₦{amount:,.0f} has been added to your Wallet as your December Ambassador Stipend. Do more this month to earn more.",
        data={"amount": str(amount), "type": "ambassador_stipend"},
        notif_type="AMBASSADOR",
    )

    print(f"{email} ✅ Credited ₦{amount:,.0f}")

print("\n✅ PROCESS COMPLETED\n")
