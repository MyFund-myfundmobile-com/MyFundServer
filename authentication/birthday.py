"""Personal birthday greetings - push, email and SMS built from the saver's
own MyFund journey (balance, dividends, streak, goals, Top Saver finishes,
referrals), reusing the Active Saver personalisation helpers.

Who is greeted: active, unbanned, KYC completed (approved; legacy "true",
or submitted for review), with a real date of birth. 1900-01-01 is the
placeholder the sign-up flow stores when no DOB was given - ~2.8k users
have it, so it must never count as a birthday.
"""
import logging
from datetime import timedelta
from decimal import Decimal

from django.db.models import Sum
from django.utils import timezone
from django.utils.html import escape

logger = logging.getLogger(__name__)

KYC_DONE = ("approved", "true", "submitted", "Pending...")
PLACEHOLDER_DOB_YEAR = 1900

# Each channel reaches the celebrant at a different time of day (Lagos time):
# push first thing, email around late morning, SMS mid-afternoon. The task
# runs hourly and sends at most ONE channel per user per run, each at least
# MIN_GAP after the previous one - so even a late deploy/restart keeps them
# spread out instead of firing all three together.
CHANNEL_HOURS = (("push", 8), ("email", 11), ("sms", 15))
MIN_GAP = timedelta(minutes=50)


def next_channel(greeting, now, channels=CHANNEL_HOURS):
    """Name of the channel to send now for this BirthdayGreeting, or None."""
    local_hour = timezone.localtime(now).hour
    previous = None
    for name, hour in channels:
        sent_at = getattr(greeting, f"{name}_sent_at")
        if sent_at:
            previous = sent_at
            continue
        if local_hour < hour or (previous and now - previous < MIN_GAP):
            return None
        return name
    return None


def birthday_users(today):
    from .models import CustomUser

    return (CustomUser.objects
            .filter(is_active=True, is_banned=False, is_deleted=False, kyc_status__in=KYC_DONE,
                    date_of_birth__month=today.month, date_of_birth__day=today.day)
            .exclude(date_of_birth__year=PLACEHOLDER_DOB_YEAR)
            .exclude(email=""))


def _naira(amount):
    return f"₦{Decimal(amount or 0):,.0f}"


def _plural(n, word, plural=None):
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _span(months):
    years, rest = divmod(months, 12)
    return " and ".join(p for p in (_plural(years, "year") if years else "",
                                     _plural(rest, "month") if rest else "") if p)


def highlights_for(user, now=None):
    from .active_saver_views import _month_index, previous_month, saving_streak
    from .models import CustomUser, TargetSavings, TopSaverHistory, Transaction

    now = now or timezone.now()
    out = []
    months_with_us = max(0, _month_index(now.month, now.year)
                         - _month_index(user.date_joined.month, user.date_joined.year))

    balance = (user.savings or Decimal("0")) + (user.investment or Decimal("0"))
    if balance > 0:
        out.append(f"You've built {_naira(balance)} in savings and investments with MyFund.")

    dividends = (Transaction.objects.filter(user=user, transaction_type="credit", status="confirmed",
                                            description__istartswith="Dividends")
                 .aggregate(total=Sum("amount"))["total"] or Decimal("0"))
    if dividends > 0:
        out.append(f"Your money has earned you {_naira(dividends)} in dividends so far.")

    month, year = previous_month(now)
    streak = saving_streak(user, month, year)
    if streak >= 2:
        out.append(f"You've grown your savings {streak} months in a row. That's real discipline.")

    if user.properties:
        out.append(f"You co-own {_plural(int(user.properties), 'property', 'properties')} through MyFund.")

    goal = (TargetSavings.objects.filter(user=user, is_active=True, target_amount__gt=0)
            .order_by("-current_amount").first())
    if goal and goal.current_amount:
        progress = min(100, int(goal.current_amount * 100 / goal.target_amount))
        out.append(f"You're {progress}% of the way to your “{goal.name}” goal.")

    top3 = (TopSaverHistory.objects.filter(user=user, rank__lte=3).exclude(month=now.month, year=now.year)
            .values("month", "year").distinct().count())
    if top3:
        out.append(f"You've been one of MyFund's Top Savers of the Month {_plural(top3, 'time')}.")

    referred = CustomUser.objects.filter(referral=user, is_deleted=False).count()
    if referred:
        out.append(f"You've invited {_plural(referred, 'person', 'people')} to start saving with MyFund.")

    return out, months_with_us


def birthday_message(user, now=None):
    now = now or timezone.now()
    name = (user.first_name or "").strip() or "there"
    try:
        highlights, months_with_us = highlights_for(user, now)
    except Exception:
        logger.exception("Birthday highlights failed for %s", user.pk)
        highlights, months_with_us = [], 0

    if months_with_us >= 12:
        tenure = f"You've been part of the MyFund family for {_span(months_with_us)}, and we're grateful for every month of it."
        sms_thanks = f"Thank you for {_plural(months_with_us // 12, 'year')} of saving with us."
    else:
        tenure = "This is your first birthday with MyFund, and we're so glad you're here."
        sms_thanks = "We're so glad you're saving with us."

    if highlights:
        push_body = f"Happy birthday from MyFund! {highlights[0]} Here's to a year of even bigger wins."
    else:
        push_body = "The MyFund team wishes you a happy and memorable birthday. Long life and prosperity!"

    return {
        "name": name,
        "tenure": tenure,
        "highlights": highlights,
        "subject": f"🎂 Happy Birthday, {name}! Celebrating your MyFund journey" if highlights
        else f"🎂 Happy Birthday, {name}!",
        "push_title": f"🎂 Happy Birthday, {name}!",
        "push_body": push_body,
        # Plain GSM text (no emoji/curly quotes) keeps this to one SMS page.
        "sms": (f"Happy Birthday, {name}! The MyFund team is celebrating you today. {sms_thanks} "
                f"Here's to more financial wins this year!"),
    }


def birthday_email_html(msg):
    """Body for send_generic_email's email/email.html wrapper."""
    parts = [
        "<p style='font-size:36px;margin:0 0 8px;'>🎂</p>",
        f"<h2 style='margin:0 0 14px;'>Happy Birthday, {escape(msg['name'])}!</h2>",
        f"<p>Today the whole MyFund team is celebrating you. {msg['tenure']}</p>",
    ]
    if msg["highlights"]:
        items = "".join(f"<li style='margin:0 0 8px;'>{escape(line)}</li>" for line in msg["highlights"])
        parts += [
            "<p style='margin:22px 0 8px;font-weight:bold;color:#4C28BC;'>Look how far you've come</p>",
            f"<ul style='padding-left:20px;margin:0 0 16px;line-height:1.5;'>{items}</ul>",
            "<p>Every one of those milestones came from a choice you made to show up for your future. "
            "We're proud to be part of the journey.</p>",
        ]
    else:
        parts.append("<p>Every great financial journey starts with a single step, and we'll be right "
                     "here to help you take the next one.</p>")
    parts.append("<p>May this new year bring you good health, growth and many more financial wins. 🥳</p>"
                 "<p>With love,<br><strong>The MyFund Team</strong></p>")
    return "".join(parts)
