# segments.py
#
# Single-source-of-truth classifier for the admin Email tab's Recruitment
# audience segments (Referrers / Consistent Savers / High Balance / Loyal
# & Active / New & Engaged). Deliberately NOT eleven independent querysets
# each re-deriving its own filters - every user is evaluated once, against
# a fixed priority order, and placed in the FIRST segment they match.
# Overlap between segments is therefore structurally impossible (a user
# can only ever be in one bucket's result list), rather than something
# that has to be checked for after the fact.
#
# classify_recruitment_segments() computes everything fresh on every call
# (a handful of aggregate queries, not a persisted column) so a deposit
# made five minutes ago is immediately reflected - nothing here is ever
# written back to CustomUser as a stored "segment" field, which would go
# stale the moment a user's balance/activity changes again.
#
# Known approximations, forced by fields that don't exist yet in this
# codebase (see the 2026-09-04 admin_views.py investigation this was
# built from) - each is called out at its point of use below:
#   - "email verified"        -> is_confirmed (closest existing proxy)
#   - "account closed/suspended" -> is_banned OR is_active=False
#   - "app session"            -> last_active_at (a single last-seen
#                                  timestamp, not a real session log)
#   - "has_ambassador_record"  -> is_ambassador (flat boolean; there is no
#                                  ambassador application/cohort model)
#   - top_decile_balance percentile -> computed in Python, since Postgres
#                                  percentile aggregates aren't available
#                                  here (contrib.postgres isn't installed,
#                                  and dev can fall back to SQLite anyway)

import math
from collections import Counter
from datetime import timedelta

from dateutil.relativedelta import relativedelta
from django.db.models import Exists, F, OuterRef
from django.db.models.functions import TruncMonth
from django.utils import timezone

from .models import CustomUser, Transaction

# "A successful credit into a savings or investment product" - same
# definition already used by not_yet_saved_this_month/engagement_team
# elsewhere in admin_views.py. Deliberately excludes WALLET (a deposit
# has to have actually gone toward saving/investing, not just sit in the
# wallet) and excludes anything not `status='confirmed'` (no reversals,
# no failed/pending transactions).
DEPOSIT_FILTER = dict(
    credited_to__in=["SAVINGS", "INVESTMENT"],
    transaction_type="credit",
    status="confirmed",
)

DEFAULT_COOLING_OFF_DAYS = 7

RECRUITMENT_SEGMENT_ORDER = (
    "referrers",
    "consistent_savers",
    "high_balance",
    "loyal_active",
    "new_engaged",
)

RECRUITMENT_SEGMENT_LABELS = {
    "referrers": "Referrers",
    "consistent_savers": "Consistent Savers",
    "high_balance": "High Balance",
    "loyal_active": "Loyal & Active",
    "new_engaged": "New & Engaged",
}


def _current_balance_expr():
    return F("savings") + F("investment") + F("wallet")


def apply_absolute_suppressions(queryset, now=None, cooling_off_days=DEFAULT_COOLING_OFF_DAYS):
    """
    The suppression list every segment gets, always, not selectable in
    the UI: unsubscribed, hard-bounced, unconfirmed, banned/inactive, or
    emailed too recently. Shared here (not duplicated per-caller) so a
    new suppression reason only ever needs adding in one place.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(days=cooling_off_days)
    return queryset.filter(
        is_deleted=False,
        is_subscribed=True,
        email_undeliverable=False,
        is_confirmed=True,
        is_banned=False,
        is_active=True,
    ).exclude(
        last_campaign_email_sent_at__gte=cutoff,
    )


def suppression_breakdown(queryset, now=None, cooling_off_days=DEFAULT_COOLING_OFF_DAYS):
    """
    How many of `queryset` each individual suppression rule would remove,
    computed independently (not cumulatively) so the confirmation-step UI
    can show "12 unsubscribed, 3 bounced, ..." rather than one opaque
    total. Intentionally NOT mutually exclusive - one address can be both
    unsubscribed and bounced, and should be counted in both reasons.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(days=cooling_off_days)
    base = queryset.filter(is_deleted=False)
    return {
        "unsubscribed": base.filter(is_subscribed=False).count(),
        "hard_bounced": base.filter(email_undeliverable=True).count(),
        "unconfirmed": base.filter(is_confirmed=False).count(),
        "banned_or_inactive": base.filter(
            Exists(
                CustomUser.objects.filter(pk=OuterRef("pk")).filter(
                    F("is_banned") | ~F("is_active")
                )
            )
        ).count()
        if False
        else base.filter(is_banned=True).count() + base.filter(is_active=False).count(),
        "cooling_off": base.filter(last_campaign_email_sent_at__gte=cutoff).count(),
    }


def classify_recruitment_segments(base_queryset=None, now=None, cooling_off_days=DEFAULT_COOLING_OFF_DAYS):
    """
    Evaluates the Recruitment audience's 5 segments in fixed priority
    order (first match wins) over every user who passes the absolute
    suppressions AND the Recruitment-specific gate (never an ambassador,
    at least one lifetime deposit - never-funded users belong in a
    separate reactivation campaign, not recruitment).

    Returns {segment_key: [user_id, ...], "none": [user_id, ...],
    "candidate_count": int}. "none" is funded, non-ambassador users who
    match nothing - expected (see spec this was built from), not a bug.
    """
    now = now or timezone.now()
    queryset = base_queryset if base_queryset is not None else CustomUser.objects.all()

    base = apply_absolute_suppressions(queryset, now=now, cooling_off_days=cooling_off_days)

    deposit_exists = Transaction.objects.filter(user=OuterRef("pk"), **DEPOSIT_FILTER)
    base = base.annotate(has_deposit=Exists(deposit_exists)).filter(
        has_deposit=True, is_ambassador=False,
    )

    candidate_ids = list(base.values_list("id", flat=True))
    empty = {key: [] for key in RECRUITMENT_SEGMENT_ORDER}
    empty["none"] = []
    empty["candidate_count"] = 0
    if not candidate_ids:
        return empty

    # ── Bulk-precompute the "expensive" per-user facts (a handful of
    # queries total, not one per candidate) ──────────────────────────

    # Everyone, system-wide, who's ever made a deposit - used both for
    # "confirmed_referral" (did MY referee deposit) and for
    # top_decile_balance's population (spec: "across all funded users",
    # not just this candidate set).
    deposited_user_ids = set(
        Transaction.objects.filter(**DEPOSIT_FILTER)
        .values_list("user_id", flat=True)
        .distinct()
    )

    # confirmed_referral: a referred user who themselves has >=1 deposit.
    # Signup alone doesn't count (per spec).
    referral_pairs = CustomUser.objects.filter(
        is_deleted=False, referral_id__in=candidate_ids,
    ).values_list("referral_id", "id")
    confirmed_referral_count = Counter()
    for referrer_id, referred_id in referral_pairs:
        if referred_id in deposited_user_ids:
            confirmed_referral_count[referrer_id] += 1

    # deposit_month: a calendar month containing >=1 deposit, over the
    # last 6 COMPLETE months (current partial month excluded, per spec).
    this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    six_months_ago = this_month_start - relativedelta(months=6)
    month_rows = (
        Transaction.objects.filter(
            user_id__in=candidate_ids,
            date__gte=six_months_ago,
            date__lt=this_month_start,
            **DEPOSIT_FILTER,
        )
        .annotate(month=TruncMonth("date"))
        .values("user_id", "month")
        .distinct()
    )
    deposit_month_count = Counter()
    for row in month_rows:
        deposit_month_count[row["user_id"]] += 1

    recent_60_cutoff = now - timedelta(days=60)
    recent_deposit_ids = set(
        Transaction.objects.filter(
            user_id__in=candidate_ids, date__gte=recent_60_cutoff, **DEPOSIT_FILTER,
        )
        .values_list("user_id", flat=True)
        .distinct()
    )

    rows = base.values("id", "savings", "investment", "wallet", "date_joined", "last_active_at")
    balances, signup_dates, last_active = {}, {}, {}
    for row in rows:
        balances[row["id"]] = (row["savings"] or 0) + (row["investment"] or 0) + (row["wallet"] or 0)
        signup_dates[row["id"]] = row["date_joined"]
        last_active[row["id"]] = row["last_active_at"]

    # top_decile_balance - 90th percentile of current balance across
    # EVERY funded user in the whole system (not just this candidate
    # set), computed in Python (see module docstring on why).
    all_funded_balances = sorted(
        CustomUser.objects.filter(is_deleted=False, id__in=deposited_user_ids)
        .annotate(bal=_current_balance_expr())
        .values_list("bal", flat=True)
    )
    top_decile_balance = None
    if all_funded_balances:
        idx = max(0, math.ceil(0.90 * len(all_funded_balances)) - 1)
        top_decile_balance = all_funded_balances[idx]

    fourteen_days_ago = now - timedelta(days=14)
    signup_180_cutoff = now - timedelta(days=180)

    result = {key: [] for key in RECRUITMENT_SEGMENT_ORDER}
    result["none"] = []

    for uid in candidate_ids:
        if confirmed_referral_count.get(uid, 0) >= 1:
            result["referrers"].append(uid)
        elif deposit_month_count.get(uid, 0) >= 4:
            result["consistent_savers"].append(uid)
        elif top_decile_balance is not None and balances.get(uid, 0) >= top_decile_balance:
            result["high_balance"].append(uid)
        elif signup_dates[uid] <= signup_180_cutoff and uid in recent_deposit_ids:
            result["loyal_active"].append(uid)
        elif (
            signup_dates[uid] > signup_180_cutoff
            and uid in deposited_user_ids
            and last_active.get(uid) is not None
            and last_active[uid] >= fourteen_days_ago
        ):
            result["new_engaged"].append(uid)
        else:
            result["none"].append(uid)

    result["candidate_count"] = len(candidate_ids)
    return result
