# cohort3_performance_summary_email.py
#
# Personalized email + push to every Cohort 3 ambassador: their last 5
# months of performance (April-August 2026) plus a push toward the
# Cohort 3 Award & Send-Forth Programme on September 26th. Each
# ambassador's table is genuinely different (their own monthly signups/
# confirmed/attendance/points), so this can't go through the app's
# single-token campaign compose flow - same pattern as
# december_ambassador_stipends.py: one send_generic_email call per
# person with that person's own fully-built HTML.
#
# Sent "personal style" - authentication/templates/email/email_plain.html,
# no branded header/logo, minimal footer - meant to read like Dr Tee
# actually wrote it, not a broadcast.
#
# SEND_MODE controls what happens:
#   "preview" - renders everything, sends nothing (default).
#   "test"    - sends every ambassador's real content to TEST_EMAILS.
#   "live"    - sends to all 13 Cohort 3 ambassadors for real, plus a
#               push notification to each pointing them at their inbox.
#
# SEND_SAMPLE (independent of SEND_MODE) - sends ONE illustrative sample
# (cohort-average numbers, addressed "Ambassador" - never a real
# individual's data) to SAMPLE_EMAILS, so non-ambassador reviewers can
# see the format without any real ambassador's private figures leaking
# to people who aren't them.

import os
import json
import django
from decimal import Decimal

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from django.db.models import Avg
from authentication.models import CustomUser, AmbassadorMonthlyReport, AmbassadorCohort
from authentication.utils import send_generic_email, send_transactional_email, send_push_notification

# ------------------ CONFIG ------------------
SEND_MODE = "preview"  # "preview" | "test" | "live"
TEST_EMAILS = ["tolulopeahmed@gmail.com", "company@myfundmobile.com"]

# Brevo hit its 300/day cap today (2026-09-18) before this batch could
# fully send - see get_brevo_usage_today(). Resend still has headroom
# (transactional-sender, separate quota - see resend_service.py), so this
# run goes through send_transactional_email (Resend-first, Brevo-fallback)
# instead of send_generic_email (Brevo-only). Only 13 sends needed and
# Resend's remaining credit today is small (<20), so SEND_PUSH stays False
# here - the push already went out successfully in the earlier Brevo-mode
# run and doesn't need to be repeated.
USE_RESEND = True
SEND_PUSH = False

SEND_SAMPLE = False
SAMPLE_EMAILS = [
    "janet.adegbenro@gmail.com",
    "josephgideon@gmail.com",
    "ceo@myfundmobile.com",
]

PLAIN_TEMPLATE = "email/email_plain.html"  # "personal style" - no header/footer

MONTHS = ["2026-04", "2026-05", "2026-06", "2026-07", "2026-08"]
MONTH_LABELS = {
    "2026-04": "April", "2026-05": "May", "2026-06": "June",
    "2026-07": "July", "2026-08": "August",
}
AWARD_DATE = "September 26th"

# ------------------ SHARED RENDERING ------------------

def rows_to_html_table(rows):
    header = (
        '<tr style="background-color:#4C28BC;color:#ffffff;">'
        '<th style="padding:8px 10px;text-align:left;">Month</th>'
        '<th style="padding:8px 10px;text-align:center;">Signups</th>'
        '<th style="padding:8px 10px;text-align:center;">Confirmed</th>'
        '<th style="padding:8px 10px;text-align:center;">Attendance</th>'
        '<th style="padding:8px 10px;text-align:center;">Points</th>'
        "</tr>"
    )
    body_rows = "".join(
        '<tr style="border-bottom:1px solid #E5E7EB;">'
        f'<td style="padding:8px 10px;">{r["month"]}</td>'
        f'<td style="padding:8px 10px;text-align:center;">{r["signups"]}</td>'
        f'<td style="padding:8px 10px;text-align:center;">{r["confirmed"]}</td>'
        f'<td style="padding:8px 10px;text-align:center;">{r["attendance"]}</td>'
        f'<td style="padding:8px 10px;text-align:center;">{r["points"]:.2f}</td>'
        "</tr>"
        for r in rows
    )
    return (
        '<table style="border-collapse:collapse;width:100%;max-width:480px;'
        'font-family:sans-serif;font-size:14px;">'
        f"{header}{body_rows}</table>"
    )


def encouragement_line(rows, name):
    recent = rows[-1]["points"]
    prior = [r["points"] for r in rows[:-1]]
    prior_avg = sum(prior) / len(prior) if prior else 0
    if recent >= prior_avg and recent > 0:
        return f"You're finishing strong, {name} - keep that energy going into this final stretch."
    if sum(r["points"] for r in rows) == 0:
        return (
            f"There's still time to get on the board this month, {name} - "
            f"every signup and session attended between now and {AWARD_DATE} counts."
        )
    return f"Let's bring that energy back up this September, {name} - you've already shown you can do more."


def build_body(name, rows, total_points, best):
    table_html = rows_to_html_table(rows)
    line = encouragement_line(rows, name)
    best_line = (
        f"<p>Your standout month was <strong>{best['month']}</strong> with "
        f"<strong>{best['points']:.2f} points</strong>.</p>"
        if best
        else ""
    )
    return f"""
    <p>Hi {name},</p>
    <p>Here's a quick look at your MyFund Ambassador performance over the last 5 months:</p>
    {table_html}
    <p style="margin-top:14px;"><strong>Total points (last 5 months): {total_points:.2f}</strong></p>
    {best_line}
    <p>{line}</p>
    <p>The <strong>Cohort 3 Award &amp; Send-Forth Programme</strong> is coming up on
    <strong>{AWARD_DATE}</strong> - this final stretch is your chance to finish strong
    before we celebrate everything this cohort has built. Every signup, confirmed
    referral, and session attended between now and then still counts.</p>
    <p>Let's make this last push count 💪</p>
    <p>Cheers,<br><strong>Tolulope Ahmed (Dr Tee)</strong><br>CEO, MyFund</p>
    """


# ------------------ PER-AMBASSADOR CONTENT ------------------

def build_rows_for_user(user):
    reports = {
        r.month: r
        for r in AmbassadorMonthlyReport.objects.filter(user=user, month__in=MONTHS)
    }
    rows = []
    total_points = Decimal("0.00")
    best = None
    for m in MONTHS:
        r = reports.get(m)
        pts = r.total_points_awarded if r else Decimal("0.00")
        row = {
            "month": MONTH_LABELS[m],
            "signups": r.signups_approved if r else 0,
            "confirmed": r.confirmed_approved if r else 0,
            "attendance": r.attendance_approved if r else 0,
            "points": float(pts),
        }
        rows.append(row)
        total_points += pts
        if r and (best is None or pts > Decimal(str(best["points"]))):
            best = row
    return rows, float(total_points), best


def build_ambassador_email(user):
    rows, total_points, best = build_rows_for_user(user)
    subject = f"{user.first_name}, your last 5 months + one more push before {AWARD_DATE} 🏆"
    html_message = build_body(user.first_name, rows, total_points, best)
    return subject, html_message, {
        "email": user.email, "first_name": user.first_name,
        "rows": rows, "total_points": round(total_points, 2),
        "best_month": best["month"] if best else None,
    }


# ------------------ SAMPLE (illustrative, cohort-average, non-ambassadors) ------------------

def build_sample_rows(ambassadors):
    rows = []
    total_points = 0.0
    best = None
    for m in MONTHS:
        agg = AmbassadorMonthlyReport.objects.filter(
            user__in=ambassadors, month=m
        ).aggregate(s=Avg("signups_approved"), c=Avg("confirmed_approved"),
                    a=Avg("attendance_approved"), p=Avg("total_points_awarded"))
        pts = round(float(agg["p"] or 0), 2)
        row = {
            "month": MONTH_LABELS[m],
            "signups": round(agg["s"] or 0),
            "confirmed": round(agg["c"] or 0),
            "attendance": round(agg["a"] or 0),
            "points": pts,
        }
        rows.append(row)
        total_points += pts
        if best is None or pts > best["points"]:
            best = row
    return rows, total_points, best


def build_sample_email(ambassadors):
    rows, total_points, best = build_sample_rows(ambassadors)
    subject = f"[SAMPLE] Ambassador, your last 5 months + one more push before {AWARD_DATE} 🏆"
    body = build_body("Ambassador", rows, total_points, best)
    sample_note = (
        '<p style="background:#FEF3C7;border:1px solid #F59E0B;border-radius:6px;'
        'padding:10px 14px;font-size:13px;color:#92400E;">'
        "⚠️ SAMPLE ONLY - illustrative, cohort-average numbers, not a real "
        "ambassador's data. Each actual ambassador receives their own real "
        "figures and name, not this generic version.</p>"
    )
    return subject, sample_note + body


# ------------------ RUN ------------------

def main():
    cohort3 = AmbassadorCohort.objects.get(cohort_number=3)
    ambassadors = CustomUser.objects.filter(
        ambassador_cohort=cohort3, is_ambassador=True
    ).order_by("first_name")

    preview_data = []
    print(f"\n📊 COHORT 3 PERFORMANCE SUMMARY — mode: {SEND_MODE}, sample: {SEND_SAMPLE}\n" + "-" * 50)

    for user in ambassadors:
        subject, html_message, meta = build_ambassador_email(user)
        preview_data.append({"subject": subject, "html": html_message, **meta})

        if SEND_MODE == "preview":
            print(f"{user.email} — previewed only, not sent")
            continue

        recipients = TEST_EMAILS if SEND_MODE == "test" else [user.email]
        send_fn = send_transactional_email if USE_RESEND else send_generic_email
        send_fn(
            subject=subject,
            message=html_message,
            recipient_list=recipients,
            template=PLAIN_TEMPLATE,
        )
        provider = "Resend" if USE_RESEND else "Brevo"
        print(f"EMAIL {user.email} — sent to {', '.join(recipients)} via {provider} ({SEND_MODE} mode)")

        if SEND_MODE == "live" and SEND_PUSH:
            send_push_notification(
                user=user,
                title="Your Cohort 3 Report is In! 📬",
                message=(
                    f"Hi {user.first_name}, your last 5 months of Ambassador "
                    f"performance just landed in your inbox - check it out! "
                    f"Let's finish strong toward the Award & Send-Forth "
                    f"Programme on {AWARD_DATE} 🏆"
                ),
                data={"type": "ambassador_performance_summary"},
                notif_type="AMBASSADOR",
            )
            print(f"PUSH  {user.email} — sent")

    with open("/tmp/cohort3_performance_emails_preview.json", "w") as f:
        json.dump(preview_data, f, indent=2)
    print(f"\n✅ Preview data for {len(preview_data)} ambassadors written to "
          "/tmp/cohort3_performance_emails_preview.json")

    if SEND_SAMPLE:
        subject, html_message = build_sample_email(ambassadors)
        if SEND_MODE == "preview":
            print(f"\nSAMPLE — previewed only, not sent to {SAMPLE_EMAILS}")
        else:
            send_fn = send_transactional_email if USE_RESEND else send_generic_email
            send_fn(
                subject=subject,
                message=html_message,
                recipient_list=SAMPLE_EMAILS,
                template=PLAIN_TEMPLATE,
            )
            print(f"\nSAMPLE — sent to {', '.join(SAMPLE_EMAILS)}")


if __name__ == "__main__":
    main()
