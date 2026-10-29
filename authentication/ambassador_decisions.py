"""Sorting ambassador applications into Qualified / Maybe / Unqualified.

The app suggests a label from a scored rubric (admin always confirms or
changes it), then sending the decision emails + pushes the applicant.

Rubric = the persona of a great MyFund ambassador, from the programme
brief: someone who already saves, influences people positively, builds
communities and drives real financial impact ("not just share flyers"),
can commit to the six months, and has a concrete plan in their own words.
"""
import logging

from django.db import transaction
from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)

LABELS = {"qualified": "Qualified", "maybe": "Maybe", "unqualified": "Unqualified"}
# Application status each decision moves it to. Maybe = waitlist, which can
# still be promoted (or declined) later.
STATUS_FOR = {"qualified": "accepted", "maybe": "shortlisted", "unqualified": "rejected"}
DECIDABLE = ("submitted", "shortlisted")

QUALIFIED_AT = 65
MAYBE_AT = 45

PERSONA = (
    "Already saves (so speaks from real experience), reaches 100+ people a week across "
    "several communities, has promoted something before, can commit to six months of "
    "Saturday meetings and monthly targets, and explains a concrete plan in their own words."
)

REACH_POINTS = {"Over 1,000": 14, "300–1,000": 12, "100–300": 9, "50–100": 5, "Under 50": 2}
HABIT_POINTS = {
    "I save consistently every month": 7, "I save occasionally": 4,
    "I am just starting": 2, "I do not currently save": 0,
}
LEADER_OCCUPATIONS = {"Working Professional", "Business Owner", "Entrepreneur"}
LEADER_COMMUNITIES = {"Church", "Workplace", "Professional Association", "Business Community", "Campus"}


def _text(answers, key):
    return str(answers.get(key) or "").strip()


def _tiered(length, tiers):
    for minimum, points in tiers:
        if length >= minimum:
            return points
    return 0


def score_application(answers, has_video=False):
    """{score 0-100, label, strengths, gaps, leadership, leadership_reasons}."""
    strengths, gaps = [], []
    score = 0

    # Commitment (15) - a "No" here rules them out for this cohort.
    missing = [label for key, label in (("six_months", "the six months"), ("weekly_meetings", "Saturday meetings"),
                                        ("monthly_targets", "monthly targets")) if answers.get(key) != "Yes"]
    if missing:
        gaps.append("Can't commit to " + ", ".join(missing))
    else:
        score += 15
        strengths.append("Fully committed (6 months, Saturdays, targets)")

    # Saves themselves (15).
    saving = (8 if answers.get("has_saved") == "Yes" else 0) + HABIT_POINTS.get(answers.get("saving_habits"), 0)
    score += saving
    if answers.get("has_saved") == "Yes":
        strengths.append("Has saved on MyFund")
    else:
        gaps.append("Hasn't saved on MyFund yet")

    # Community and reach (20).
    communities = [c for c in answers.get("communities") or [] if c]
    score += 6 if len(communities) >= 3 else 4 if len(communities) == 2 else 2 if communities else 0
    reach = answers.get("weekly_reach")
    score += REACH_POINTS.get(reach, 0)
    if REACH_POINTS.get(reach, 0) >= 9:
        strengths.append(f"Reaches {reach} people a week")
    elif reach:
        gaps.append(f"Small weekly reach ({reach})")

    # Influence experience (15).
    if answers.get("has_promoted") == "Yes":
        score += 7 + _tiered(len(_text(answers, "promotion_experience")), [(120, 8), (40, 4)])
        strengths.append("Has promoted or sold before")
    else:
        gaps.append("No promotion experience")

    # Motivation and plan, in their own words (25).
    motivation = _tiered(len(_text(answers, "motivation")), [(300, 10), (120, 6), (40, 3)])
    plan = _tiered(len(_text(answers, "growth_plan")), [(400, 12), (150, 8), (50, 4)])
    products = [p for p in answers.get("products") or [] if p != "I am still learning"]
    score += motivation + plan + (3 if products else 0)
    if plan >= 8:
        strengths.append("Clear, detailed growth plan")
    elif plan <= 4:
        gaps.append("Thin growth plan")
    if motivation <= 3:
        gaps.append("Short motivation")

    # Presence (10).
    has_social = bool(_text(answers, "social_link")) or any(_text(answers, k) for k in answers if k.startswith("link_"))
    score += (5 if has_video else 0) + (3 if has_social else 0) + (2 if answers.get("follow_confirmed") is True else 0)
    if has_video:
        strengths.append("Sent an intro video")

    score = max(0, min(100, score))
    if missing or score < MAYBE_AT:
        label = "unqualified"
    elif score >= QUALIFIED_AT:
        label = "qualified"
    else:
        label = "maybe"

    # Leadership: high scorers who already influence people where they work,
    # worship, study or do business, and aim high.
    leadership_reasons = []
    if label == "qualified" and score >= 75:
        if answers.get("occupation") in LEADER_OCCUPATIONS:
            leadership_reasons.append(answers["occupation"])
        led = sorted(LEADER_COMMUNITIES.intersection(communities))
        if led:
            leadership_reasons.append("Active in " + ", ".join(led))
        if answers.get("signup_target") in ("50", "100+"):
            leadership_reasons.append(f"Aims for {answers['signup_target']} sign-ups in month one")
        if REACH_POINTS.get(reach, 0) >= 12:
            leadership_reasons.append(f"Reaches {reach} a week")
    leadership = len(leadership_reasons) >= 2

    return {
        "score": score, "label": label, "strengths": strengths, "gaps": gaps,
        "leadership": leadership, "leadership_reasons": leadership_reasons if leadership else [],
    }


def suggestion_for(app):
    return score_application(app.answers or {}, has_video=bool(app.answers.get("video_link") or app.video_path))


# ---- Decision messages ------------------------------------------------------
SIGN_OFF = "<br><br>— <b>Chubi</b><br>DME, MyFund"
FROM = "MyFund <hello@myfundmobile.com>"


def _button(url, label):
    return (f'<a href="{url}" style="display:inline-block;padding:12px 22px;border-radius:10px;'
            f'background:#4C28BC;color:#ffffff;text-decoration:none;font-weight:bold">{label}</a>')


def decision_message(app, label, first_name):
    """(subject, html, push_title, push_body) for a decision."""
    intake = app.intake
    hi = f"Hi {first_name},<br><br>"
    if label == "qualified":
        group = (f"<br><br>{_button(intake.group_link, 'Join the Ambassador WhatsApp group')}"
                 if intake.group_link else " We'll share the group link with you shortly.")
        onboarding = f" {intake.onboarding_note}" if intake.onboarding_note else ""
        html = (
            hi + "Congratulations! You have been selected to be part of the <b>MyFund Ambassador Program</b>"
            f" ({intake.title}).<br><br>"
            "Thank you for taking the time to apply and for the thought you put into your answers; "
            "we believe you'll be a great fit.<br><br><b>Next steps</b><br>"
            "1. Join the Ambassador WhatsApp group. This is where all announcements, meeting schedules "
            f"and updates will be shared.{group}<br><br>"
            "2. If you haven't yet created or funded your MyFund account, please do that this week, "
            "so you have real experience to speak from.<br><br>"
            "3. This week you'll complete a Personality Test and get activated to Ambassador status."
            f"{onboarding}<br><br>Once again, congratulations! 🎊🎉<br><br>See you in the group" + SIGN_OFF
        )
        return ("🎉 Congratulations! You've Been Selected As A MyFund Ambassador", html,
                "You've been selected! 🎉",
                f"Congratulations {first_name}, you're in the MyFund Ambassador Program. Check your email for next steps.")
    if label == "maybe":
        html = (
            hi + "Thank you for applying to the <b>MyFund Ambassador Program</b>. We really appreciate the time "
            "and thought you put into your application.<br><br>"
            "We loved your application and we're putting you on the <b>waitlist</b>. We're starting this "
            "cohort with a smaller group right now.<br><br>"
            "This means we're keeping your application on file and plan to open a second batch in about "
            "<b>a month</b>. We'll reach out when it does, and you don't need to resubmit anything.<br><br>"
            "In the meantime, create your MyFund account and start saving. Real experience goes a long way."
            "<br><br>Thanks for your patience.<br><br>Warm regards." + SIGN_OFF
        )
        return ("Your MyFund Ambassador application: you're on our waitlist", html,
                "You're on the Ambassador waitlist",
                f"Thanks {first_name}! We loved your application and you're on our list for the next batch.")
    html = (
        hi + "Thank you for applying to the <b>MyFund Ambassador Program</b> and for the time you put into "
        "your application.<br><br>"
        "We had many strong applications, and we're not able to offer you a place in this cohort.<br><br>"
        "This isn't the end of the road. You're very welcome to apply again for a future cohort, and the "
        "best preparation is real experience: save consistently on MyFund and share what you learn with "
        "the people around you.<br><br>Thank you for wanting to help others grow financially." + SIGN_OFF
    )
    return ("Your MyFund Ambassador application", html,
            "Update on your Ambassador application",
            "Thank you for applying to the MyFund Ambassador Program. Check your email for an update.")


def set_label(app, label):
    if label not in LABELS:
        raise ValidationError("Choose Qualified, Maybe or Unqualified.")
    if app.status not in DECIDABLE:
        raise ValidationError("This application has already been decided.")
    app.review_label = label
    app.save(update_fields=["review_label"])


def send_decision(app):
    """Email + push the applicant their current label, and move the status."""
    from django.utils import timezone

    from .models import CustomUser
    from .utils import send_push_notification, send_transactional_email

    label = app.review_label
    if label not in LABELS:
        raise ValidationError("Choose Qualified, Maybe or Unqualified first.")
    if app.status not in DECIDABLE:
        raise ValidationError("This application has already been decided.")
    if app.decision_sent_label == label:
        raise ValidationError(f"They've already been sent the {LABELS[label]} message.")

    user = app.user or CustomUser.objects.filter(email__iexact=app.email, is_deleted=False).first()
    if user and not app.user_id:
        app.user = user
    app.status = STATUS_FOR[label]
    app.decision_sent_label = label
    app.decision_sent_at = timezone.now()
    app.save(update_fields=["user", "status", "decision_sent_label", "decision_sent_at"])

    first_name = (user.first_name if user else "") or _text(app.answers, "full_name").split(" ")[0] or "there"
    subject, html, push_title, push_body = decision_message(app, label, first_name)

    def notify():
        try:
            send_transactional_email(subject=subject, message=html, recipient_list=[app.email], from_email=FROM)
        except Exception:
            logger.exception("Ambassador decision email failed for %s", app.email)
        if user:
            try:
                send_push_notification(user=user, title=push_title, message=push_body, notif_type="SYSTEM",
                                       data={"type": "AMBASSADOR_APPLICATION", "status": app.status})
            except Exception:
                logger.exception("Ambassador decision push failed for %s", app.email)

    from .ambassador_application_views import _run_in_background
    transaction.on_commit(lambda: _run_in_background(notify))


# ---- Reminders for unfinished (draft) applications --------------------------
REMIND_IDLE = 24   # hours since they last saved: don't nudge someone mid-way
REMIND_GAP = 48    # hours between reminders


def reminder_block(app, now=None):
    """Why a draft can't be reminded right now, or "" if it can."""
    from datetime import timedelta
    from django.utils import timezone

    now = now or timezone.now()
    if app.status != "draft":
        return "Already submitted."
    if not app.reminder_consent:
        return "They didn't ask for reminders when they started."
    if not app.intake.is_open:
        return "Applications for this intake are closed."
    if app.updated_at >= now - timedelta(hours=REMIND_IDLE):
        return "They worked on it in the last 24 hours."
    if app.last_reminded_at and app.last_reminded_at > now - timedelta(hours=REMIND_GAP):
        return "A reminder went out in the last 48 hours."
    return ""


def send_draft_reminder(app):
    """Email an unfinished applicant to finish. Raises ValidationError when
    not allowed; records the reminder only once it's actually sent."""
    from django.utils import timezone

    from .utils import send_transactional_email

    blocked = reminder_block(app)
    if blocked:
        raise ValidationError(blocked)
    programme = app.intake.programme
    first_name = _text(app.answers, "full_name").split(" ")[0] or "there"
    url = f"https://www.myfundmobile.com/{programme}"
    html = (
        f"Hi {first_name},<br><br>"
        f"We noticed you started your <b>MyFund {programme.title()}</b> application but haven't submitted it yet"
        f" (it's {app.progress}% done).<br><br>"
        "It only takes a few minutes to finish. Use the same email, enter the code we send you, and you'll "
        "pick up exactly where you stopped.<br><br>"
        "If you've run into any issues, just reply to this email and we'll help.<br><br>"
        + _button(url, "Finish and Submit My Application") + "<br><br>— <b>MyFund</b>"
    )
    result = send_transactional_email(
        f"Your MyFund {programme.title()} application isn't submitted yet", html, [app.email], from_email=FROM)
    if not result or not result.get("sent"):
        raise ValidationError("The email couldn't be sent. Please try again shortly.")
    # Not applicant activity, so updated_at (their last save) stays as it was.
    type(app).objects.filter(pk=app.pk).update(last_reminded_at=timezone.now(), reminder_count=app.reminder_count + 1)
    app.refresh_from_db()
