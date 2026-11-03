"""Hosted, signed-link Active Saver interview (www.myfundmobile.com/activesaver/interview).

For consistent savers who weren't that month's Top 3 (those get the Top
Saver form): a warm, personalised invite to share their story for MyFund's
marketing and tell us what to fix. Same plumbing as the Top Saver form
(top_saver_views.py) - signed link instead of a login, autosave, team
alerts on start / booking / submit, Calendly live interview - kept on its
own model so the two queues never mix.

A preview link (``preview_link``) shows the form exactly as one saver would
see it, but saves nothing and alerts nobody.
"""
import base64
import datetime
import logging
import secrets
from decimal import Decimal

from django.core import signing
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.html import escape
from rest_framework.decorators import api_view, authentication_classes, parser_classes, permission_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import ActiveSaverInterview, CustomUser, Employee, TargetSavings, TopSaverHistory, Transaction
from .top_saver_views import (CALENDLY_INTERVIEW_URL, CLAIM_SALT, FROM, UPLOAD_KINDS, _button, _eligible_months,
                              _interview_team, _is_booked, _sniff, private_url)
from .utils import send_push_notification

logger = logging.getLogger(__name__)
TOKEN_SALT = "myfund.active-saver.interview.v1"
TOKEN_MAX_AGE = 60 * 60 * 24 * 90
PREVIEW_SALT = "myfund.active-saver.preview.v1"
PREVIEW_MAX_AGE = 60 * 60 * 24 * 7

# Who's invited each month (invite_active_savers_of_month, 1st of the month):
# saved more than they withdrew in each of at least MIN_STREAK months in a
# row, ending with the month that just ended - and not in its Top 3.
MIN_STREAK = 3
# Most-consistent first, so a big month doesn't flood the team's queue.
MAX_INVITES_PER_MONTH = 25
# Nobody is asked again within this many months of their last invite.
REINVITE_AFTER_MONTHS = 3
# Team and company accounts never get invited.
EXCLUDED_EMAILS = {"company@myfundmobile.com", "info@myfundmobile.com"}

# Four content questions, a live-interview offer and a rating - short and
# warm rather than a survey. "challenges" is how issues reach the team.
QUESTIONS = [
    {"key": "saving_for", "type": "textarea", "required": True, "maxLength": 500,
     "label": "What are you saving towards right now?",
     "help": "A home, school fees, a business, japa, peace of mind... anything goes."},
    {"key": "impact", "type": "textarea", "required": True, "maxLength": 2000,
     "label": "How has saving with MyFund changed things for you?",
     "help": "In your own words. A few sentences is perfect."},
    {"key": "proud_moment", "type": "textarea", "required": False, "maxLength": 1500,
     "label": "What's one moment you felt proud of your progress?"},
    {"key": "challenges", "type": "textarea", "required": False, "maxLength": 3000,
     "label": "Is there anything about MyFund that's been difficult, or that you wish worked better?",
     "help": "Tell us honestly. We read every answer and we'll work on fixing it."},
    {"key": "live_interview", "type": "choice", "required": True, "options": ["Yes", "No", "Maybe later"],
     "label": "Would you be open to a short live interview about your saving journey, to inspire others?"},
    {"key": "live_interview_contact", "type": "schedule", "required": False, "maxLength": 300,
     "when": ["live_interview", "Yes"], "url": CALENDLY_INTERVIEW_URL,
     "label": "Amazing! Pick a time for your 30-minute live interview.",
     "help": "Weekdays 9am-7pm or Saturdays 9am-4pm. Someone from the MyFund team will call you on the number you enter."},
    {"key": "rating", "type": "rating", "required": True, "max": 5,
     "label": "On a scale of 1 to 5, how would you rate your MyFund experience?"},
    {"key": "feature_consent", "type": "boolean", "required": False,
     "label": "MyFund can feature my story, first name and photo on its website and social media."},
]
QUESTION_KEYS = {q["key"]: q for q in QUESTIONS}


def _token(interview):
    return signing.dumps({"interview": interview.pk, "user": interview.user_id}, salt=TOKEN_SALT)


def interview_link(interview):
    return f"https://www.myfundmobile.com/activesaver/interview?token={_token(interview)}"


def preview_link(user):
    """Seven-day link showing ``user``'s personalised form; nothing it does
    is saved or sent (for the team to check before invites go out)."""
    token = signing.dumps({"user": user.pk}, salt=PREVIEW_SALT)
    return f"https://www.myfundmobile.com/activesaver/interview?preview={token}"


def _from_request(request):
    """(interview, is_preview) for the link, or (None, False)."""
    params = request.query_params
    try:
        if params.get("preview"):
            value = signing.loads(params["preview"], salt=PREVIEW_SALT, max_age=PREVIEW_MAX_AGE)
            user = CustomUser.objects.get(pk=value["user"])
            month, year = previous_month()
            return ActiveSaverInterview(user=user, month=month, year=year, streak_months=saving_streak(user, month, year)), True
        value = signing.loads(params.get("token", ""), salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
        return ActiveSaverInterview.objects.select_related("user").get(pk=value["interview"], user_id=value["user"]), False
    except (signing.BadSignature, signing.SignatureExpired, ActiveSaverInterview.DoesNotExist,
            CustomUser.DoesNotExist, KeyError, TypeError):
        return None, False


def previous_month(now=None):
    now = now or timezone.now()
    return (12, now.year - 1) if now.month == 1 else (now.month - 1, now.year)


def _month_index(month, year):
    return year * 12 + month - 1


def _label(month, year):
    return datetime.date(year, month, 1).strftime("%B %Y")


def saving_streak(user, month, year):
    """Months in a row, ending ``month``/``year``, with positive net saving
    (every saver with one is on that month's TopSaverHistory board)."""
    return streaks({user.pk}, month, year).get(user.pk, 0)


def streaks(user_ids, month, year):
    """{user_id: consecutive positive-saving months ending month/year}."""
    end = _month_index(month, year)
    seen = {}
    for user_id, m, y in TopSaverHistory.objects.filter(user_id__in=user_ids, year__gte=year - 5).values_list("user_id", "month", "year"):
        seen.setdefault(user_id, set()).add(_month_index(m, y))
    result = {}
    for user_id, months in seen.items():
        count = 0
        while end - count in months:
            count += 1
        result[user_id] = count
    return result


def _naira(amount):
    return f"₦{Decimal(amount or 0):,.0f}"


def personalization(user, interview):
    """The warm, specific bits for the intro: all from their own account."""
    now = timezone.now()
    dividends = (Transaction.objects.filter(user=user, transaction_type="credit", status="confirmed",
                                            description__istartswith="Dividends")
                 .aggregate(total=Sum("amount"))["total"] or Decimal("0"))
    balance = (user.savings or Decimal("0")) + (user.investment or Decimal("0"))
    months_with_us = max(0, _month_index(now.month, now.year) - _month_index(user.date_joined.month, user.date_joined.year))
    # Their best finish in a finished month's Top 5 (best rank, then latest).
    best = (TopSaverHistory.objects.filter(user=user, rank__lte=5)
            .exclude(month=now.month, year=now.year).order_by("rank", "-year", "-month").first())
    goal = (TargetSavings.objects.filter(user=user, is_active=True, target_amount__gt=0)
            .order_by("-current_amount").first())
    # Past Top 3 with a story still untold: a fresh 48-hour link to the
    # existing Top Saver claim flow (the same one the landing page emails).
    story_link = None
    if _eligible_months(user):
        story_link = ("https://www.myfundmobile.com/topsaver/start?token="
                      + signing.dumps({"user": user.pk}, salt=CLAIM_SALT))

    highlights = []
    if interview.streak_months >= 2:  # one month isn't a streak yet
        highlights.append({"icon": "flame", "text": f"{interview.streak_months} months in a row of growing your savings"})
    if dividends > 0:
        highlights.append({"icon": "coins", "text": f"{_naira(dividends)} earned in MyFund dividends so far"})
    if balance > 0:
        highlights.append({"icon": "wallet", "text": f"{_naira(balance)} saved and invested with MyFund"})
    if goal:
        progress = min(100, int(goal.current_amount * 100 / goal.target_amount))
        highlights.append({"icon": "target", "text": f"{progress}% of the way to your {goal.name} goal"})
    if months_with_us >= 2:
        years, months = divmod(months_with_us, 12)
        span = " and ".join(p for p in (f"{years} year{'s' * (years > 1)}" if years else "",
                                         f"{months} month{'s' * (months > 1)}" if months else "") if p)
        highlights.append({"icon": "heart", "text": f"Part of the MyFund family for {span}"})

    past_top_saver = None
    if best:
        past_top_saver = {"rank": best.rank, "month": _label(best.month, best.year), "story_link": story_link}

    if interview.streak_months >= 6:
        cheer = "That kind of consistency is rare, and it's exactly the habit that builds real wealth."
    elif interview.streak_months >= MIN_STREAK:
        cheer = "Month after month, you've kept showing up for your future. That's how real wealth is built."
    else:
        cheer = "Every naira you put away is a vote for your future self, and we see you."
    return {"highlights": highlights, "past_top_saver": past_top_saver, "cheer": cheer}


def _serialize(interview, preview=False):
    user = interview.user
    return {
        "id": interview.pk, "preview": preview,
        "name": user.full_name or user.first_name or "MyFund saver", "first_name": user.first_name or "",
        "month": interview.month, "year": interview.year, "streak_months": interview.streak_months,
        "status": interview.status, "answers": interview.answers or {}, "submitted_at": interview.submitted_at,
        "video": {"name": interview.video_name} if interview.video_path else None,
        "photo": bool(interview.photo_path),
        "has_profile_picture": bool(str(user.profile_picture or "").strip() not in ("", "nan")),
        **personalization(user, interview),
    }


def _clean_answers(answers):
    """Only the form's questions, with the right types; None if invalid."""
    if not isinstance(answers, dict):
        return None
    clean = {}
    for key, value in answers.items():
        question = QUESTION_KEYS.get(key)
        if not question:
            return None
        if value in (None, ""):
            continue
        if question["type"] == "boolean":
            if not isinstance(value, bool):
                return None
        elif question["type"] == "rating":
            try:
                value = int(value)
            except (TypeError, ValueError):
                return None
            if not 1 <= value <= question["max"]:
                return None
        elif question["type"] == "choice":
            if value not in question["options"]:
                return None
        else:
            if not isinstance(value, str) or len(value) > question["maxLength"]:
                return None
            value = value.strip()
        clean[key] = value
    if clean.get("live_interview") != "Yes":
        clean.pop("live_interview_contact", None)  # Only asked after a Yes.
    return clean


# ---- Team alerts --------------------------------------------------------------
def _alert_team(interview, kind, title, line, details=""):
    """Push + email the interview team (same people as Top Saver)."""
    from .request_views import REQUEST_APPROVERS
    from .utils import send_transactional_email
    user = interview.user
    who = user.full_name or user.email
    tag = f"{interview.streak_months} months saving in a row" if interview.streak_months >= 2 else "MyFund saver"
    summary = f"{who} ({tag}) {line}"
    html = (f"Hi team,<br><br><b>{escape(who)}</b> ({tag}) "
            f"{escape(line)}<br><br>{details}"
            f"Phone on their MyFund account: {escape(user.phone_number or 'not set')}<br>"
            f"Email: {escape(user.email)}<br><br>"
            "Their answers are in the MyFund app: Admin → Requests → Active Saver.")
    for admin in _interview_team():
        screen_params = ({"screen": "AdminRequestsTab", "params": {"kind": "active_saver"}}
                         if admin.email.lower() in REQUEST_APPROVERS else None)
        try:
            send_push_notification(
                admin, title=title, message=summary, notif_type="ADMIN_ALERT",
                data={"type": kind, "interview_id": interview.pk,
                      "deep_link": {"screen": "Admin", "screen_params": screen_params}},
            )
        except Exception:
            logger.exception("Active Saver %s push failed for %s", kind, admin.email)
        try:
            send_transactional_email(subject=f"{title}: {who}", message=html, recipient_list=[admin.email], from_email=FROM)
        except Exception:
            logger.exception("Active Saver %s email failed for %s", kind, admin.email)


def notify_started(interview):
    _alert_team(interview, "ACTIVE_SAVER_STARTED", "💜 Active Saver story started",
                "has started their Active Saver story form.")


def notify_submitted(interview):
    answers = interview.answers or {}
    issue = str(answers.get("challenges") or "").strip()
    _alert_team(interview, "ACTIVE_SAVER_SUBMITTED", "✅ Active Saver story submitted",
                "has submitted their Active Saver story.",
                (f"Something they'd like fixed: <b>{escape(issue)}</b><br><br>" if issue else ""))


def notify_interview_booked(interview):
    _alert_team(
        interview, "ACTIVE_SAVER_INTERVIEW_BOOKED", "📅 Active Saver live interview booked",
        "has booked a 30-minute live interview on Calendly.",
        "The time and the number to call are in the MyFund Google Calendar and on "
        '<a href="https://calendly.com/app/scheduled_events/user/me">Calendly → Meetings</a>. '
        "Whoever's free takes the call; reschedule from Calendly if no one can make it.<br><br>")


def notify_live_interview(interview):
    contact = (interview.answers or {}).get("live_interview_contact") or ""
    _alert_team(
        interview, "ACTIVE_SAVER_LIVE_INTERVIEW", "📞 Active Saver wants a live interview",
        "said yes to a live interview but didn't book a slot.",
        (f"They asked to be reached on: <b>{escape(contact)}</b><br><br>" if contact else ""))


def _later(fn):
    from .ambassador_application_views import _run_in_background
    transaction.on_commit(lambda: _run_in_background(fn))


# ---- The form -----------------------------------------------------------------
@api_view(["GET", "PATCH", "POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def active_saver_interview(request):
    interview, preview = _from_request(request)
    if not interview:
        return Response({"error": "This link is invalid or has expired. Please use the link in your email."}, status=404)
    if request.method == "GET":
        return Response({"interview": _serialize(interview, preview), "questions": QUESTIONS})
    if interview.status in {"submitted", "closed"}:
        return Response({"error": "Your story has already been submitted."}, status=409)

    answers = _clean_answers(request.data.get("answers", interview.answers or {}))
    if answers is None:
        return Response({"error": "One of the answers is invalid or too long."}, status=400)
    if request.method == "POST":
        missing = [q["label"] for q in QUESTIONS if q["required"] and q["key"] not in answers]
        if missing:
            return Response({"error": "Please answer: " + "; ".join(missing)}, status=400)

    if preview:
        # Nothing is stored or sent: echo back what a real save would show.
        interview.answers = answers
        interview.status = "submitted" if request.method == "POST" else "started"
        return Response({"interview": _serialize(interview, True), "questions": QUESTIONS})

    with transaction.atomic():
        interview = ActiveSaverInterview.objects.select_for_update().select_related("user").get(pk=interview.pk)
        was_invited = interview.status == "invited"
        was_booked = _is_booked(interview.answers)
        interview.answers = answers
        interview.status = "started"
        if not interview.started_at:
            interview.started_at = timezone.now()
        if request.method == "POST":
            interview.status = "submitted"
            interview.submitted_at = timezone.now()
            _later(lambda: notify_submitted(interview))
            if answers.get("live_interview") == "Yes" and not _is_booked(answers):
                _later(lambda: notify_live_interview(interview))
        interview.save()
        if _is_booked(answers) and not was_booked:
            _later(lambda: notify_interview_booked(interview))
        if was_invited:
            # First autosave: tell the team someone's opened up.
            _later(lambda: notify_started(interview))
    return Response({"interview": _serialize(interview), "questions": QUESTIONS})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@parser_classes([MultiPartParser])
def active_saver_upload(request):
    """Optional photo or short video (?kind=photo|video, field "file")."""
    interview, preview = _from_request(request)
    kind = request.query_params.get("kind", "video")
    upload = request.FILES.get("file")
    if not interview or kind not in UPLOAD_KINDS or not upload:
        return Response({"error": "Choose a valid link and file."}, status=400)
    if preview:
        return Response({"error": "Uploads are switched off in preview."}, status=400)
    if interview.status in {"submitted", "closed"}:
        return Response({"error": "Your story has already been submitted."}, status=409)
    max_size, types, _ = UPLOAD_KINDS[kind]
    if upload.size > max_size or upload.size < 12:
        return Response({"error": f"Choose a {kind} up to {max_size // (1024 * 1024)} MB."}, status=400)
    head = upload.read(32)
    upload.seek(0)
    ext = _sniff(kind, head)
    if not ext or upload.content_type.split(";")[0].strip() not in types:
        return Response({"error": "Use an MP4, MOV or WebM video." if kind == "video" else "Use a JPG, PNG or WebP photo."}, status=400)
    try:
        from utils.imageKit import imagekit
        from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions
        result = imagekit.upload(
            file=base64.b64encode(upload.read()).decode(),
            file_name=f"active-saver-{kind}-{interview.pk}-{secrets.token_hex(6)}.{ext}",
            options=UploadFileRequestOptions(is_private_file=True, folder=f"/active-saver-{kind}s", use_unique_file_name=True),
        )
        if not result.file_id or not result.file_path:
            raise RuntimeError("upload failed")
        if kind == "video":
            interview.video_file_id, interview.video_path = result.file_id, result.file_path
            interview.video_name = f"Active Saver story.{ext}"
            fields = ["video_file_id", "video_path", "video_name", "updated_at"]
        else:
            interview.photo_file_id, interview.photo_path = result.file_id, result.file_path
            fields = ["photo_file_id", "photo_path", "updated_at"]
        interview.save(update_fields=fields)
    except Exception:
        logger.exception("Active Saver %s upload failed for %s", kind, interview.pk)
        return Response({"error": "Upload failed. Please try again."}, status=503)
    return Response({"interview": _serialize(interview)})


# ---- Monthly invites ------------------------------------------------------------
def candidates(month, year):
    """[(user, streak_months, rank)] to invite for month/year, most
    consistent first: MIN_STREAK+ months in a row, outside the Top 3, not
    on the team, not invited in the last REINVITE_AFTER_MONTHS months."""
    board = {row.user_id: row.rank for row in TopSaverHistory.objects.filter(month=month, year=year, rank__gt=3, user__isnull=False)}
    runs = {uid: n for uid, n in streaks(set(board), month, year).items() if n >= MIN_STREAK}
    team = {e.lower() for e in Employee.objects.exclude(email__isnull=True).values_list("email", flat=True) if e}
    cutoff = _month_index(month, year) - REINVITE_AFTER_MONTHS
    recent = {uid for uid, m, y in ActiveSaverInterview.objects.filter(user_id__in=runs, year__gte=year - 1)
              .values_list("user_id", "month", "year") if _month_index(m, y) > cutoff}
    users = CustomUser.objects.filter(pk__in=set(runs) - recent, is_active=True, is_staff=False, is_deleted=False, is_banned=False)
    picked = [(u, runs[u.pk], board[u.pk]) for u in users if u.email.lower() not in EXCLUDED_EMAILS | team]
    picked.sort(key=lambda item: (-item[1], item[2]))
    return picked[:MAX_INVITES_PER_MONTH]


def send_invite(interview):
    """Push + email: warm and specific, one button to the form."""
    from .utils import send_transactional_email

    user = interview.user
    first = user.first_name or "there"
    month = datetime.date(interview.year, interview.month, 1).strftime("%B")
    link = interview_link(interview)
    details = personalization(user, interview)
    past = details["past_top_saver"]
    shout = (f"And we haven't forgotten: you were <b>#{past['rank']}</b> on our Top Savers board in {past['month']}. 🏆<br><br>"
             if past else "")
    streak = interview.streak_months
    if streak >= 2:
        subject = f"💜 {first}, {streak} months in a row. We'd love to hear your story"
        opener = (f"We noticed something special: with {month} done, you've grown your savings with MyFund "
                  f"<b>{streak} months in a row</b>. {details['cheer']}<br><br>")
        push_title = f"💜 {streak} months in a row, {first}!"
        push_body = "You've kept growing your savings. We'd love to hear your story. Tap to share it."
    else:
        # Sent by hand (or asked for at /saverstory) without a streak yet.
        subject = f"💜 {first}, we'd love to hear your MyFund story"
        opener = f"Thank you for saving with MyFund. {details['cheer']}<br><br>"
        push_title = f"💜 We'd love to hear your story, {first}!"
        push_body = "Tell us about your MyFund journey. It takes about 3 minutes. Tap to share it."
    html = (
        f"Hi {first},<br><br>"
        + opener
        + shout +
        "We'd love to hear your story, in your own words. What you're saving for, what's changed, "
        "and anything we can do better. It takes about 3 minutes.<br><br>"
        + _button(link, "Share My Story") +
        "<br><br>Thank you for being part of the MyFund family. 💜<br><br>— <b>MyFund</b>"
    )
    send_push_notification(user, title=push_title, notif_type="SYSTEM", message=push_body,
                           data={"type": "ACTIVE_SAVER_INVITE", "interview_id": interview.pk, "deep_link": {"url": link}})
    return send_transactional_email(subject=subject, message=html, recipient_list=[user.email], from_email=FROM)


def open_for(user):
    """This month's interview for ``user`` (created if new), for invites
    sent by hand or asked for at /saverstory. Reuses one already open."""
    month, year = previous_month()
    interview, created = ActiveSaverInterview.objects.get_or_create(
        user=user, month=month, year=year,
        defaults={"streak_months": saving_streak(user, month, year),
                  "rank": TopSaverHistory.objects.filter(user=user, month=month, year=year).values_list("rank", flat=True).first()})
    return interview, created


def invite_now(user):
    """Send ``user`` their story form straight away (email + push)."""
    interview, _ = open_for(user)
    send_invite(interview)
    return interview


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def active_saver_mine(request):
    """www.myfundmobile.com/saverstory once they've logged in there: their
    own story form's token, straight away - nothing is emailed."""
    interview, _ = open_for(request.user)
    return Response({"token": _token(interview)})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def active_saver_request(request):
    """www.myfundmobile.com/saverstory, for anyone who can't log in there
    (e.g. signed up with Google): POST {email} - their own story form is
    emailed to them (proves the inbox
    is theirs, since the form shows their balances). Same reply either way,
    so it can't be used to look people up."""
    from .ambassador_application_views import _over_limit, _run_in_background

    email = str(request.data.get("email") or "").strip().lower()
    if "@" not in email or len(email) > 254:
        return Response({"error": "Enter the email on your MyFund account."}, status=400)
    reply = Response({"message": "If that email has a MyFund account, we've sent it a link to your story form."})
    ip = request.META.get("REMOTE_ADDR", "")
    if _over_limit(f"activesaver_request_ip:{ip}", 10) or _over_limit(f"activesaver_request_email:{email}", 3):
        return reply
    user = CustomUser.objects.filter(email__iexact=email, is_deleted=False, is_active=True, is_banned=False).first()
    if not user:
        return reply

    def send():
        try:
            invite_now(user)
        except Exception:
            logger.exception("Active Saver request failed for %s", user.email)
    _run_in_background(send)
    return reply


def invite_month(month, year):
    """Create + send this month's invites; safe to re-run (never twice)."""
    sent = 0
    for user, streak, rank in candidates(month, year):
        interview, created = ActiveSaverInterview.objects.get_or_create(
            user=user, month=month, year=year, defaults={"streak_months": streak, "rank": rank})
        if not created:
            continue
        try:
            send_invite(interview)
            sent += 1
        except Exception:
            logger.exception("Active Saver invite failed for %s", user.email)
    return sent


# ---- Admin Requests follow-ups --------------------------------------------------
def follow_up(interview, action):
    """remind (unfinished, 48h apart), invite_video, or close."""
    from datetime import timedelta

    from rest_framework.exceptions import ValidationError

    from .utils import send_transactional_email

    if action == "close":
        if interview.status == "closed":
            raise ValidationError("Already closed.")
        interview.status = "closed"
        interview.save(update_fields=["status", "updated_at"])
        return
    if action not in ("remind", "invite_video"):
        raise ValidationError("Choose remind, invite to video interview or close.")
    first = interview.user.first_name or "there"
    link = interview_link(interview)
    if action == "remind":
        if interview.status not in ("invited", "started"):
            raise ValidationError("They've already submitted their story.")
        if interview.last_reminded_at and interview.last_reminded_at > timezone.now() - timedelta(hours=48):
            raise ValidationError("A reminder went out in the last 48 hours.")
        subject = f"{first}, we'd still love to hear your MyFund story 💜"
        html = (f"Hi {first},<br><br>You've grown your savings <b>{interview.streak_months} months in a row</b>, "
                "and we'd still love to hear how you do it.<br><br>"
                "It takes about 3 minutes, and you'll continue where you stopped.<br><br>"
                + _button(link, "Finish My Story") + "<br><br>— <b>MyFund</b>")
        interview.reminder_count += 1
        interview.last_reminded_at = timezone.now()
        interview.save(update_fields=["reminder_count", "last_reminded_at", "updated_at"])
    else:
        if interview.status == "closed":
            raise ValidationError("This request is closed.")
        subject = f"{first}, let's feature your saving story on video 🎥"
        html = (f"Hi {first},<br><br>Thank you for sharing your MyFund journey. Your story can inspire many people "
                "to start saving, and we'd love to feature you in a short <b>video interview</b> "
                "(about 10 minutes, on a video call).<br><br>"
                "Just reply to this email with a day and time that works for you this week, and our team will "
                "send the call link. Prefer to record yourself? Add a short video in your story form instead."
                "<br><br>" + _button(link, "Open My Story Form") + "<br><br>— <b>MyFund</b>")
    send_transactional_email(subject=subject, message=html, recipient_list=[interview.user.email], from_email=FROM)


def serialize_request(obj, data):
    """Admin Requests detail fields (data already has name/email/phone)."""
    answers = obj.answers or {}
    data.update(
        streak_months=obj.streak_months, rank=obj.rank, month=obj.month, year=obj.year,
        responses=[{"label": q["label"], "value": f"{answers[q['key']]} / 5" if q["type"] == "rating" else str(answers[q["key"]])}
                   for q in QUESTIONS if q["key"] in answers],
        video=bool(obj.video_path), video_url=private_url(obj.video_path), photo_url=private_url(obj.photo_path),
        reminder_count=obj.reminder_count, last_reminded_at=obj.last_reminded_at,
        wants_live_interview=answers.get("live_interview") == "Yes",
        live_interview_contact=answers.get("live_interview_contact", ""),
        status=obj.status, status_label=dict(ActiveSaverInterview.STATUS).get(obj.status, obj.status.title()),
        actions=(["remind", "invite_video", "close"] if obj.status in {"invited", "started"}
                 else ["invite_video", "close"] if obj.status == "submitted" else []),
    )
    return data
