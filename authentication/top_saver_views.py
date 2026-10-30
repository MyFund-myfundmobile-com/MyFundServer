"""Hosted, signed-link Top Saver interview (www.myfundmobile.com/topsaver).

Replaces the Google Form. The link is tied to one recognition record rather
than a login, so winners can open it from the email on any device, while
nobody can reach another winner's delivery or interview details.
"""
import base64
import datetime
import logging
import secrets

from django.core import signing
from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, parser_classes, permission_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import CustomUser, Employee, TopSaverRecognition
from .utils import send_push_notification

logger = logging.getLogger(__name__)
TOKEN_SALT = "myfund.top-saver.interview.v1"
TOKEN_MAX_AGE = 60 * 60 * 24 * 120

# The questions from the Top Saver Google Form, in its order. Name and email
# come from their MyFund account, so they aren't asked again.
QUESTIONS = [
    {"key": "motivation", "type": "textarea", "required": True, "maxLength": 1500,
     "label": "What or who motivated you to start saving/investing with MyFund?",
     "help": "Be as brief but as detailed as possible."},
    {"key": "challenges", "type": "textarea", "required": True, "maxLength": 3000,
     "label": "Any challenges so far that you want us to fix? (and we'll fix it within a month)",
     "help": "Be as brief but as detailed as possible."},
    {"key": "word_for_others", "type": "textarea", "required": True, "maxLength": 1500,
     "label": "A word for someone out there on how MyFund has helped you.",
     "help": "Be as brief but as detailed as possible."},
    {"key": "live_interview", "type": "choice", "required": True, "options": ["Yes", "No", "Maybe later"],
     "label": "Would you be interested in a further live interview about your financial progress to help others?"},
    {"key": "rating", "type": "rating", "required": True, "max": 5,
     "label": "On a scale of 1 to 5, how would you rate your MyFund experience?",
     "help": "Based on your general experience (mobile app, customer service, etc.)"},
]
QUESTION_KEYS = {q["key"]: q for q in QUESTIONS}


def recognition_token(recognition):
    return signing.dumps({"recognition": recognition.pk, "user": recognition.user_id}, salt=TOKEN_SALT)


def interview_link(recognition):
    return f"https://www.myfundmobile.com/topsaver?token={recognition_token(recognition)}"


def _recognition(token):
    try:
        value = signing.loads(token, salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
        return TopSaverRecognition.objects.select_related("user").get(pk=value["recognition"], user_id=value["user"])
    except (signing.BadSignature, signing.SignatureExpired, TopSaverRecognition.DoesNotExist, KeyError, TypeError):
        return None


def private_url(path):
    """Signed one-hour link to a private ImageKit upload (admin review)."""
    if not path:
        return None
    from utils.imageKit import imagekit
    return imagekit.url({"path": path, "signed": True, "expire_seconds": 3600})


def month_name(recognition):
    return datetime.date(recognition.year, recognition.month, 1).strftime("%B")


def _serialize(recognition):
    user = recognition.user
    return {
        "id": recognition.pk, "name": user.full_name or user.first_name or "Top Saver",
        "first_name": user.first_name or "", "email": user.email,
        "month": recognition.month, "year": recognition.year,
        "rank": recognition.rank, "status": recognition.status, "first_time_winner": recognition.first_time_winner,
        "shirt_size": recognition.shirt_size, "delivery_address": recognition.delivery_address,
        "delivery_phone": recognition.delivery_phone or user.phone_number or "",
        "delivery_cost_acknowledged": recognition.delivery_cost_acknowledged,
        "answers": recognition.answers or {}, "started_at": recognition.started_at,
        "submitted_at": recognition.submitted_at,
        "video": {"name": recognition.video_name} if recognition.video_path else None,
        "photo": bool(recognition.photo_path),
        "has_profile_picture": bool(str(user.profile_picture or "").strip() not in ("", "nan")),
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
        if question["type"] == "rating":
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
    return clean


def _team_recipients():
    """Admin execs plus everyone active in Engagement, Media & Comms and CX."""
    emails = set(Employee.objects.filter(is_active=True, department__in=["Engagement", "Media and Communications", "CX"])
                 .values_list("email", flat=True))
    emails.update({"tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com", "company@myfundmobile.com"})
    return CustomUser.objects.filter(is_active=True, email__in={e.lower() for e in emails if e} | emails)


def notify_started(recognition):
    from .request_views import REQUEST_APPROVERS
    who = recognition.user.full_name or recognition.user.email
    for admin in _team_recipients():
        # Requests is approvers-only in the app; everyone else lands on Admin.
        screen_params = ({"screen": "AdminRequestsTab", "params": {"kind": "top_saver"}}
                         if admin.email.lower() in REQUEST_APPROVERS else None)
        try:
            send_push_notification(
                admin,
                title="🏆 Top Saver interview started",
                message=f"{who} (#{recognition.rank}, {month_name(recognition)}) has started their Top Saver interview.",
                data={"type": "TOP_SAVER_INTERVIEW_STARTED", "recognition_id": recognition.pk,
                      "deep_link": {"screen": "Admin", "screen_params": screen_params}},
                notif_type="ADMIN_ALERT",
            )
        except Exception:
            logger.exception("Top Saver start alert failed for %s", admin.email)


@api_view(["GET", "PATCH", "POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def top_saver_interview(request):
    recognition = _recognition(request.query_params.get("token", ""))
    if not recognition:
        return Response({"error": "This Top Saver link is invalid or has expired. Please use the link in your email."}, status=404)
    if request.method == "GET":
        return Response({"recognition": _serialize(recognition), "questions": QUESTIONS})
    if recognition.status in {"submitted", "closed"}:
        return Response({"error": "This interview has already been submitted."}, status=409)

    data = request.data
    answers = _clean_answers(data.get("answers", recognition.answers or {}))
    if answers is None:
        return Response({"error": "One of the answers is invalid or too long."}, status=400)
    size = str(data.get("shirt_size", recognition.shirt_size) or "").strip()
    if size and size not in dict(TopSaverRecognition.SHIRT_SIZES):
        return Response({"error": "Choose a valid T-shirt size."}, status=400)

    with transaction.atomic():
        recognition = TopSaverRecognition.objects.select_for_update().select_related("user").get(pk=recognition.pk)
        was_invited = recognition.status == "invited"
        if recognition.first_time_winner:
            recognition.shirt_size = size
            recognition.delivery_address = str(data.get("delivery_address", recognition.delivery_address) or "").strip()[:1000]
            recognition.delivery_phone = str(data.get("delivery_phone", recognition.delivery_phone) or "").strip()[:30]
            recognition.delivery_cost_acknowledged = bool(data.get("delivery_cost_acknowledged", recognition.delivery_cost_acknowledged))
        recognition.answers = answers
        recognition.status = "started"
        if not recognition.started_at:
            recognition.started_at = timezone.now()
        if request.method == "POST":
            missing = [q["label"] for q in QUESTIONS if q["required"] and q["key"] not in answers]
            if recognition.first_time_winner:
                if not recognition.shirt_size:
                    missing.append("T-shirt size")
                if not recognition.delivery_address:
                    missing.append("delivery address")
                if not recognition.delivery_phone:
                    missing.append("delivery phone number")
                if not recognition.delivery_cost_acknowledged:
                    missing.append("delivery cost confirmation")
            if missing:
                return Response({"error": "Please complete: " + "; ".join(missing)}, status=400)
            recognition.status = "submitted"
            recognition.submitted_at = timezone.now()
        recognition.save()
        if was_invited:
            # First save (the page autosaves as they type): tell the team.
            from .ambassador_application_views import _run_in_background
            transaction.on_commit(lambda: _run_in_background(lambda: notify_started(recognition)))
    return Response({"recognition": _serialize(recognition), "questions": QUESTIONS})


UPLOAD_KINDS = {
    # kind: (max bytes, allowed content types, folder)
    "video": (25 * 1024 * 1024, ("video/mp4", "video/quicktime", "video/webm"), "/top-saver-interviews"),
    "photo": (8 * 1024 * 1024, ("image/jpeg", "image/png", "image/webp"), "/top-saver-photos"),
}


def _sniff(kind, head):
    if kind == "video":
        return "webm" if head.startswith(b"\x1a\xdf\xa3") else "mp4" if head[4:8] == b"ftyp" else None
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"\x89PNG"):
        return "png"
    return "webp" if head[:4] == b"RIFF" and head[8:12] == b"WEBP" else None


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@parser_classes([MultiPartParser])
def top_saver_video(request):
    """Optional video or photo upload (?kind=video|photo, field "file" or "video")."""
    recognition = _recognition(request.query_params.get("token", ""))
    kind = request.query_params.get("kind", "video")
    upload = request.FILES.get("file") or request.FILES.get("video")
    if not recognition or kind not in UPLOAD_KINDS or not upload:
        return Response({"error": "Choose a valid interview link and file."}, status=400)
    if recognition.status in {"submitted", "closed"}:
        return Response({"error": "This interview has already been submitted."}, status=409)
    max_size, types, folder = UPLOAD_KINDS[kind]
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
            file_name=f"top-saver-{kind}-{recognition.pk}-{secrets.token_hex(6)}.{ext}",
            options=UploadFileRequestOptions(is_private_file=True, folder=folder, use_unique_file_name=True),
        )
        if not result.file_id or not result.file_path:
            raise RuntimeError("upload failed")
        if kind == "video":
            recognition.video_file_id, recognition.video_path = result.file_id, result.file_path
            recognition.video_name = f"Top Saver interview.{ext}"
            fields = ["video_file_id", "video_path", "video_name", "updated_at"]
        else:
            recognition.photo_file_id, recognition.photo_path = result.file_id, result.file_path
            fields = ["photo_file_id", "photo_path", "updated_at"]
        recognition.save(update_fields=fields)
    except Exception:
        logger.exception("Top Saver %s upload failed for %s", kind, recognition.pk)
        return Response({"error": "Upload failed. Please try again."}, status=503)
    return Response({"recognition": _serialize(recognition)})


# ---- Monthly recognition messages ------------------------------------------
# Photo of the T-shirt for the first-time winner email. Leave blank until a
# real photo is uploaded (www.myfundmobile.com/images/...), then set it here.
MERCH_IMAGE_URL = ""
FROM = "MyFund <hello@myfundmobile.com>"


def _button(url, label):
    return (f'<a href="{url}" style="display:inline-block;padding:13px 24px;border-radius:10px;'
            f'background:#4C28BC;color:#ffffff;text-decoration:none;font-weight:bold">{label}</a>')


def send_recognition(recognition):
    """Push + email a Top 3 winner: free T-shirt + interview the first time,
    just the interview after that. Tapping the push opens the form."""
    from .utils import send_transactional_email

    user = recognition.user
    first = user.first_name or "there"
    month = month_name(recognition)
    link = interview_link(recognition)
    if recognition.first_time_winner:
        merch = (f'<br><img src="{MERCH_IMAGE_URL}" alt="MyFund T-shirt" width="280" '
                 'style="max-width:100%;border-radius:14px"><br>' if MERCH_IMAGE_URL else "")
        subject = f"🏆 {first}, you're one of MyFund's Top Savers for {month}!"
        html = (
            f"Hi {first},<br><br>"
            f"Congratulations! 🎉 You finished <b>#{recognition.rank}</b> among MyFund's Top Savers for <b>{month}</b>. "
            "Your consistency is paying off.<br><br>"
            "As a first-time Top Saver, you've earned a <b>free MyFund T-shirt</b> 👕" + merch + "<br><br>"
            "We'd also love to feature your saving story. It takes about 3 minutes:<br>"
            "&bull; choose your T-shirt size and delivery address (delivery cost is covered by you)<br>"
            "&bull; answer a few quick questions about your MyFund journey<br><br>"
            + _button(link, "Claim My T-shirt &amp; Share My Story") +
            "<br><br>Keep growing your funds. 💜<br><br>— <b>MyFund</b>"
        )
        push_title = f"🏆 You're a Top Saver for {month}!"
        push_body = f"Congrats {first}! You finished #{recognition.rank} and earned a free MyFund T-shirt. Tap to claim it."
    else:
        subject = f"🏆 You're a Top Saver again, {first}!"
        html = (
            f"Hi {first},<br><br>"
            f"Congratulations! 🎉 You finished <b>#{recognition.rank}</b> among MyFund's Top Savers for <b>{month}</b> again. "
            "Your consistency is inspiring.<br><br>"
            "We'd love to hear how you keep it up. It takes about 3 minutes:<br><br>"
            + _button(link, "Share My Story") +
            "<br><br>Keep growing your funds. 💜<br><br>— <b>MyFund</b>"
        )
        push_title = f"🏆 Top Saver again for {month}!"
        push_body = f"Congrats {first}! You finished #{recognition.rank} again. Tap to share your story."

    send_push_notification(user, title=push_title, message=push_body, notif_type="SYSTEM",
                           data={"type": "TOP_SAVER_RECOGNITION", "recognition_id": recognition.pk,
                                 "deep_link": {"url": link}})
    return send_transactional_email(subject=subject, message=html, recipient_list=[user.email], from_email=FROM)


def send_top_ten_encouragement(user, rank, month):
    """Ranks 4-10: a well-done nudge (no interview), as before."""
    from .utils import send_transactional_email

    first = user.first_name or "there"
    send_push_notification(user, title=f"You're the #{rank} Top Saver for {month}! 🚀", notif_type="SYSTEM",
                           message=f"Well done {first}! Keep growing your funds to make the Top 3 next month.",
                           data={"type": "TOP_SAVER_ENCOURAGE", "rank": rank})
    send_transactional_email(
        subject=f"You're the #{rank} Top Saver for {month}! 🚀", from_email=FROM, recipient_list=[user.email],
        message=(f"Hi {first},<br><br>You finished <b>#{rank}</b> among MyFund's Top Savers for <b>{month}</b>. Well done!"
                 "<br><br>Keep growing your funds. The Top 3 each month are featured, and first-timers get a free "
                 "MyFund T-shirt.<br><br>— <b>MyFund</b>"),
    )


def is_first_time_winner(user, month, year):
    """Never in the Top 3 before this month (recognitions started with this
    rollout, so the older leaderboard history counts too)."""
    from .models import TopSaverHistory
    return not (
        TopSaverRecognition.objects.filter(user=user).exclude(month=month, year=year).exists()
        or TopSaverHistory.objects.filter(user=user, rank__lte=3).exclude(month=month, year=year).exists()
    )


def top_saver_follow_up(recognition, action):
    """Admin Requests actions: remind (unfinished, 48h apart), invite to a
    video interview (preset email), or close the request."""
    from datetime import timedelta

    from rest_framework.exceptions import ValidationError

    from .utils import send_transactional_email

    if action == "close":
        if recognition.status == "closed":
            raise ValidationError("Already closed.")
        recognition.status = "closed"
        recognition.save(update_fields=["status", "updated_at"])
        return
    if action not in ("remind", "invite_video"):
        raise ValidationError("Choose remind, invite to video interview or close.")
    first = recognition.user.first_name or "there"
    link = interview_link(recognition)
    if action == "remind":
        if recognition.status not in ("invited", "started"):
            raise ValidationError("They've already submitted their interview.")
        if recognition.last_reminded_at and recognition.last_reminded_at > timezone.now() - timedelta(hours=48):
            raise ValidationError("A reminder went out in the last 48 hours.")
        subject = f"{first}, your Top Saver T-shirt and story are waiting 👕" if recognition.first_time_winner \
            else f"{first}, we'd still love your Top Saver story"
        html = (f"Hi {first},<br><br>You're one of MyFund's Top Savers for <b>{month_name(recognition)}</b>, "
                "and we'd still love to hear your story"
                + (" and send your free MyFund T-shirt" if recognition.first_time_winner else "") + ".<br><br>"
                "It takes about 3 minutes, and you'll continue where you stopped.<br><br>"
                + _button(link, "Finish My Top Saver Form") + "<br><br>— <b>MyFund</b>")
        recognition.reminder_count += 1
        recognition.last_reminded_at = timezone.now()
        recognition.save(update_fields=["reminder_count", "last_reminded_at", "updated_at"])
    else:
        if recognition.status == "closed":
            raise ValidationError("This request is closed.")
        subject = f"{first}, let's feature your Top Saver story on video 🎥"
        html = (f"Hi {first},<br><br>Thank you for being one of MyFund's Top Savers for <b>{month_name(recognition)}</b>. "
                "Your story can inspire many people to start saving, and we'd love to feature you in a short "
                "<b>video interview</b> (about 10 minutes, on a video call).<br><br>"
                "Just reply to this email with a day and time that works for you this week, and our team will "
                "send the call link. Prefer to record yourself? Add a short video in your Top Saver form instead."
                "<br><br>" + _button(link, "Open My Top Saver Form") + "<br><br>— <b>MyFund</b>")
    send_transactional_email(subject=subject, message=html, recipient_list=[recognition.user.email], from_email=FROM)
