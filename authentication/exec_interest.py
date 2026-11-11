"""Ambassadors standing for a cohort executive role, from the web app's
/lead page (replaces the Google Form).

  POST /api/ambassador-exec/start/     {email, role?} - once they enter a
       valid ambassador email: creates their entry ("started").
  POST /api/ambassador-exec/interest/  multipart email, role, why_fit,
       ideas, why_vote, photo (JPG/PNG/WebP <= 10 MB; required the first
       time) - "completed". Submitting again updates it.
  GET  /api/admin/exec-interests/      staff list for the mobile admin.

Tolulope, Janet and Chubi get a push when someone starts and when they
complete, with the cohort's running "Started: N · Completed: M"."""
import base64
import logging
import secrets

from django.db import transaction
from django.db.models import Count, F
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import (
    api_view, authentication_classes, parser_classes, permission_classes,
)
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response

from .ambassador_application_views import AMBASSADOR_ALERT_EMAILS, _run_in_background
from .exec_interest_models import ExecutiveInterest
from .models import CustomUser
from .top_saver_views import _sniff
from .utils import send_push_notification, send_transactional_email

logger = logging.getLogger(__name__)

MAX_PHOTO = 10 * 1024 * 1024
PHOTO_TYPES = ("image/jpeg", "image/png", "image/webp")
ROLES = dict(ExecutiveInterest.ROLE_CHOICES)
MAX_TEXT = 2000
ADMIN_SCREEN = {"screen": "AdminExecInterests"}


def _ambassador(email):
    email = (email or "").strip().lower()
    return CustomUser.objects.filter(email__iexact=email, is_ambassador=True).first() if email else None


def totals(cohort):
    rows = ExecutiveInterest.objects.filter(cohort=cohort)
    return rows.count(), rows.filter(submitted_at__isnull=False).count()


def notify_team(title, message, cohort):
    """Push Tolulope, Janet and Chubi once each, after the save commits,
    with the cohort's running totals appended."""
    def send():
        try:
            started, completed = totals(cohort)
            text = f"{message} Started: {started} · Completed: {completed}"
            data = {"type": "EXEC_INTEREST", "started": started, "completed": completed,
                    "deep_link": ADMIN_SCREEN}
            for user in CustomUser.objects.filter(email__in=AMBASSADOR_ALERT_EMAILS, is_active=True):
                if getattr(user, "expo_push_tokens", None):
                    send_push_notification(user=user, title=title, message=text, data=data,
                                           notif_type="ADMIN_ALERT")
        except Exception:
            logger.exception("Exec interest team push failed")

    transaction.on_commit(lambda: _run_in_background(send))


def _name(user):
    return f"{user.first_name} {user.last_name}".strip() or user.email


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@parser_classes([JSONParser, FormParser])
def start_exec_interest(request):
    user = _ambassador(request.data.get("email"))
    if not user:
        return Response({"error": "No ambassador account was found with that email address."},
                        status=status.HTTP_404_NOT_FOUND)
    entry, created = ExecutiveInterest.objects.get_or_create(user=user, cohort=user.ambassador_cohort)
    role = request.data.get("role") or ""
    if role in ROLES and not entry.submitted_at and entry.role != role:
        entry.role = role
        entry.save(update_fields=["role", "updated_at"])
    if created:
        for_role = f" for {ROLES[entry.role]}" if entry.role else ""
        notify_team("Executive interest started ✍️",
                    f"{_name(user)} started their interest form{for_role}.", entry.cohort)
    return Response({
        "first_name": user.first_name,
        "role": entry.role,
        "completed": bool(entry.submitted_at),
        "has_photo": bool(entry.photo_url),
    })


def _upload_photo(upload, user):
    """Public ImageKit URL - the photo is for official ambassador posts."""
    from utils.imageKit import imagekit
    from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions

    head = upload.read(32)
    upload.seek(0)
    ext = _sniff("photo", head)
    if not ext or upload.content_type.split(";")[0].strip() not in PHOTO_TYPES:
        raise ValueError("Use a JPG, PNG or WebP photo.")
    result = imagekit.upload(
        file=base64.b64encode(upload.read()).decode(),
        file_name=f"exec-{user.pk}-{secrets.token_hex(6)}.{ext}",
        options=UploadFileRequestOptions(folder="/ambassador-exec", use_unique_file_name=True),
    )
    if not result.file_id or not result.url:
        raise RuntimeError("upload failed")
    return result.file_id, result.url


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@parser_classes([MultiPartParser, FormParser])
def submit_exec_interest(request):
    d = request.data
    user = _ambassador(d.get("email"))
    if not user:
        return Response({"error": "No ambassador account was found with that email address."},
                        status=status.HTTP_404_NOT_FOUND)

    role = d.get("role") or ""
    if role not in ROLES:
        return Response({"error": "Choose the role you're interested in."}, status=400)
    answers = {k: (d.get(k) or "").strip() for k in ("why_fit", "ideas", "why_vote")}
    if any(len(v) < 20 for v in answers.values()):
        return Response({"error": "Please answer all three questions (a few sentences each)."}, status=400)
    if any(len(v) > MAX_TEXT for v in answers.values()):
        return Response({"error": f"Keep each answer under {MAX_TEXT} characters."}, status=400)

    entry = ExecutiveInterest.objects.filter(user=user, cohort=user.ambassador_cohort).first()
    upload = request.FILES.get("photo")
    if not upload and not (entry and entry.photo_url):
        return Response({"error": "Add a clear photo of yourself."}, status=400)
    if upload and (upload.size > MAX_PHOTO or upload.size < 12):
        return Response({"error": "Choose a photo up to 10 MB."}, status=400)

    photo = None
    if upload:
        try:
            photo = _upload_photo(upload, user)
        except ValueError as exc:
            return Response({"error": str(exc)}, status=400)
        except Exception:
            logger.exception("Exec interest photo upload failed for %s", user.pk)
            return Response({"error": "Photo upload failed. Please try again."}, status=503)

    started_now = entry is None
    updated = bool(entry and entry.submitted_at)
    entry = entry or ExecutiveInterest(user=user, cohort=user.ambassador_cohort)
    entry.role = role
    entry.why_fit, entry.ideas, entry.why_vote = answers["why_fit"], answers["ideas"], answers["why_vote"]
    if photo:
        entry.photo_file_id, entry.photo_url = photo
    if not entry.submitted_at:
        entry.submitted_at = timezone.now()
    entry.save()

    role_name = ROLES[role]
    if not updated:
        if started_now:  # skipped the start step (e.g. page cached) - still count it
            notify_team("Executive interest started ✍️",
                        f"{_name(user)} started their interest form for {role_name}.", entry.cohort)
        notify_team("Executive interest completed ✅",
                    f"{_name(user)} completed their interest form for {role_name}.", entry.cohort)
    try:
        send_transactional_email(
            subject=f"You're in the running for {role_name} 🎉",
            message=(
                f"Hi {user.first_name},<br><br>"
                f"Thank you for putting yourself forward for <b>{role_name}</b> in the "
                f"{entry.cohort or 'ambassador'} executive team. "
                f"{'Your updated answers are saved.' if updated else 'Your interest has been received.'}"
                f"<br><br>Remember, these roles are about serving the team, not being the boss. "
                f"If we all win together, MyFund wins.<br><br>"
                f"You can update your answers or photo any time before the vote at "
                f"<a href='https://myfundmobile.com/lead'>myfundmobile.com/lead</a>.<br><br>MyFund"
            ),
            recipient_list=[user.email],
            from_email="MyFund <info@myfundmobile.com>",
        )
    except Exception:
        logger.exception("Exec interest email failed for %s", user.pk)

    return Response({
        "first_name": user.first_name,
        "role": role,
        "role_name": role_name,
        "cohort": str(entry.cohort) if entry.cohort else "",
        "updated": updated,
        "photo_url": entry.photo_url,
    }, status=status.HTTP_200_OK if updated else status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAdminUser])
def admin_exec_interests(request):
    """Everyone who started or completed, for the cohort of the newest entry
    (the current election), completed first, by role."""
    latest = ExecutiveInterest.objects.order_by("-created_at").first()
    cohort = latest.cohort if latest else None
    rows = (ExecutiveInterest.objects.filter(cohort=cohort).select_related("user")
            .order_by(F("submitted_at").asc(nulls_last=True), "role"))
    started, completed = totals(cohort)
    by_role = {r["role"]: r["n"] for r in rows.filter(submitted_at__isnull=False)
               .values("role").annotate(n=Count("id"))}
    return Response({
        "cohort": str(cohort) if cohort else "",
        "started": started,
        "completed": completed,
        "roles": [{"role": k, "name": v, "completed": by_role.get(k, 0)} for k, v in ROLES.items()],
        "results": [{
            "id": r.id,
            "name": _name(r.user),
            "email": r.user.email,
            "phone": r.user.phone_number,
            "role": r.role,
            "role_name": ROLES.get(r.role, ""),
            "status": "completed" if r.submitted_at else "started",
            "why_fit": r.why_fit,
            "ideas": r.ideas,
            "why_vote": r.why_vote,
            "photo_url": r.photo_url,
            "started_at": r.created_at,
            "submitted_at": r.submitted_at,
        } for r in rows],
    })
