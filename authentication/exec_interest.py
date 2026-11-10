"""POST /api/ambassador-exec/interest/ - an ambassador puts themselves
forward for a cohort executive role, from the web app's /lead page.

Identified by their ambassador email, like the weekly attendance form.
Multipart: email, role, why_fit, ideas, why_vote, photo (JPG/PNG/WebP up
to 10 MB; required the first time). Submitting again updates their entry,
so they can change role or answers before the election."""
import base64
import logging
import secrets

from rest_framework import status
from rest_framework.decorators import (
    api_view, authentication_classes, parser_classes, permission_classes,
)
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .exec_interest_models import ExecutiveInterest
from .models import CustomUser
from .top_saver_views import _sniff
from .utils import ALWAYS_ADMIN_NOTIFY_EMAIL, send_push_notification, send_transactional_email

logger = logging.getLogger(__name__)

MAX_PHOTO = 10 * 1024 * 1024
PHOTO_TYPES = ("image/jpeg", "image/png", "image/webp")
ROLES = dict(ExecutiveInterest.ROLE_CHOICES)
MAX_TEXT = 2000


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
    email = (d.get("email") or "").strip().lower()
    user = CustomUser.objects.filter(email__iexact=email, is_ambassador=True).first()
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

    updated = entry is not None
    entry = entry or ExecutiveInterest(user=user, cohort=user.ambassador_cohort)
    entry.role = role
    entry.why_fit, entry.ideas, entry.why_vote = answers["why_fit"], answers["ideas"], answers["why_vote"]
    if photo:
        entry.photo_file_id, entry.photo_url = photo
    entry.save()

    role_name = ROLES[role]
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
        if not updated:
            founder = CustomUser.objects.filter(email=ALWAYS_ADMIN_NOTIFY_EMAIL).first()
            if founder:
                send_push_notification(
                    user=founder,
                    title="New executive interest",
                    message=f"{user.first_name} {user.last_name} wants to be {role_name}.",
                    data={"type": "EXEC_INTEREST"},
                    notif_type="SYSTEM",
                )
    except Exception:
        logger.exception("Exec interest notifications failed for %s", user.pk)

    return Response({
        "first_name": user.first_name,
        "role": role,
        "role_name": role_name,
        "cohort": str(entry.cohort) if entry.cohort else "",
        "updated": updated,
        "photo_url": entry.photo_url,
    }, status=status.HTTP_200_OK if updated else status.HTTP_201_CREATED)
