"""Email-verified, resumable applications. Tokens only grant access to one application."""
import base64
import logging
import secrets
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password
from django.core import signing
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.exceptions import APIException, AuthenticationFailed, ValidationError as APIValidationError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication
from .models import AmbassadorIntake, AmbassadorApplication, AmbassadorEmailChallenge, CustomUser, Transaction
from .ambassador_application_schema import STEPS, errors_for, progress_for
from .utils import send_transactional_email

logger = logging.getLogger(__name__)
SALT = 'ambassador-application-v1'


def current_intake():
    intake = AmbassadorIntake.objects.filter(active=True).order_by('-opens_at').first()
    if not intake:
        raise APIValidationError({'error': 'There is no application intake at the moment.'})
    return intake


def require_open(intake):
    if not intake.is_open:
        raise APIValidationError({'error': 'Applications for this intake are closed. Your saved application is still available to view.'})


def application_token(app):
    return signing.dumps({'id': str(app.pk)}, salt=SALT)


def get_application(request):
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Application '):
        try:
            payload = signing.loads(auth[12:], salt=SALT, max_age=7 * 86400)
            return AmbassadorApplication.objects.select_related('intake', 'user').get(pk=payload['id'])
        except (signing.BadSignature, KeyError, ValueError, AmbassadorApplication.DoesNotExist):
            raise AuthenticationFailed('Please verify your email again to resume your application.')
    # Existing MyFund logins may use JWT or DRF tokens. No anonymous profile lookup.
    authenticated = JWTAuthentication().authenticate(request) if auth.startswith('Bearer ') else TokenAuthentication().authenticate(request)
    if not authenticated:
        raise AuthenticationFailed('Verify your email to continue.')
    user = authenticated[0]
    if user.is_deleted or not user.is_active:
        raise AuthenticationFailed('This account is not available.')
    intake = current_intake()
    app = AmbassadorApplication.objects.filter(intake=intake, email=user.email.lower()).first()
    if not app:
        require_open(intake)
        app = make_application(intake, user.email.lower(), user=user)
    return app


def profile_for(user):
    if not user or user.is_deleted:
        return None
    credits = Transaction.objects.filter(user=user, transaction_type='credit', status='confirmed', credited_to='SAVINGS')
    return dict(first_name=user.first_name, joined=user.date_joined.date().isoformat(),
                has_saved=credits.exists() or user.savings > 0)


def _run_in_background(fn):
    # Pushes go out after the request returns: no Celery/Redis cost, and an
    # Expo hiccup never slows or fails the applicant's save.
    import threading
    threading.Thread(target=fn, daemon=True).start()


# Pre-launch testing runs against the live DB, so until launch these pushes
# go to the founder only. Flip to True at launch to alert the admin list and
# the Engagement team.
NOTIFY_FULL_TEAM = False
PRELAUNCH_NOTIFY_EMAILS = ['tolulopeahmed@gmail.com']


def notify_team(title, message, data):
    """Push to the admin alert list plus every active Engagement team
    member (who run the ambassador programme), once each - or, before
    launch, to PRELAUNCH_NOTIFY_EMAILS only."""
    from .models import Employee
    from .utils import get_admin_notify_users, send_push_notification

    def send():
        try:
            if NOTIFY_FULL_TEAM:
                engagement = Employee.objects.filter(department='Engagement', is_active=True).values_list('email', flat=True)
                recipients = {u.pk: u for u in get_admin_notify_users(category='system')}
                for u in CustomUser.objects.filter(email__in=list(engagement), is_active=True):
                    recipients.setdefault(u.pk, u)
            else:
                recipients = {u.pk: u for u in CustomUser.objects.filter(email__in=PRELAUNCH_NOTIFY_EMAILS, is_active=True)}
            for user in recipients.values():
                if getattr(user, 'expo_push_tokens', None):
                    send_push_notification(user=user, title=title, message=message, data=data, notif_type='ADMIN_ALERT')
        except Exception:
            logger.exception('Ambassador application team push failed')

    transaction.on_commit(lambda: _run_in_background(send))


def _applicant_name(app):
    return (str(app.answers.get('full_name') or '').strip()
            or (app.user.full_name if app.user_id else '') or app.email)


def make_application(intake, email, user=None, consent=True):
    user = user or CustomUser.objects.filter(email__iexact=email, is_deleted=False, is_active=True).first()
    defaults = {}
    if user:
        defaults = dict(full_name=user.full_name, phone=user.phone_number, has_account='Yes',
                        account_email=user.email, has_saved='Yes' if profile_for(user)['has_saved'] else 'No')
    app, created = AmbassadorApplication.objects.get_or_create(intake=intake, email=email,
        defaults={'user': user, 'answers': defaults, 'reminder_consent': consent, 'progress': progress_for(defaults)})
    if created:
        notify_team('🌱 Ambassador application started',
                    f'{_applicant_name(app)} just started an ambassador application'
                    f'{" (MyFund user)" if user else ""}.',
                    {'type': 'AMBASSADOR_APPLICATION_STARTED', 'application_id': str(app.pk)})
    return app


def video_url(app):
    if not app.video_path:
        return None
    from utils.imageKit import imagekit
    return imagekit.url({'path': app.video_path, 'signed': True, 'expire_seconds': 3600})


def serialize(app):
    return dict(id=str(app.pk), email=app.email, answers=app.answers, status=app.status, step=app.step,
                progress=app.progress, revision=app.revision, reminder_consent=app.reminder_consent,
                updated_at=app.updated_at.isoformat(), submitted_at=app.submitted_at,
                profile=profile_for(app.user), intake=intake_data(app.intake),
                video={'name': app.video_name, 'url': video_url(app)} if app.video_path else None)


def intake_data(intake):
    return dict(title=intake.title, slug=intake.slug, closes_at=intake.closes_at, is_open=intake.is_open)


@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def application_config(request):
    return Response({'intake': intake_data(current_intake()), 'steps': STEPS, 'video_max_bytes': 25 * 1024 * 1024})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def request_code(request):
    intake = current_intake()
    email = str(request.data.get('email', '')).strip().lower()
    try:
        validate_email(email)
        if len(email) > 254:
            raise ValidationError('Email too long')
    except ValidationError:
        return Response({'error': 'Enter a valid email address.'}, status=400)
    if not intake.is_open and not AmbassadorApplication.objects.filter(intake=intake, email=email).exists():
        return Response({'error': 'Applications for this intake are closed.'}, status=400)
    if request.data.get('privacy_accepted') is not True:
        return Response({'error': 'Please acknowledge the application privacy notice.'}, status=400)
    # Use the direct peer as a conservative shared limit; never trust arbitrary forwarded headers.
    ip_hash = salted_hmac(SALT, request.META.get('REMOTE_ADDR', '')).hexdigest()
    now = timezone.now()
    with transaction.atomic():
        AmbassadorIntake.objects.select_for_update().get(pk=intake.pk)
        recent = AmbassadorEmailChallenge.objects.filter(created_at__gte=now - timedelta(hours=1))
        if recent.filter(email=email).count() >= 5 or recent.filter(ip_hash=ip_hash).count() >= 60:
            return Response({'error': 'Too many code requests. Please try again in an hour.'}, status=429)
        if recent.filter(email=email, created_at__gte=now-timedelta(seconds=60)).exists():
            return Response({'error': 'Please wait one minute before requesting another code.'}, status=429)
        code = f'{secrets.randbelow(1000000):06d}'
        challenge = AmbassadorEmailChallenge.objects.create(intake=intake, email=email, ip_hash=ip_hash,
            code_hash=make_password(code), reminder_consent=request.data.get('reminder_consent') is not False)
    try:
        result = send_transactional_email('Your MyFund ambassador application code',
            f'Your verification code is <strong>{code}</strong>. It expires in 10 minutes. '
            'Enter it on the MyFund application page. If you did not request it, you can ignore this email.', [email], template='email/email_light.html')
        if not result or not result.get('sent'):
            raise RuntimeError('Email delivery not accepted')
    except Exception:
        logger.warning('Ambassador OTP delivery failed (challenge %s)', challenge.pk)
        return Response({'error': 'We could not send the code. Please wait a minute and try again.'}, status=503)
    return Response({'challenge': str(challenge.pk), 'message': 'Check your inbox for the six-digit code.'})


def _over_limit(key, limit, window=3600):
    """Fixed-window counter in Django's cache (no extra infrastructure)."""
    from django.core.cache import cache
    cache.add(key, 0, window)
    try:
        return cache.incr(key) > limit
    except ValueError:  # expired between add and incr
        cache.set(key, 1, window)
        return False


def _clean_email(request):
    email = str(request.data.get('email', '')).strip().lower()
    try:
        validate_email(email)
        if len(email) > 254:
            raise ValidationError('Email too long')
    except ValidationError:
        return None
    return email


def _member(email):
    return CustomUser.objects.filter(email__iexact=email, is_active=True, is_deleted=False, is_banned=False).first()


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def lookup_email(request):
    """Existing MyFund members sign in with their password instead of an
    emailed code. Reveals only whether to ask for a password and the first
    name (Google-style "Welcome back, Ada"), never other account details;
    rate-limited per IP to slow down email probing."""
    email = _clean_email(request)
    if not email:
        return Response({'error': 'Enter a valid email address.'}, status=400)
    ip_hash = salted_hmac(SALT, request.META.get('REMOTE_ADDR', '')).hexdigest()
    if _over_limit(f'amb-lookup:{ip_hash}', 30):
        return Response({'error': 'Too many attempts. Please try again in an hour.'}, status=429)
    user = _member(email)
    if user and user.has_usable_password():
        return Response({'member': True, 'first_name': (user.first_name or '').split(' ')[0][:40]})
    return Response({'member': False})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def password_login(request):
    intake = current_intake()
    email = _clean_email(request)
    if not email:
        return Response({'error': 'Enter a valid email address.'}, status=400)
    if request.data.get('privacy_accepted') is not True:
        return Response({'error': 'Please acknowledge the application privacy notice.'}, status=400)
    ip_hash = salted_hmac(SALT, request.META.get('REMOTE_ADDR', '')).hexdigest()
    if _over_limit(f'amb-pw-email:{email}', 8) or _over_limit(f'amb-pw-ip:{ip_hash}', 40):
        return Response({'error': 'Too many sign-in attempts. Use a code instead, or try again in an hour.'}, status=429)
    user = _member(email)
    if not user or not user.check_password(str(request.data.get('password', ''))):
        return Response({'error': 'Incorrect password. Try again or get a code instead.'}, status=400)
    app = AmbassadorApplication.objects.filter(intake=intake, email=email).first()
    if not app:
        require_open(intake)
        app = make_application(intake, email, user=user, consent=request.data.get('reminder_consent') is not False)
    return Response({'token': application_token(app), 'application': serialize(app)})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def verify_code(request):
    try:
        with transaction.atomic():
            challenge = AmbassadorEmailChallenge.objects.select_for_update().select_related('intake').get(pk=request.data.get('challenge'))
            if challenge.used or challenge.attempts >= 5 or challenge.created_at < timezone.now()-timedelta(minutes=10):
                return Response({'error': 'This code has expired. Request a new code.'}, status=400)
            challenge.attempts += 1
            challenge.save(update_fields=['attempts'])
            code = str(request.data.get('code', ''))
            if len(code) != 6 or not check_password(code, challenge.code_hash):
                return Response({'error': 'Incorrect code. Please check your email.'}, status=400)
            app = AmbassadorApplication.objects.filter(intake=challenge.intake, email=challenge.email).first()
            if not app:
                require_open(challenge.intake)
                app = make_application(challenge.intake, challenge.email, consent=challenge.reminder_consent)
            challenge.used = True
            challenge.save(update_fields=['used'])
    except (AmbassadorEmailChallenge.DoesNotExist, ValueError, ValidationError):
        return Response({'error': 'Invalid code request. Please request a new code.'}, status=400)
    return Response({'token': application_token(app), 'application': serialize(app)})


def check_revision(app, data):
    if data.get('revision') != app.revision:
        error = APIException('Your draft changed in another tab. Reload to see the latest saved answers before editing.')
        error.status_code = 409
        raise error


@api_view(['GET', 'PATCH'])
@authentication_classes([])
@permission_classes([AllowAny])
def application_draft(request):
    app = get_application(request)
    if request.method == 'GET':
        return Response({'application': serialize(app), 'token': application_token(app)})
    with transaction.atomic():
        app = AmbassadorApplication.objects.select_for_update().get(pk=app.pk)
        require_open(app.intake)
        if app.status != 'draft':
            return Response({'error': 'This application has already been submitted.'}, status=409)
        check_revision(app, request.data)
        answers = request.data.get('answers', {})
        if not isinstance(answers, dict):
            return Response({'error': 'Invalid answers.'}, status=400)
        errors = errors_for(answers)
        # Incomplete typing (phone/email/number) is saved as a draft; only reject unsafe shapes/sizes.
        from .ambassador_application_schema import FIELDS
        if any(key not in FIELDS or not isinstance(value, (str, int, bool, list, type(None)))
               or isinstance(value, str) and len(value) > FIELDS[key].get('maxLength', 2500)
               or isinstance(value, list) and (len(value) > 20 or any(not isinstance(v, str) or len(v) > 100 for v in value))
               for key, value in answers.items()):
            return Response({'error': 'An answer is too long or has an invalid format.'}, status=400)
        step = request.data.get('step', 0)
        if type(step) is not int or not 0 <= step <= len(STEPS):
            return Response({'error': 'Invalid step.'}, status=400)
        if app.video_path and answers.get('video_link'):
            return Response({'error': 'Remove your uploaded video before adding a video link.'}, status=400)
        app.answers = answers
        app.step = step
        app.progress = progress_for(answers)
        # Reminders are on for every applicant (no opt-in checkbox); only an
        # explicit false turns them off.
        app.reminder_consent = request.data.get('reminder_consent') is not False
        app.revision += 1
        app.save()
    return Response({'application': serialize(app)})


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def application_submit(request):
    app = get_application(request)
    with transaction.atomic():
        app = AmbassadorApplication.objects.select_for_update().get(pk=app.pk)
        if app.status != 'draft':
            return Response({'application': serialize(app)})  # Safe retry after lost response.
        require_open(app.intake)
        check_revision(app, request.data)
        errors = errors_for(app.answers, complete=True)
        if request.data.get('confirmed') is not True:
            errors['confirmed'] = 'Confirm that your answers are accurate.'
        if errors:
            return Response({'error': 'Please check the highlighted answers.', 'fields': errors}, status=400)
        app.status = 'submitted'
        app.submitted_at = timezone.now()
        app.progress = 100
        app.revision += 1
        app.save()
        where = str(app.answers.get('location') or '').strip()
        notify_team('✅ Ambassador application submitted',
                    f'{_applicant_name(app)}{f" from {where}" if where else ""} just submitted an ambassador application. Tap to review.',
                    {'type': 'AMBASSADOR_APPLICATION_SUBMITTED', 'application_id': str(app.pk)})
    # Receipt is durable in-app. No unsolicited mail or role changes at submission.
    return Response({'application': serialize(app)})


@api_view(['POST', 'DELETE'])
@authentication_classes([])
@permission_classes([AllowAny])
@parser_classes([MultiPartParser])
def application_video(request):
    app = get_application(request)
    from utils.imageKit import imagekit
    from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions
    old_file = None
    with transaction.atomic():
        app = AmbassadorApplication.objects.select_for_update().get(pk=app.pk)
        require_open(app.intake)
        if app.status != 'draft':
            return Response({'error': 'This application has already been submitted.'}, status=409)
        try:
            revision = int(request.query_params.get('revision', '-1'))
        except ValueError:
            revision = -1
        check_revision(app, {'revision': revision})
        if request.method == 'DELETE':
            old_file = app.video_file_id
            app.video_file_id = app.video_path = app.video_name = ''
        else:
            upload = request.FILES.get('video')
            if not upload or upload.size > 25 * 1024 * 1024 or upload.size < 12:
                return Response({'error': 'Choose a video up to 25 MB.'}, status=400)
            head = upload.read(32)
            upload.seek(0)
            ext = 'webm' if head.startswith(b'\x1aE\xdf\xa3') else 'mp4' if head[4:8] == b'ftyp' else None
            if not ext or upload.content_type not in ('video/mp4', 'video/quicktime', 'video/webm'):
                return Response({'error': 'Use an MP4, MOV or WebM video.'}, status=400)
            try:
                result = imagekit.upload(file=base64.b64encode(upload.read()).decode(),
                    file_name=f'{app.pk}-{secrets.token_hex(6)}.{ext}',
                    options=UploadFileRequestOptions(is_private_file=True, folder='/ambassador-applications', use_unique_file_name=True))
                if not result.file_id or not result.file_path or not result.is_private_file:
                    raise RuntimeError('Private video upload failed')
            except Exception:
                logger.warning('Ambassador video upload failed for application %s', app.pk)
                return Response({'error': 'Video upload failed. Please retry or use a shared video link.'}, status=503)
            old_file = app.video_file_id
            app.video_file_id, app.video_path = result.file_id, result.file_path
            app.video_name = 'Introduction video.' + ext
            app.answers = {**app.answers, 'video_link': '', 'video_shared': False}
        app.revision += 1
        app.save()
    if old_file:
        try:
            imagekit.delete_file(old_file)
        except Exception:
            logger.warning('Old private application video needs cleanup: %s', old_file)
    return Response({'application': serialize(app)})
