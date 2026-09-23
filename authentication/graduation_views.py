import re

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import CustomUser, InfluencerApplication

URL_RE = re.compile(r'^https?://\S+\.\S+', re.IGNORECASE)


def graduation_access(user):
    cohort = user.ambassador_cohort
    cert = getattr(user, 'ambassador_certificate', None)
    if user.email.strip().lower() == 'company@myfundmobile.com':
        return True
    if cert and cert.early_access:
        return True
    if not cohort:
        return False
    release = cohort.send_forth_date or cohort.end_date
    return bool(release and timezone.localdate() >= release) or (cohort.status == 'ended' and cohort.cohort_number != 3)


class ApplicationInput(serializers.Serializer):
    why_influencer = serializers.CharField(min_length=10, max_length=2000)
    niche = serializers.CharField(min_length=2, max_length=150)
    monthly_content = serializers.IntegerField(min_value=1, max_value=10000)
    monthly_signups = serializers.IntegerField(min_value=1, max_value=1000000)
    monthly_savers = serializers.IntegerField(min_value=1, max_value=1000000)
    # One free-text field (not per-platform inputs) - less friction for
    # someone with only 1-2 platforms and no fixed list to maintain as
    # new platforms show up - but each non-blank line still has to look
    # like an actual URL, since messy free text is hard to parse later
    # for follower-count verification or outreach.
    social_links = serializers.CharField(max_length=3000)
    # {"instagram": 1200, ...} - self-reported, keyed by whichever
    # platforms the applicant actually filled a link in for.
    social_followers = serializers.DictField(child=serializers.IntegerField(min_value=0), required=False, default=dict)
    engagement_rate = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    portfolio_link = serializers.CharField(max_length=1000, required=False, allow_blank=True, default='')
    plan = serializers.CharField(min_length=20, max_length=5000)
    contact_method = serializers.ChoiceField(choices=['whatsapp', 'email'])
    tshirt_size = serializers.ChoiceField(choices=['S', 'M', 'L', 'XL', 'XXL'])
    # Sets the ongoing-vs-6-month-cohort expectation up front rather than
    # as a surprise later.
    commitment_confirmed = serializers.BooleanField()
    # Self-attested, not actually verified - checking real follow status
    # would need a separate OAuth integration per platform, out of scope
    # here.
    follow_confirmed = serializers.BooleanField()

    def validate_social_links(self, value):
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        if not lines:
            raise serializers.ValidationError('Add at least one social profile link.')
        bad = [line for line in lines if not URL_RE.match(line)]
        if bad:
            raise serializers.ValidationError(
                f'These don’t look like valid links (must start with http:// or https://): {", ".join(bad)}'
            )
        return value

    def validate_portfolio_link(self, value):
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        bad = [line for line in lines if not URL_RE.match(line)]
        if bad:
            raise serializers.ValidationError(
                f'These don’t look like valid links (must start with http:// or https://): {", ".join(bad)}'
            )
        return value

    def validate_follow_confirmed(self, value):
        if not value:
            raise serializers.ValidationError('Please confirm you follow MyFund on social media.')
        return value

    def validate_commitment_confirmed(self, value):
        if not value:
            raise serializers.ValidationError('Please confirm you understand this role is ongoing.')
        return value

    def validate(self, data):
        if data['monthly_savers'] > data['monthly_signups']:
            raise serializers.ValidationError('Monthly savers cannot exceed your signup target.')
        return data


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def graduation(request):
    user = request.user
    eligible = graduation_access(user)
    kyc_approved = user.kyc_status == 'approved'
    if request.method == 'POST':
        if not eligible or user.is_influencer:
            return Response({'detail':'Influencer applications are not available for your account.'}, status=403)
        # Defense in depth - can_apply below already hides the button
        # for a non-KYC-approved user, but that's a client-side gate
        # only; a paid, ongoing role needs the same verification bar as
        # Ambassador itself did, checked again here regardless of what
        # the client sent.
        if not kyc_approved:
            return Response({'detail':'Complete KYC verification before applying for the Influencer programme.'}, status=403)
        form = ApplicationInput(data=request.data)
        form.is_valid(raise_exception=True)
        with transaction.atomic():
            CustomUser.objects.select_for_update().get(pk=user.pk)
            existing = InfluencerApplication.objects.filter(user=user).first()
            if existing and existing.status != 'rejected':
                return Response({'detail':'Your application has already been submitted.'}, status=409)
            InfluencerApplication.objects.update_or_create(user=user, defaults={**form.validated_data, 'status':'pending', 'review_reason':'', 'reviewed_at':None})
    app = InfluencerApplication.objects.filter(user=user).first()
    cohort = user.ambassador_cohort
    cert = getattr(user, 'ambassador_certificate', None)
    return Response({
        'eligible': eligible,
        'name': f'{user.first_name} {user.last_name}'.strip(),
        'email': user.email,
        'phone_number': user.phone_number,
        'kyc_status': user.kyc_status,
        'date_joined': user.date_joined,
        'profile_picture': user.profile_picture,
        'cohort': str(cohort) if cohort else 'Ambassador Programme',
        'start_date': cohort.start_date if cohort else None,
        'end_date': cohort.end_date if cohort else None,
        'certificate_url': request.build_absolute_uri(cert.file.url) if eligible and cert and cert.file else None,
        'can_apply': eligible and kyc_approved and not user.is_influencer and (not app or app.status == 'rejected'),
        'application': {'status':app.status, 'reason':app.review_reason} if app else None,
    })
