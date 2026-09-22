from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import CustomUser, InfluencerApplication


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
    monthly_content = serializers.IntegerField(min_value=1, max_value=10000)
    monthly_signups = serializers.IntegerField(min_value=1, max_value=1000000)
    monthly_savers = serializers.IntegerField(min_value=1, max_value=1000000)
    social_links = serializers.CharField(max_length=3000)
    plan = serializers.CharField(min_length=20, max_length=5000)

    def validate(self, data):
        if data['monthly_savers'] > data['monthly_signups']:
            raise serializers.ValidationError('Monthly savers cannot exceed your signup target.')
        return data


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def graduation(request):
    user = request.user
    eligible = graduation_access(user)
    if request.method == 'POST':
        if not eligible or user.is_influencer:
            return Response({'detail':'Influencer applications are not available for your account.'}, status=403)
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
        'cohort': str(cohort) if cohort else 'Ambassador Programme',
        'start_date': cohort.start_date if cohort else None,
        'end_date': cohort.end_date if cohort else None,
        'certificate_url': request.build_absolute_uri(cert.file.url) if eligible and cert and cert.file else None,
        'can_apply': eligible and not user.is_influencer and (not app or app.status == 'rejected'),
        'application': {'status':app.status, 'reason':app.review_reason} if app else None,
    })
