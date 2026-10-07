import csv
from datetime import timedelta
from django.contrib import admin, messages
from django import forms
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.html import format_html, format_html_join
from .models import AmbassadorIntake, AmbassadorApplication
from .ambassador_application_schema import fields_for
from .ambassador_application_views import video_url
from .utils import send_transactional_email


@admin.register(AmbassadorIntake)
class AmbassadorIntakeAdmin(admin.ModelAdmin):
    list_display = ['title', 'programme', 'opens_at', 'closes_at', 'active']
    list_filter = ['programme', 'active']

    def save_model(self, request, obj, form, change):
        # One active intake per programme - opening an ambassador cohort
        # must not close the influencer portal, and vice versa.
        if obj.active:
            AmbassadorIntake.objects.filter(programme=obj.programme).exclude(pk=obj.pk).update(active=False)
        super().save_model(request, obj, form, change)


class ReviewForm(forms.ModelForm):
    class Meta:
        model = AmbassadorApplication
        fields = '__all__'

    def clean_status(self):
        status = self.cleaned_data['status']
        if self.instance.status == 'draft' and status != 'draft':
            raise forms.ValidationError('Only applicants can submit their own drafts.')
        if self.instance.status != 'draft' and status == 'draft':
            raise forms.ValidationError('Submitted applications cannot be changed back into drafts.')
        return status


@admin.register(AmbassadorApplication)
class AmbassadorApplicationAdmin(admin.ModelAdmin):
    form = ReviewForm
    change_list_template = 'admin/authentication/ambassadorapplication/change_list.html'
    list_display = ['email', 'applicant_name', 'intake', 'status', 'progress', 'step_label', 'updated_at', 'submitted_at', 'reminder_count']
    list_filter = ['intake__programme', 'intake', 'status', 'reminder_consent', 'created_at', 'submitted_at']
    search_fields = ['email', 'user__first_name', 'user__last_name', 'answers__full_name']
    list_select_related = ['intake', 'user']
    readonly_fields = ['id', 'intake', 'email', 'user', 'answer_summary', 'video_preview', 'progress', 'step', 'revision',
        'reminder_consent', 'created_at', 'updated_at', 'submitted_at', 'last_reminded_at', 'reminder_count']
    fields = ['id', 'intake', 'email', 'user', 'status', 'progress', 'step', 'answer_summary', 'video_preview', 'review_notes',
        'reminder_consent', 'created_at', 'updated_at', 'submitted_at', 'last_reminded_at', 'reminder_count', 'revision']
    actions = ['export_applications', 'remind_drafts']

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description='Applicant')
    def applicant_name(self, obj):
        return obj.answers.get('full_name', '—')

    @admin.display(description='Last section')
    def step_label(self, obj):
        from .ambassador_application_schema import steps_for
        titles = [step['title'] for step in steps_for(obj.intake.programme)] + ['Review']
        return titles[min(obj.step, len(titles) - 1)]

    def answer_summary(self, obj):
        rows = []
        for key, f in fields_for(obj.intake.programme).items():
            value = obj.answers.get(key, '—')
            rows.append((f['label'], ', '.join(value) if isinstance(value, list) else str(value)))
        return format_html('<table>{}</table>', format_html_join('', '<tr><th>{}</th><td style="white-space:pre-wrap">{}</td></tr>', rows))

    def video_preview(self, obj):
        url = video_url(obj) or obj.answers.get('video_link')
        if not url:
            return 'No video provided (optional)'
        # Draft links are untrusted until validated at submission.
        from django.core.validators import URLValidator
        from django.core.exceptions import ValidationError
        try:
            URLValidator(schemes=['https'])(url)
        except ValidationError:
            return 'The draft video link is incomplete.'
        return format_html('<a href="{}" target="_blank" rel="noopener noreferrer">Watch introduction video</a>', url)

    def changelist_view(self, request, extra_context=None):
        response = super().changelist_view(request, extra_context)
        if hasattr(response, 'context_data') and response.context_data and 'cl' in response.context_data:
            qs = response.context_data['cl'].queryset
            total, drafts = qs.count(), qs.filter(status='draft').count()
            response.context_data['application_metrics'] = dict(total=total, drafts=drafts, submitted=total-drafts,
                conversion=round(100*(total-drafts)/total) if total else 0)
        return response

    @admin.action(description='Export selected applications as CSV', permissions=['view'])
    def export_applications(self, request, queryset):
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="ambassador-applications.csv"'
        response.write('\ufeff')
        writer = csv.writer(response)
        programmes = set(queryset.values_list('intake__programme', flat=True)) or {'ambassador'}
        fields = {}
        for programme in sorted(programmes):
            fields.update(fields_for(programme))
        writer.writerow(['ID', 'Intake', 'Email', 'Status', 'Completion %', 'Started', 'Last saved', 'Submitted', 'Reminder consent', 'Video uploaded'] + [f['label'] for f in fields.values()])
        def safe(value):
            value = ', '.join(map(str, value)) if isinstance(value, list) else str(value or '')
            return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')) else value
        for app in queryset.iterator():
            values = [app.pk, app.intake, app.email, app.status, app.progress, app.created_at, app.updated_at, app.submitted_at,
                      app.reminder_consent, bool(app.video_path)] + [app.answers.get(k, '') for k in fields]
            writer.writerow([safe(v) for v in values])
        return response

    @admin.action(description='Email a reminder to eligible unfinished applicants (max 50)', permissions=['change'])
    def remind_drafts(self, request, queryset):
        now = timezone.now()
        ids = list(queryset.filter(status='draft', reminder_consent=True, updated_at__lt=now-timedelta(hours=24)).values_list('pk', flat=True)[:50])
        sent = failed = 0
        for pk in ids:
            with transaction.atomic():
                app = AmbassadorApplication.objects.select_for_update().select_related('intake').get(pk=pk)
                if app.status != 'draft' or not app.reminder_consent or not app.intake.is_open or app.updated_at >= now-timedelta(hours=24) or (app.last_reminded_at and app.last_reminded_at > now-timedelta(hours=48)):
                    continue
                try:
                    programme = app.intake.programme
                    result = send_transactional_email(f'Your MyFund {programme} application is saved',
                        f'Your {programme} application is still a draft. You can pick up where you stopped at '
                        f'<a href="https://www.myfundmobile.com/{programme}/apply">MyFund applications</a>. '
                        'Use the same email and verify your code to resume. The introduction video is optional. '
                        'You requested application reminders; you can turn them off in your saved application.',
                        [app.email], template='email/email_light.html')
                    if not result or not result.get('sent'):
                        raise RuntimeError('Delivery failed')
                except Exception:
                    failed += 1
                    continue
                # Do not change last-saved time: this is admin contact, not applicant activity.
                app.last_reminded_at = now
                app.reminder_count += 1
                app.save(update_fields=['last_reminded_at', 'reminder_count'])
                self.log_change(request, app, 'Sent requested draft reminder')
                sent += 1
        self.message_user(request, f'{sent} reminder(s) sent; {failed} failed. Ineligible/recent drafts were skipped.', messages.WARNING if failed else messages.SUCCESS)
