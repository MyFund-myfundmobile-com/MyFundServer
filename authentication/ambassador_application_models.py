"""Recruitment data is separate from ambassador membership and financial records."""
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class AmbassadorIntake(models.Model):
    # One application engine, several programmes: each intake belongs to one,
    # and that picks the question set (ambassador_application_schema).
    PROGRAMMES = [('ambassador', 'Ambassador'), ('influencer', 'Influencer')]
    programme = models.CharField(max_length=20, choices=PROGRAMMES, default='ambassador', db_index=True)
    slug = models.SlugField(unique=True)
    title = models.CharField(max_length=120)
    opens_at = models.DateTimeField()
    closes_at = models.DateTimeField()
    active = models.BooleanField(default=True)

    @property
    def is_open(self):
        return self.active and self.opens_at <= timezone.now() < self.closes_at

    def __str__(self):
        return f'{self.get_programme_display()}: {self.title}'


class AmbassadorApplication(models.Model):
    STATUS = [('draft', 'Draft'), ('submitted', 'Submitted'), ('shortlisted', 'Shortlisted'),
              ('accepted', 'Accepted'), ('rejected', 'Not selected')]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intake = models.ForeignKey(AmbassadorIntake, on_delete=models.PROTECT)
    email = models.EmailField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    answers = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=STATUS, default='draft', db_index=True)
    step = models.PositiveSmallIntegerField(default=0)
    progress = models.PositiveSmallIntegerField(default=0)
    revision = models.PositiveIntegerField(default=0)
    reminder_consent = models.BooleanField(default=False)
    video_file_id = models.CharField(max_length=200, blank=True)
    video_path = models.CharField(max_length=1000, blank=True)
    video_name = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    last_reminded_at = models.DateTimeField(null=True, blank=True)
    reminder_count = models.PositiveIntegerField(default=0)
    review_notes = models.TextField(blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['intake', 'email'], name='unique_ambassador_intake_email')]
        ordering = ['-updated_at']

    def __str__(self):
        return f'{self.email} — {self.intake}'


class AmbassadorEmailChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    intake = models.ForeignKey(AmbassadorIntake, on_delete=models.CASCADE)
    email = models.EmailField(db_index=True)
    ip_hash = models.CharField(max_length=64, db_index=True)
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    used = models.BooleanField(default=False)
    reminder_consent = models.BooleanField(default=False)
