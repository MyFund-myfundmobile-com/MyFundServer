"""FOYA Global Honors 2026 voting campaign: Home banner + at most 3 pushes."""
from datetime import datetime
from zoneinfo import ZoneInfo

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

WAT = ZoneInfo("Africa/Lagos")
# FOYA closes 2026-11-04 23:59 EAT, which is 21:59 in Lagos.
VOTING_CLOSES = datetime(2026, 11, 4, 21, 59, tzinfo=WAT)
MAX_PUSHES_PER_CAMPAIGN = 3


def default_end_at():
    return VOTING_CLOSES


class FoyaCampaign(models.Model):
    is_active = models.BooleanField(default=True)
    start_at = models.DateTimeField(default=timezone.now)
    end_at = models.DateTimeField(default=default_end_at)
    signup_url = models.URLField(default="https://foyaglobal.com/signup")
    login_url = models.URLField(default="https://foyaglobal.com/login")
    # [{"key": "founder", "label": "Founder of the Year", "url": "https://..."}]
    categories = models.JSONField(default=list)
    # {"0": "founder", ..., "6": "founder"} - Monday is 0, in Lagos time.
    weekday_schedule = models.JSONField(default=dict)
    # Show today's ranking on the banner. Off until FOYA confirms rankings
    # can be shared and real votes are in.
    show_position = models.BooleanField(default=False)

    class Meta:
        verbose_name = "FOYA campaign"

    def __str__(self):
        return f"FOYA campaign ({'active' if self.is_active else 'off'}, ends {self.end_at:%d %b %Y})"

    def is_live(self, now=None):
        now = now or timezone.now()
        return self.is_active and self.start_at <= now < self.end_at

    def category_for(self, now=None):
        """Today's category in Lagos time, or None."""
        weekday = (now or timezone.now()).astimezone(WAT).weekday()
        key = (self.weekday_schedule or {}).get(str(weekday))
        return next((c for c in self.categories or [] if c.get("key") == key), None)


class FoyaPush(models.Model):
    SLOTS = [("launch", "Launch"), ("final_week", "Final week"), ("last_day", "Last day")]
    STATUSES = [("scheduled", "Scheduled"), ("sent", "Sent"), ("cancelled", "Cancelled")]
    campaign = models.ForeignKey(FoyaCampaign, on_delete=models.CASCADE, related_name="pushes")
    slot = models.CharField(max_length=20, choices=SLOTS)
    title = models.CharField(max_length=120)
    body = models.CharField(max_length=240)
    # Blank = not scheduled yet (the launch push is timed by hand once the
    # banner is live). Entered in the admin in WAT (TIME_ZONE).
    send_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=12, choices=STATUSES, default="scheduled", db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    recipients_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "FOYA push"
        constraints = [models.UniqueConstraint(fields=["campaign", "slot"], name="unique_foya_push_slot")]
        ordering = ["send_at"]

    def __str__(self):
        return f"{self.get_slot_display()} — {self.title}"

    def clean(self):
        if self.campaign_id and not self.pk and FoyaPush.objects.filter(campaign_id=self.campaign_id).count() >= MAX_PUSHES_PER_CAMPAIGN:
            raise ValidationError(f"A FOYA campaign can have at most {MAX_PUSHES_PER_CAMPAIGN} pushes.")

    def save(self, *args, **kwargs):
        # Enforced here too, not just in the admin form, so no code path can
        # add a fourth push.
        if not self.pk:
            self.clean()
        super().save(*args, **kwargs)


class FoyaPosition(models.Model):
    """MyFund's standing in one category. A new row per update, so the
    rows are the change history (with the value it replaced)."""
    campaign = models.ForeignKey(FoyaCampaign, on_delete=models.CASCADE, related_name="positions")
    category_key = models.CharField(max_length=40, db_index=True)
    position = models.PositiveIntegerField()
    field_size = models.PositiveIntegerField()
    is_tied = models.BooleanField(default=False)
    previous_position = models.PositiveIntegerField(null=True, blank=True)
    previous_field_size = models.PositiveIntegerField(null=True, blank=True)
    previous_is_tied = models.BooleanField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name = "FOYA position"
        ordering = ["-updated_at", "-id"]

    def __str__(self):
        return f"{self.category_key}: {self.position}/{self.field_size}{' (tied)' if self.is_tied else ''}"

    def clean(self):
        if not 1 <= self.position <= self.field_size:
            raise ValidationError("Position must be between 1 and the field size.")


class FoyaEvent(models.Model):
    EVENTS = [(e, e) for e in ("banner_view", "banner_tap", "push_open", "signup_tap", "login_tap", "vote_tap", "dismiss")]
    SOURCES = [("banner", "Banner"), ("push", "Push")]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    event = models.CharField(max_length=20, choices=EVENTS, db_index=True)
    category_key = models.CharField(max_length=40, blank=True)
    source = models.CharField(max_length=10, choices=SOURCES, default="banner")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = "FOYA event"
        ordering = ["-created_at"]
