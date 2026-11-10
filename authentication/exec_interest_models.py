"""Ambassadors' interest in a cohort executive role (Lead, Co-Lead, ...),
from the web app's /lead page - replaces the Google Form. One entry per
ambassador per cohort; submitting again updates it. See exec_interest.py."""
from django.conf import settings
from django.db import models


class ExecutiveInterest(models.Model):
    ROLE_CHOICES = [
        ("lead", "Lead"),
        ("co_lead", "Co-Lead"),
        ("secretary", "Secretary"),
        ("social_director", "Social Director"),
        ("me_lead", "Monitoring & Evaluation (M&E) Lead"),
        ("growth_lead", "Growth Lead"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="exec_interests"
    )
    cohort = models.ForeignKey(
        "authentication.AmbassadorCohort", on_delete=models.SET_NULL, null=True, blank=True
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    why_fit = models.TextField(help_text="Why this role, and what makes them a good fit")
    ideas = models.TextField(help_text="Ideas to make the cohort more engaging and successful")
    why_vote = models.TextField(help_text="Public: why people should vote for them")
    photo_file_id = models.CharField(max_length=100, blank=True)
    photo_url = models.URLField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["role", "created_at"]
        constraints = [
            models.UniqueConstraint(fields=["user", "cohort"], name="one_exec_interest_per_cohort")
        ]
        verbose_name = "Executive interest"

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} - {self.get_role_display()}"
