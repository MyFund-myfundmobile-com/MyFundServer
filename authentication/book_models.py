"""In-app reading progress for the ambassador book(s) - see book_views.py."""
from django.conf import settings
from django.db import models


class BookReadingProgress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="book_progress")
    book = models.CharField(max_length=40)
    last_page = models.PositiveIntegerField(default=1)
    # Furthest page reached, so jumping back to re-read doesn't undo progress.
    max_page = models.PositiveIntegerField(default=1)
    total_pages = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "book"], name="unique_book_progress")]
        verbose_name = "Book Reading Progress"
        verbose_name_plural = "Book Reading Progress"

    @property
    def percent(self):
        return round(self.max_page / self.total_pages * 100) if self.total_pages else 0

    def __str__(self):
        return f"{self.user.email} - {self.book} ({self.percent}%)"
