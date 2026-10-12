from django.contrib import admin

from .book_models import BookReadingProgress


@admin.register(BookReadingProgress)
class BookReadingProgressAdmin(admin.ModelAdmin):
    list_display = ["user", "book", "progress", "last_page", "total_pages", "completed_at", "updated_at", "started_at"]
    list_filter = ["book", ("completed_at", admin.EmptyFieldListFilter), "user__ambassador_cohort"]
    search_fields = ["user__email", "user__first_name", "user__last_name"]
    readonly_fields = ["user", "book", "last_page", "max_page", "total_pages", "started_at", "updated_at", "completed_at"]
    ordering = ["-updated_at"]

    @admin.display(description="Read", ordering="max_page")
    def progress(self, obj):
        return f"{obj.percent}% (p. {obj.max_page})"

    def has_add_permission(self, request):
        return False
