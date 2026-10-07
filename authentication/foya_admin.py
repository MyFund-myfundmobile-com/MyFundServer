from django.contrib import admin, messages

from .foya import send_to
from .foya_models import MAX_PUSHES_PER_CAMPAIGN, FoyaCampaign, FoyaEvent, FoyaPosition, FoyaPush


class FoyaPushInline(admin.TabularInline):
    model = FoyaPush
    extra = 0
    max_num = MAX_PUSHES_PER_CAMPAIGN
    fields = ["slot", "title", "body", "send_at", "status", "sent_at", "recipients_count"]
    readonly_fields = ["sent_at", "recipients_count"]


@admin.register(FoyaCampaign)
class FoyaCampaignAdmin(admin.ModelAdmin):
    list_display = ["__str__", "is_active", "show_position", "start_at", "end_at"]
    inlines = [FoyaPushInline]


@admin.register(FoyaPush)
class FoyaPushAdmin(admin.ModelAdmin):
    list_display = ["slot", "title", "send_at", "status", "sent_at", "recipients_count"]
    list_filter = ["status", "slot"]
    readonly_fields = ["sent_at", "recipients_count"]
    actions = ["send_test_to_me"]

    def has_add_permission(self, request):
        # Every campaign is capped at 3 pushes; the model refuses a 4th too.
        if FoyaCampaign.objects.exists() and all(c.pushes.count() >= MAX_PUSHES_PER_CAMPAIGN for c in FoyaCampaign.objects.all()):
            return False
        return super().has_add_permission(request)

    @admin.action(description="Send test to me (staff only, does not mark as sent)")
    def send_test_to_me(self, request, queryset):
        if not request.user.is_staff:
            self.message_user(request, "Only staff can send test pushes.", messages.ERROR)
            return
        for push in queryset:
            reached = send_to([request.user], push)
            self.message_user(request, f"“{push.get_slot_display()}” test sent to {request.user.email} ({'delivered' if reached else 'no device token'}).",
                              messages.SUCCESS if reached else messages.WARNING)


@admin.register(FoyaEvent)
class FoyaEventAdmin(admin.ModelAdmin):
    list_display = ["created_at", "event", "category_key", "source", "user"]
    list_filter = ["event", "source", "category_key"]
    readonly_fields = ["created_at", "event", "category_key", "source", "user"]

    def has_add_permission(self, request):
        return False


@admin.register(FoyaPosition)
class FoyaPositionAdmin(admin.ModelAdmin):
    list_display = ["updated_at", "category_key", "position", "field_size", "is_tied", "previous_position", "updated_by"]
    list_filter = ["category_key"]
    readonly_fields = ["previous_position", "previous_field_size", "previous_is_tied", "updated_at", "updated_by"]

    def save_model(self, request, obj, form, change):
        # Fallback editing keeps the same history trail as the web page.
        if not change:
            prev = FoyaPosition.objects.filter(campaign=obj.campaign, category_key=obj.category_key).first()
            if prev:
                obj.previous_position, obj.previous_field_size, obj.previous_is_tied = prev.position, prev.field_size, prev.is_tied
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)
