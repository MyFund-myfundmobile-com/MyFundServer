"""Scheduled reports share the mobile report's scoring and cohort ranking."""
import logging
from datetime import timedelta
from zoneinfo import ZoneInfo

from celery import shared_task
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.html import escape

from .models import CustomUser, AmbassadorPerformanceNotificationState
from .utils import send_transactional_email, send_push_notification

logger = logging.getLogger(__name__)


def notification_copy(report, previous_rank, weekly, as_of):
    rank, stats = report["rank"], report["month_summary"]
    cohort = report["cohort"]["cohort_number"]
    position, total = rank["position"], rank["total_ambassadors"]
    if weekly:
        title = f"Your weekly Cohort {cohort} performance report"
        movement = "Your weekly performance snapshot."
    else:
        direction = "improved" if position < previous_rank else "changed"
        title = f"Cohort {cohort}: overall position {direction} to #{position}"
        movement = f"Your overall cohort position moved from #{previous_rank} to #{position}."
    message = (
        f"{movement} Overall: #{position} of {total} in Cohort {cohort}, "
        f"with {rank['lifetime_points']} points since the cohort started. "
        f"{stats['month_label']} so far: {stats['signups']} sign-ups, "
        f"{stats['confirmed']} confirmed referrals, {stats['attendance']} sessions, "
        f"{stats['points']} points. Monthly position: #{stats['month_position']} of {total}. "
        f"As of {as_of:%d %b %Y, %H:%M} WAT. "
        "Live points are estimates until reports are approved. Positions can change."
    )
    return title, message


def notify_member(user, weekly, now):
    from .views import AmbassadorPerformanceReportView
    week = (now.date() - timedelta(days=now.weekday())).isoformat()
    with transaction.atomic():
        state, _ = AmbassadorPerformanceNotificationState.objects.get_or_create(
            user=user, cohort=user.ambassador_cohort,
        )
        state = AmbassadorPerformanceNotificationState.objects.select_for_update().get(pk=state.pk)
        report = AmbassadorPerformanceReportView().build_report(user).data
        if not report.get("rank") or not report.get("month_summary"):
            return
        position = report["rank"]["position"]
        for channel in ("email", "push"):
            saved = state.channels.get(channel, {})
            previous = saved.get("rank")
            weekly_due = weekly and saved.get("week") != week
            changed = previous is not None and previous != position
            if not weekly_due and not changed:
                if previous is None:
                    state.channels[channel] = {**saved, "rank": position}
                continue
            title, message = notification_copy(report, previous, weekly_due, now)
            try:
                if channel == "email":
                    result = send_transactional_email(
                        subject=title,
                        message=f"Hi {escape(user.first_name)},<br><br>{escape(message)}",
                        recipient_list=[user.email],
                    )
                    success = bool(result and result.get("sent"))
                else:
                    result = send_push_notification(
                        user=user, title=title, message=message,
                        data={"type": "AmbassadorPerformance", "cohort": user.ambassador_cohort_id,
                              "position": position, "as_of": now.isoformat()},
                    )
                    # The helper also stores an in-app notification. With no
                    # registered device, don't recreate it on every sweep.
                    success = bool(result and (result.get("success") or result.get("total") == 0))
                if success:
                    state.channels[channel] = {**saved, "rank": position,
                                               **({"week": week} if weekly_due else {})}
            except Exception:
                logger.exception("Ambassador %s notification failed for user %s", channel, user.pk)
        state.save(update_fields=["channels"])


@shared_task
def send_ambassador_performance_updates(weekly=False):
    now = timezone.now().astimezone(ZoneInfo("Africa/Lagos"))
    users = CustomUser.objects.filter(
        is_ambassador=True, is_influencer=False, is_deleted=False, is_active=True,
        ambassador_cohort__status="active", ambassador_cohort__start_date__lte=now.date(),
    ).filter(Q(ambassador_cohort__end_date__isnull=True) |
             Q(ambassador_cohort__end_date__gte=now.date())).select_related("ambassador_cohort")
    for user in users.iterator():
        try:
            notify_member(user, weekly, now)
        except Exception:
            logger.exception("Performance report failed for ambassador %s", user.pk)
