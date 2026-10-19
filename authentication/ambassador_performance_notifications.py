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


def notification_copy(report, previous_rank, weekly, as_of, first_name):
    rank, stats = report["rank"], report["month_summary"]
    cohort = report["cohort"]["cohort_number"]
    position, total = rank["position"], rank["total_ambassadors"]
    if weekly:
        email_subject = f"Your weekly Cohort {cohort} performance"
        intro = "Here is your weekly performance snapshot."
    else:
        direction = "improved" if position < previous_rank else "changed"
        email_subject = f"Cohort {cohort}: your position {direction} to #{position}"
        intro = f"Your overall cohort position moved from #{previous_rank} to #{position}."

    # Android may truncate long push bodies even when expanded. Keep this to
    # the decision-making metrics only; the tap takes the member to the full,
    # live breakdown in the app.
    push_title = f"Cohort {cohort} update"
    push_message = (
        f"You’re #{position} of {total} with {stats['points']} points: "
        f"{stats['signups']} sign-ups, {stats['confirmed']} confirmed referrals "
        f"and {stats['attendance']} sessions. Keep going—tap to view your report."
    )
    email_html = f"""
        <p>Hi {escape(first_name or 'there')},</p>
        <p>{escape(intro)}</p>
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;max-width:560px">
          <tr><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;color:#4b5563">Overall rank</td><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;text-align:right"><strong>#{position} of {total}</strong></td></tr>
          <tr><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;color:#4b5563">{escape(stats['month_label'])} points</td><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;text-align:right"><strong>{stats['points']}</strong></td></tr>
          <tr><td style="padding:14px 0;border-bottom:1px solid #e5e7eb;color:#4c28bc"><strong>Confirmed referrals — key focus</strong></td><td style="padding:14px 0;border-bottom:1px solid #e5e7eb;text-align:right;color:#4c28bc"><strong>{stats['confirmed']}</strong></td></tr>
          <tr><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;color:#4b5563">Sign-ups</td><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;text-align:right"><strong>{stats['signups']}</strong></td></tr>
          <tr><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;color:#4b5563">Sessions attended</td><td style="padding:10px 0;border-bottom:1px solid #e5e7eb;text-align:right"><strong>{stats['attendance']}</strong></td></tr>
          <tr><td style="padding:10px 0;color:#4b5563">Monthly position</td><td style="padding:10px 0;text-align:right"><strong>#{stats['month_position']} of {total}</strong></td></tr>
        </table>
        <p style="margin-top:18px">Your lifetime points: <strong>{rank['lifetime_points']}</strong>.</p>
        <p>Live points are estimates until reports are approved; positions can change.</p>
        <p style="color:#6b7280;font-size:13px">As of {as_of:%d %b %Y, %H:%M} WAT</p>
    """
    return email_subject, push_title, push_message, email_html


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
            email_subject, push_title, push_message, email_html = notification_copy(
                report, previous, weekly_due, now, user.first_name
            )
            try:
                if channel == "email":
                    result = send_transactional_email(
                        subject=email_subject,
                        message=email_html,
                        recipient_list=[user.email],
                    )
                    success = bool(result and result.get("sent"))
                else:
                    result = send_push_notification(
                        user=user, title=push_title, message=push_message,
                        data={"type": "AmbassadorPerformance", "cohort": user.ambassador_cohort_id,
                              "position": position, "as_of": now.isoformat(),
                              "deep_link": {"screen": "AmbassadorPerformanceReportScreen"}},
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
