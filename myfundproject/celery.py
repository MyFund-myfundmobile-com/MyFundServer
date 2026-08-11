from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings
from kombu import Queue

# -----------------------------
# Set default Django settings
# -----------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")

app = Celery("myfundproject")

# -----------------------------
# Config from Django settings
# -----------------------------
app.config_from_object("django.conf:settings", namespace="CELERY")
app.conf.broker_connection_retry_on_startup = True

# -----------------------------
# Define queues
# -----------------------------
app.conf.task_queues = (
    Queue("default", routing_key="default"),
    Queue("email_queue", routing_key="email"),
)

# -----------------------------
# Route tasks to queues
# -----------------------------
app.conf.task_routes = {
    "authentication.tasks.send_bulk_email_task": {"queue": "email_queue"},
    "authentication.tasks.send_single_email_task": {"queue": "email_queue"},
    "authentication.tasks.sync_user_to_brevo": {"queue": "default"},
    "authentication.tasks.send_namecheap_safe_email_task_v2": {"queue": "default"},
    "authentication.tasks.calculate_daily_roi_task": {"queue": "default"},
    "authentication.tasks.process_target_savings_deductions": {"queue": "default"},
    "authentication.tasks.retry_failed_deductions": {"queue": "default"},
    "authentication.tasks.check_completed_targets": {"queue": "default"},
    "authentication.tasks.refund_contributions_if_goal_not_reached": {
        "queue": "default"
    },
    "authentication.tasks.expire_groupbuys_task": {"queue": "default"},
    "authentication.tasks.auto_distribute_groupbuy_income_task": {"queue": "default"},
    "authentication.tasks.send_groupbuy_deadline_reminders_task": {"queue": "default"},
    "authentication.tasks.process_due_scheduled_withdrawals": {"queue": "default"},
    "authentication.tasks.send_birthday_greetings": {"queue": "default"},
    "authentication.tasks.reward_top_savers_of_month": {"queue": "default"},
    "authentication.tasks.process_quarterly_payouts_task": {"queue": "default"},
    "authentication.tasks.autosubmit_missing_ambassador_reports_task": {
        "queue": "default"
    },
}

# Default queue for unspecified tasks
app.conf.task_default_queue = "default"
app.conf.task_default_exchange = "default"
app.conf.task_default_routing_key = "default"

# -----------------------------
# Autodiscover tasks
# -----------------------------
app.autodiscover_tasks()

# -----------------------------
# Beat schedules
# -----------------------------
# All hours below are UTC (see enable_utc/timezone at the bottom of this
# file) and are written 1 hour earlier than the Africa/Lagos (WAT, UTC+1)
# wall-clock time they're meant to represent - e.g. hour=5 here fires at
# 06:00 WAT. This keeps every job's real-world Lagos-time firing point
# unchanged from before, while making the *crontab evaluation* timezone
# match UTC - the timezone next_deduction/last_processed/etc. are actually
# stored in (Django's timezone.now() is always UTC-aware). Previously both
# were WAT (enable_utc=False, timezone="Africa/Lagos"), which produced a
# recurring ~12h lag/mismatch pattern for any DAILY target-savings plan
# whose scheduled slot time-of-day fell after the deduction sweep's WAT
# run time - see process_target_savings_deductions().
#
# The two monthly jobs whose day_of_month range spans a month boundary
# (reward-top-savers-monthly, autosubmit-missing-ambassador-reports-
# monthly) have that range shifted back by one calendar day for the same
# reason (00:xx WAT on day D is 23:xx UTC on day D-1). Both underlying
# tasks are safe to fire more than once near the boundary in short/leap
# months - autosubmit_missing_ambassador_reports_for_previous_month() is
# explicitly idempotent (skips users who already have a report), and this
# range already produced the same multiplicity in most/all months before
# this change, just under the old WAT-evaluated schedule.
app.conf.beat_schedule = {
    # Target savings
    "process-target-savings-daily": {
        "task": "authentication.tasks.process_target_savings_deductions",
        "schedule": crontab(hour=5, minute=0),
    },
    "retry-failed-deductions-daily": {
        "task": "authentication.tasks.retry_failed_deductions",
        "schedule": crontab(hour=17, minute=0),
    },
    "check-completed-targets-daily": {
        "task": "authentication.tasks.check_completed_targets",
        "schedule": crontab(hour=1, minute=0),
    },
    "refund-contributions": {
        "task": "authentication.tasks.refund_contributions_if_goal_not_reached",
        "schedule": crontab(hour=23, minute=0),
    },
    "expire-overdue-groupbuys-daily": {
        "task": "authentication.tasks.expire_groupbuys_task",
        "schedule": crontab(hour=23, minute=15),
    },
    # Checks daily but only moves money for a given group once/month (see
    # auto_distribute_groupbuy_income_task docstring) - cheap no-op on most
    # days.
    "auto-distribute-groupbuy-income-daily": {
        "task": "authentication.tasks.auto_distribute_groupbuy_income_task",
        "schedule": crontab(hour=0, minute=0),
    },
    "groupbuy-deadline-reminders-daily": {
        "task": "authentication.tasks.send_groupbuy_deadline_reminders_task",
        "schedule": crontab(hour=8, minute=0),
    },
    # ROI & Payouts
    "calculate-daily-roi": {
        "task": "authentication.tasks.calculate_daily_roi_task",
        "schedule": crontab(hour=11, minute=0),
        "options": {"queue": "default"},
    },
    "process-quarterly-payouts": {
        "task": "authentication.tasks.release_quarterly_roi",
        "schedule": crontab(minute=0, hour=8, day_of_month=1, month_of_year="1,4,7,10"),
        "kwargs": {"test_mode": False},
    },
    # Top Saver Rewards
    "reward-top-savers-monthly": {
        "task": "authentication.tasks.reward_top_savers_of_month",
        "schedule": crontab(hour=23, minute=10, day_of_month="27-30"),
    },
    # Birthday Greetings
    "send-birthday-greetings-daily": {
        "task": "authentication.tasks.send_birthday_greetings",
        "schedule": crontab(hour=7, minute=0),
    },
    # Scheduled withdrawals - hourly rather than once/day. The model only
    # stores a date (no time), so hourly is already far finer than needed
    # for "due" precision - the real point is resilience: if a run fails
    # (exhausts its in-task retries), a once-daily schedule left a
    # withdrawal stuck for up to 24h with no other automated attempt. Since
    # process_due_scheduled_withdrawals/process_scheduled_withdrawal are
    # both idempotent (is_processed guard + existing-credit check), the
    # next hourly run just safely re-picks-up anything still pending.
    "process-scheduled-withdrawals-hourly": {
        "task": "authentication.tasks.process_due_scheduled_withdrawals",
        "schedule": crontab(minute=0),
    },
    "autosubmit-missing-ambassador-reports-monthly": {
        "task": "authentication.tasks.autosubmit_missing_ambassador_reports_task",
        "schedule": crontab(minute=5, hour=23, day_of_month="28-31"),
    },
}


CELERY_BEAT_SCHEDULE = {
    "daily-metrics-task": {
        "task": "authentication.tasks.daily_metrics_task",
        "schedule": crontab(hour=22, minute=0),
    },
    "weekly-metrics-task": {
        "task": "authentication.tasks.weekly_metrics_task",
        "schedule": crontab(
            hour=9,
            minute=0,
            day_of_week="monday",
        ),
    },
    "monthly-metrics-task": {
        "task": "authentication.tasks.monthly_metrics_task",
        "schedule": crontab(
            hour=10,
            minute=0,
            day_of_month=1,
        ),
    },
}

# -----------------------------
# Worker safety & performance
# -----------------------------
app.conf.update(
    task_default_retry_delay=300,  # 5 minutes
    task_max_retries=3,
    worker_prefetch_multiplier=1,  # Prevent task hoarding
    worker_max_tasks_per_child=100,  # Avoid memory leaks
    task_acks_late=True,  # Ack after task completes
    # timezone/enable_utc are NOT set here on purpose - config_from_object()
    # above already resolved app.conf.timezone from settings.CELERY_TIMEZONE
    # (UTC), and that resolution wins over a later app.conf.update() call in
    # this Celery version - setting it again here is a silent no-op. Change
    # CELERY_TIMEZONE in settings.py if this ever needs to move.
)
