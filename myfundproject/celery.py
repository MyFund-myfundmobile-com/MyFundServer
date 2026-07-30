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
<<<<<<< HEAD
=======
    "authentication.tasks.sync_user_to_brevo": {"queue": "default"},
>>>>>>> staging
    "authentication.tasks.send_namecheap_safe_email_task_v2": {"queue": "default"},
    "authentication.tasks.calculate_daily_roi_task": {"queue": "default"},
    "authentication.tasks.process_target_savings_deductions": {"queue": "default"},
    "authentication.tasks.retry_failed_deductions": {"queue": "default"},
    "authentication.tasks.check_completed_targets": {"queue": "default"},
    "authentication.tasks.refund_contributions_if_goal_not_reached": {
        "queue": "default"
    },
<<<<<<< HEAD
=======
    "authentication.tasks.expire_groupbuys_task": {"queue": "default"},
>>>>>>> staging
    "authentication.tasks.process_due_scheduled_withdrawals": {"queue": "default"},
    "authentication.tasks.send_birthday_greetings": {"queue": "default"},
    "authentication.tasks.reward_top_savers_of_month": {"queue": "default"},
    "authentication.tasks.process_quarterly_payouts_task": {"queue": "default"},
    "authentication.tasks.autosubmit_missing_ambassador_reports_task": {
        "queue": "default"
    },
<<<<<<< HEAD
       "authentication.tasks.send_inactive_signup_reminders": {
        "queue": "default"
    },
=======
>>>>>>> staging
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
app.conf.beat_schedule = {
    # Target savings
    "process-target-savings-daily": {
        "task": "authentication.tasks.process_target_savings_deductions",
        "schedule": crontab(hour=6, minute=0),
    },
    "retry-failed-deductions-daily": {
        "task": "authentication.tasks.retry_failed_deductions",
        "schedule": crontab(hour=18, minute=0),
    },
    "check-completed-targets-daily": {
        "task": "authentication.tasks.check_completed_targets",
        "schedule": crontab(hour=2, minute=0),
    },
    "refund-contributions": {
        "task": "authentication.tasks.refund_contributions_if_goal_not_reached",
        "schedule": crontab(hour=0, minute=0),
    },
<<<<<<< HEAD
=======
    "expire-overdue-groupbuys-daily": {
        "task": "authentication.tasks.expire_groupbuys_task",
        "schedule": crontab(hour=0, minute=15),
    },
>>>>>>> staging
    # ROI & Payouts
    "calculate-daily-roi": {
        "task": "authentication.tasks.calculate_daily_roi_task",
        "schedule": crontab(hour=12, minute=0),
        "options": {"queue": "default"},
    },
    "process-quarterly-payouts": {
<<<<<<< HEAD
        "task": "authentication.tasks.process_quarterly_payouts_task",
        "schedule": crontab(minute=0, hour=9, day_of_month=1, month_of_year="1,4,7,10"),
=======
        "task": "authentication.tasks.release_quarterly_roi",
        "schedule": crontab(minute=0, hour=9, day_of_month=1, month_of_year="1,4,7,10"),
        "kwargs": {"test_mode": False},
>>>>>>> staging
    },
    # Top Saver Rewards
    "reward-top-savers-monthly": {
        "task": "authentication.tasks.reward_top_savers_of_month",
        "schedule": crontab(hour=0, minute=10, day_of_month="28-31"),
    },
    # Birthday Greetings
    "send-birthday-greetings-daily": {
        "task": "authentication.tasks.send_birthday_greetings",
        "schedule": crontab(hour=8, minute=0),
    },
<<<<<<< HEAD
    # Scheduled withdrawals
    "process-scheduled-withdrawals-daily": {
        "task": "authentication.tasks.process_due_scheduled_withdrawals",
        "schedule": crontab(hour=11, minute=0),
=======
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
>>>>>>> staging
    },
    "autosubmit-missing-ambassador-reports-monthly": {
        "task": "authentication.tasks.autosubmit_missing_ambassador_reports_task",
        "schedule": crontab(minute=5, hour=0, day_of_month=1),
    },
<<<<<<< HEAD
    "send-inactive-signup-reminders": {
        "task": "authentication.tasks.send_inactive_signup_reminders",
        "schedule": crontab(hour=10, minute=0, day_of_month="*/3"),
    },
  
=======
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
>>>>>>> staging
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
<<<<<<< HEAD
    timezone=settings.TIME_ZONE,
=======
    timezone="Africa/Lagos",
    enable_utc=False,
>>>>>>> staging
)
