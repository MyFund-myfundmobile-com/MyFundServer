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
    "authentication.tasks.send_namecheap_safe_email_task_v2": {"queue": "default"},
    "authentication.tasks.calculate_daily_roi_task": {"queue": "default"},
    "authentication.tasks.process_target_savings_deductions": {"queue": "default"},
    "authentication.tasks.retry_failed_deductions": {"queue": "default"},
    "authentication.tasks.check_completed_targets": {"queue": "default"},
    "authentication.tasks.refund_contributions_if_goal_not_reached": {
        "queue": "default"
    },
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
    # ROI & Payouts
    "calculate-daily-roi": {
        "task": "authentication.tasks.calculate_daily_roi_task",
        "schedule": crontab(hour=12, minute=0),
        "options": {"queue": "default"},
    },
    "process-quarterly-payouts": {
        "task": "authentication.tasks.process_quarterly_payouts_task",
        "schedule": crontab(minute=0, hour=9, day_of_month=1, month_of_year="1,4,7,10"),
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
    # Scheduled withdrawals
    "process-scheduled-withdrawals-daily": {
        "task": "authentication.tasks.process_due_scheduled_withdrawals",
        "schedule": crontab(hour=11, minute=0),
    },
    "autosubmit-missing-ambassador-reports-monthly": {
        "task": "authentication.tasks.autosubmit_missing_ambassador_reports_task",
        "schedule": crontab(minute=5, hour=0, day_of_month=1),
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
    timezone=settings.TIME_ZONE,
)
