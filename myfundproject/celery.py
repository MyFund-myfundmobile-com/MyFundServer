from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")

app = Celery("myfundproject")

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object("django.conf:settings", namespace="CELERY")

# CORRECTED SCHEDULE - Use the exact task names from your tasks.py
app.conf.beat_schedule = {
    # Process target savings every 5 minutes for testing
    "process-target-savings-every-5-mins": {
        "task": "authentication.tasks.process_target_savings_deductions",  # ← CORRECT NAME
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
    },
    # Check for completed targets daily at 2:00 AM
    "check-completed-targets-daily": {
        "task": "authentication.tasks.check_completed_targets",
        "schedule": crontab(hour=2, minute=0),
    },
    # Retry failed deductions every 5 minutes
    "retry-failed-deductions-every-5-mins": {
        "task": "authentication.tasks.retry_failed_deductions",
        "schedule": crontab(minute="*/5"),
    },
    # Existing refund task - daily at midnight
    "refund-contributions": {
        "task": "authentication.tasks.refund_contributions_if_goal_not_reached",
        "schedule": crontab(hour=0, minute=0),
    },
}

app.autodiscover_tasks()

# Use the timezone from your settings
app.conf.timezone = settings.TIME_ZONE
