# celery.py
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")

app = Celery("myfundproject")

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Add beat schedule
app.conf.beat_schedule = {
    # Target savings deductions - run every 15 minutes
    "process-recurring-target-savings": {
        "task": "authentication.tasks.process_recurring_target_savings",
        "schedule": crontab(minute="*/15"),
    },
    # Existing refund task - daily at midnight
    "refund-contributions": {
        "task": "authentication.tasks.refund_contributions_if_goal_not_reached",
        "schedule": crontab(hour=0, minute=0),
    },
}

app.autodiscover_tasks()
