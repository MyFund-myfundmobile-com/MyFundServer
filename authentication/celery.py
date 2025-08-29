from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# Set the default Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")

app = Celery("myfundproject")

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

# SIMPLIFIED SCHEDULE - NO DUPLICATES
app.conf.beat_schedule = {
    # Process target savings EVERY HOUR at :00
    "process-target-savings-hourly": {
        "task": "authentication.tasks.process_target_savings_deductions",
        "schedule": crontab(minute=0),  # Every hour at :00
    },
    # Check for completed targets daily at 2:00 AM
    "check-completed-targets-daily": {
        "task": "authentication.tasks.check_completed_targets",
        "schedule": crontab(hour=2, minute=0),
    },
    # Retry failed deductions every hour at :30
    "retry-failed-deductions-hourly": {
        "task": "authentication.tasks.retry_failed_deductions",
        "schedule": crontab(minute=30),
    },
}

# Use the timezone from your settings
app.conf.timezone = settings.CELERY_TIMEZONE


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")
