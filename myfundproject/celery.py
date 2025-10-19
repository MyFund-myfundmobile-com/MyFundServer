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

# --- Target Savings Tasks ---
app.conf.beat_schedule = {
    # Process target savings every 5 minutes for testing
    "process-target-savings-every-5-mins": {
        "task": "authentication.tasks.process_target_savings_deductions",
        "schedule": crontab(minute="*/5"),
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
    # Refund contributions daily at midnight
    "refund-contributions": {
        "task": "authentication.tasks.refund_contributions_if_goal_not_reached",
        "schedule": crontab(hour=0, minute=0),
    },
}

app.autodiscover_tasks()
app.conf.timezone = settings.TIME_ZONE

# --- ROI & Payout Tasks ---
# celery.py - Update the beat schedule
app.conf.beat_schedule.update(
    {
        "calculate-daily-roi": {
            "task": "authentication.tasks.calculate_daily_roi_task",
            "schedule": crontab(hour=23, minute=59),  # End of day
        },
        "process-quarterly-payouts": {
            "task": "authentication.tasks.process_quarterly_payouts_task",
            "schedule": crontab(
                minute=0, hour=9, day_of_month=1, month_of_year="1,4,7,10"
            ),  # 9AM on first day of quarter
        },
    }
)
