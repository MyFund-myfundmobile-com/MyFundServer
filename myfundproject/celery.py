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

# Retry connecting to broker on startup
app.conf.broker_connection_retry_on_startup = True

# Auto-discover tasks
app.autodiscover_tasks()

# --- Target Savings Tasks ---
app.conf.beat_schedule = {
    # Process target savings once daily (morning)
    # even though most are weekly/monthly, this ensures daily due ones are covered
    "process-target-savings-daily": {
        "task": "authentication.tasks.process_target_savings_deductions",
        "schedule": crontab(hour=6, minute=0),  # once per day
    },
    # Retry failed deductions once per day (evening)
    "retry-failed-deductions-daily": {
        "task": "authentication.tasks.retry_failed_deductions",
        "schedule": crontab(hour=18, minute=0),  # 6PM daily retry
    },
    # Check for completed targets once per day
    "check-completed-targets-daily": {
        "task": "authentication.tasks.check_completed_targets",
        "schedule": crontab(hour=2, minute=0),
    },
    # Refund contributions once per day (midnight)
    "refund-contributions": {
        "task": "authentication.tasks.refund_contributions_if_goal_not_reached",
        "schedule": crontab(hour=0, minute=0),
    },
}


app.autodiscover_tasks()
app.conf.timezone = settings.TIME_ZONE

# --- ROI & Payout Tasks ---
app.conf.beat_schedule.update(
    {
        "calculate-daily-roi": {
            "task": "authentication.tasks.calculate_daily_roi_task",
            "schedule": crontab(hour=12, minute=0),  # End of day
        },
        "process-quarterly-payouts": {
            "task": "authentication.tasks.process_quarterly_payouts_task",
            "schedule": crontab(
                minute=0, hour=9, day_of_month=1, month_of_year="1,4,7,10"
            ),  # 9AM on first day of quarter
        },
    }
)


# --- End-of-month Top Saver rewards ---
app.conf.beat_schedule.update(
    {
        "reward-top-savers-monthly": {
            "task": "authentication.tasks.reward_top_savers_of_month",
            "schedule": crontab(hour=0, minute=10, day_of_month="28-31"),
            # runs on last few days to cover months with 28,30,31 days
        },
    }
)


app.conf.beat_schedule.update(
    {
        "send-birthday-greetings-daily": {
            "task": "authentication.tasks.send_birthday_greetings",
            "schedule": crontab(hour=8, minute=0),  # Runs every morning at 8 AM
        },
    }
)


app.conf.beat_schedule.update(
    {
        "process-scheduled-withdrawals-daily": {
            "task": "authentication.tasks.process_due_scheduled_withdrawals",
            "schedule": crontab(hour=11, minute=0),
        },
    }
)

# Celery settings for Namecheap-safe email sending
app.conf.update(
    # Rate limiting for email tasks
    task_annotations={
        "authentication.tasks.send_namecheap_safe_email_task": {
            "rate_limit": "45/h",  # MAX 45 emails per hour
        },
        "authentication.tasks.send_bulk_email_task": {
            "rate_limit": "100/h",  # 100 per hour for small batches
        },
    },
    # Retry settings
    task_default_retry_delay=300,  # 5 minutes
    task_max_retries=3,
    # Worker settings
    worker_prefetch_multiplier=1,  # Process one task at a time
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks
)
