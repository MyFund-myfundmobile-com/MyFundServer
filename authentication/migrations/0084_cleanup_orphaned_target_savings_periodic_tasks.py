from django.db import migrations


# django_celery_beat's DatabaseScheduler reads its schedule from
# PeriodicTask rows in the DB, and syncs new/changed entries from
# celery.py's own app.conf.beat_schedule on startup - but it never deletes
# rows that are no longer present there. Over time this left three stale
# rows still enabled and still firing every cycle, alongside the
# code-defined "process-target-savings-daily"/"retry-failed-deductions-
# daily" entries:
#
#   - "process-recurring-target-savings" (every 15 min, 21k+ runs) calls
#     "authentication.tasks.process_recurring_target_savings", a function
#     that no longer exists anywhere in this codebase - every dispatch is a
#     guaranteed NotRegistered error on the worker side.
#   - "process-target-savings-every-5-mins" (63k+ runs) and
#     "retry-failed-deductions-every-5-mins" duplicate
#     "process-target-savings-daily"/"retry-failed-deductions-daily" at a
#     much higher frequency than intended, for no benefit (both underlying
#     tasks are already idempotent per-run - a target no longer due simply
#     isn't picked up again until its next_deduction/next_retry catches up).
#
# None of these three caused the actual outage being fixed alongside this
# migration (that was a queue-routing bug - see the queue="default" change
# on process_target_savings_deductions/process_due_scheduled_withdrawals/
# calculate_daily_roi_task in authentication/tasks.py, and the removed
# CELERY_TASK_ROUTES block in settings.py), but they're confusing, wasteful
# dead weight worth clearing out while in here.
STALE_PERIODIC_TASK_NAMES = [
    "process-recurring-target-savings",
    "process-target-savings-every-5-mins",
    "retry-failed-deductions-every-5-mins",
]


def delete_stale_periodic_tasks(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name__in=STALE_PERIODIC_TASK_NAMES).delete()


def noop_reverse(apps, schema_editor):
    # Deliberately not recreating these on reverse - they were dead
    # weight/misconfigured, not a feature to restore.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0083_add_groupbuy_chat_message"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(delete_stale_periodic_tasks, noop_reverse),
    ]
