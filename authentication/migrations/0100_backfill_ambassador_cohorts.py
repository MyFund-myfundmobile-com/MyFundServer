import datetime

from django.db import migrations

# Historical backfill only - read-only with respect to is_ambassador and
# every payment/reward field it drives (referral thresholds,
# AmbassadorMonthlyReport stipends). This migration only ever writes to
# the brand-new ambassador_cohort column added in 0099; it never touches
# is_ambassador itself.
#
# Data source for the split (see the 2026-09 conversation this was built
# from - there is no clean historical "which cohort" record anywhere in
# the DB, only these two facts we can actually verify):
#   - is_ambassador=True today  -> currently active -> Cohort 3 (the
#     in-app Ambassador Info screen states Cohort 3 runs Apr 1-Sep 30).
#   - is_ambassador=False but has at least one AmbassadorMonthlyReport
#     row -> a *former* ambassador (only an ambassador could ever submit
#     one of those reports) who was in Cohort 1 or Cohort 2, but which of
#     the two can't be determined from existing data. Bucketed together
#     into one legacy placeholder (cohort_number=1) rather than guessing -
#     an admin can split it later via the bulk-assign action once/if a
#     real list turns up.
# Everyone else (never an ambassador) is left with ambassador_cohort=NULL.
COHORT_3_START = datetime.date(2026, 4, 1)
COHORT_3_END = datetime.date(2026, 9, 30)


def backfill_cohorts(apps, schema_editor):
    AmbassadorCohort = apps.get_model("authentication", "AmbassadorCohort")
    CustomUser = apps.get_model("authentication", "CustomUser")
    AmbassadorMonthlyReport = apps.get_model("authentication", "AmbassadorMonthlyReport")

    legacy_cohort, _ = AmbassadorCohort.objects.get_or_create(
        cohort_number=1,
        defaults={
            "name": "Cohort 1-2 (Legacy, pre-tracking)",
            "status": "ended",
        },
    )
    cohort_3, _ = AmbassadorCohort.objects.get_or_create(
        cohort_number=3,
        defaults={
            "start_date": COHORT_3_START,
            "end_date": COHORT_3_END,
            "status": "active",
        },
    )

    CustomUser.objects.filter(is_ambassador=True).update(ambassador_cohort=cohort_3)

    former_ambassador_ids = list(
        AmbassadorMonthlyReport.objects.filter(
            user__is_ambassador=False
        ).values_list("user_id", flat=True).distinct()
    )
    if former_ambassador_ids:
        CustomUser.objects.filter(id__in=former_ambassador_ids).update(
            ambassador_cohort=legacy_cohort
        )


def unbackfill_cohorts(apps, schema_editor):
    AmbassadorCohort = apps.get_model("authentication", "AmbassadorCohort")
    CustomUser = apps.get_model("authentication", "CustomUser")

    CustomUser.objects.filter(
        ambassador_cohort__cohort_number__in=[1, 3]
    ).update(ambassador_cohort=None)
    AmbassadorCohort.objects.filter(cohort_number__in=[1, 3]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0099_ambassadorcohort_customuser_ambassador_cohort'),
    ]

    operations = [
        migrations.RunPython(backfill_cohorts, unbackfill_cohorts),
    ]
