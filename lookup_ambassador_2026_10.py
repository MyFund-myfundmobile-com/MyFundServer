# Read-only: ambassador points/referral lookup by phone. Run with:
#   venv/bin/python manage.py shell < lookup_ambassador_2026_10.py
from django.db.models import Q
from authentication.models import CustomUser, AmbassadorMonthlyReport, AmbassadorAttendanceSubmission
from authentication.views import _live_ambassador_month
from authentication.models import AmbassadorPointConfig

DIGITS = "8187157971"
u = CustomUser.objects.filter(
    Q(phone_number__endswith=DIGITS) | Q(phone_number__endswith="0" + DIGITS)
).first()
print("USER", u and (u.pk, u.first_name, u.last_name, u.email, u.phone_number, "ambassador", u.is_ambassador,
                     "influencer", u.is_influencer, "code", getattr(u, "referral_code", None)))
if u:
    cfg = AmbassadorPointConfig.get_active()
    for key in ("2026-09", "2026-10"):
        print("LIVE", key, "signups/confirmed/attendance/points =", _live_ambassador_month(u, key, cfg))
    for r in AmbassadorMonthlyReport.objects.filter(user=u).order_by("month"):
        print("REPORT", r.month, r.status, "signups", r.signups_approved, "confirmed", r.confirmed_approved,
              "attendance", r.attendance_approved, "points", r.total_points_awarded)
    print("ATTENDANCE", list(AmbassadorAttendanceSubmission.objects.filter(user=u).values_list("month", flat=True)))
    for x in CustomUser.objects.filter(referral=u).order_by("-date_joined"):
        print("REFERRAL", x.date_joined, x.first_name, x.last_name, x.email, "savings", x.savings,
              "reward_granted", x.referral_reward_granted, x.referral_reward_confirmed_at)
