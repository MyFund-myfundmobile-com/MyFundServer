# Read-only: why can't this ambassador start the /lead form? Run with:
#   venv/bin/python manage.py shell < lookup_exec_email_2026_11.py
from django.db.models import Q
from authentication.models import CustomUser, AmbassadorCohort
from authentication.ambassador_application_models import AmbassadorApplication

EMAIL = "adesuru_adewale@yahoo.co.uk"
local = EMAIL.split("@")[0]

print("CURRENT COHORTS", list(AmbassadorCohort.objects.values_list("cohort_number", "status")))
print("--- exact email match")
for u in CustomUser.objects.filter(email__iexact=EMAIL):
    print("USER", u.pk, repr(u.email), u.first_name, u.last_name, u.phone_number, "ambassador", u.is_ambassador,
          "influencer", getattr(u, "is_influencer", None), "cohort", u.ambassador_cohort,
          "active", u.is_active, "deleted", getattr(u, "is_deleted", None))
print("--- similar emails / names")
for u in CustomUser.objects.filter(Q(email__icontains=local[:8]) | Q(email__icontains="adesuru")
                                   | Q(first_name__icontains="adesuru") | Q(last_name__icontains="adesuru")
                                   | Q(first_name__icontains="adewale", last_name__icontains="adesuru"))[:20]:
    print("SIMILAR", u.pk, repr(u.email), u.first_name, u.last_name, u.phone_number,
          "ambassador", u.is_ambassador, "cohort", u.ambassador_cohort)
print("--- ambassador applications")
for a in AmbassadorApplication.objects.filter(Q(email__icontains="adesuru") | Q(email__iexact=EMAIL)):
    print("APP", repr(a.email), a.status, a.intake, "user", a.user_id and (a.user_id, a.user.email))
