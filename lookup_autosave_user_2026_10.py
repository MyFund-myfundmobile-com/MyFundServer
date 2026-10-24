# Read-only: AutoSave support lookup for one user. Run with:
#   venv/bin/python manage.py shell < lookup_autosave_user_2026_10.py
from authentication.models import CustomUser, AutoSave, Transaction, Card

EMAIL = "marianoluwakemi170@gmail.com"

u = CustomUser.objects.filter(email__iexact=EMAIL).first()
print("USER", u and (u.pk, u.first_name, u.last_name, u.email, "savings", u.savings, "autosave_enabled", u.autosave_enabled, "joined", u.date_joined))
if u:
    for a in AutoSave.objects.filter(user=u):
        print("AUTOSAVE", a.pk, a.amount, a.frequency, "active", a.active, a.paystack_plan_code, a.paystack_sub_code, a.paystack_trans_ref)
    for c in Card.objects.filter(user=u):
        print("CARD", c.pk, c.card_last4_digits, "reusable", c.reusable, "active", c.is_active)
    for t in Transaction.objects.filter(user=u).order_by("-pk")[:25]:
        print("TX", t.pk, t.date, getattr(t, "time", ""), t.transaction_type, t.amount, t.status, t.description, t.transaction_id, t.paystack_reference)
