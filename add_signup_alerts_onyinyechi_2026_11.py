# add_signup_alerts_onyinyechi_2026_11.py
#
# One-off: lets Onyinyechi Otum (CX intern) receive the "new user signup"
# admin push alerts. Push routing is AdminNotifyRecipient (see
# utils.get_admin_notify_users), deliberately separate from is_staff, with a
# toggle per alert type - she gets signups ONLY (transaction alerts show
# other users' payment details). Also prints the other recipients' toggles
# for comparison. Safe to re-run.

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from authentication.models import AdminNotifyRecipient, CustomUser
from authentication.utils import get_admin_notify_users

EMAIL = "onyinyechiotum@gmail.com"

user = CustomUser.objects.filter(email__iexact=EMAIL).first()
if not user:
    raise SystemExit(f"No account for {EMAIL}")

row, created = AdminNotifyRecipient.objects.get_or_create(
    email=user.email,
    defaults=dict(
        label="Onyinyechi Otum (CX intern)",
        notify_signups=True,
        notify_transactions=False,
        notify_groupbuy=False,
        notify_system=False,
        is_active=True,
    ),
)
if not created:
    row.notify_signups = True
    row.is_active = True
    row.save(update_fields=["notify_signups", "is_active"])
print(("Added" if created else "Updated"), row,
      f"signups={row.notify_signups} transactions={row.notify_transactions} "
      f"groupbuy={row.notify_groupbuy} system={row.notify_system}")

print("\nAll active recipients:")
for r in AdminNotifyRecipient.objects.filter(is_active=True).order_by("email"):
    print(f"  {r.email:38} signups={r.notify_signups} tx={r.notify_transactions} "
          f"groupbuy={r.notify_groupbuy} system={r.notify_system}")

ok = get_admin_notify_users("signups").filter(pk=user.pk).exists()
tokens = len(user.expo_push_tokens or [])
print(f"\nWill receive signup alerts: {ok}  (registered devices: {tokens})")
