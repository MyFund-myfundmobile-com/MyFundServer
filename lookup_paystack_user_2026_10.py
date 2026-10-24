# Read-only: what Paystack has charged one customer, and their subscription. Run with:
#   venv/bin/python manage.py shell < lookup_paystack_user_2026_10.py
import requests
from django.conf import settings

EMAIL = "marianoluwakemi170@gmail.com"
SUB_CODE = "SUB_gdii6bed0mjyrgs"
H = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}

cust = requests.get(f"https://api.paystack.co/customer/{EMAIL}", headers=H).json()
cid = (cust.get("data") or {}).get("id")
print("CUSTOMER", cid, cust.get("message"))

txs = requests.get("https://api.paystack.co/transaction", headers=H, params={"customer": cid, "perPage": 20}).json()
for t in txs.get("data") or []:
    plan = t.get("plan") or {}
    print("PSTX", t.get("paid_at") or t.get("created_at"), t.get("status"), int(t.get("amount", 0)) / 100,
          t.get("reference"), t.get("channel"), "plan:", plan.get("plan_code") if isinstance(plan, dict) else plan)

sub = requests.get(f"https://api.paystack.co/subscription/{SUB_CODE}", headers=H).json().get("data") or {}
print("SUB", sub.get("status"), "next:", sub.get("next_payment_date"), "created:", sub.get("createdAt"))
