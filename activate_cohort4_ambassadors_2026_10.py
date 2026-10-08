"""One-off: activate the Cohort 4 ambassadors (October 2026).

For each email that has a MyFund account: put them in Cohort 4, switch on
ambassador access, and send a personal push (tap opens their Ambassador
page) and email (with the Cohort 4 WhatsApp group button). Then send the
admins (Tolulope, Janet, Chubi) a push + email summary.

Safe to re-run: anyone already an ambassador in Cohort 4 is skipped and
not messaged again. Emails without a MyFund account are only reported.

    python manage.py shell < activate_cohort4_ambassadors_2026_10.py          # dry run
    LIVE=1 python manage.py shell < activate_cohort4_ambassadors_2026_10.py   # for real
"""
import html
import os

from authentication.models import AmbassadorCohort, CustomUser
from authentication.utils import send_generic_email, send_push_notification

LIVE = os.environ.get("LIVE") == "1"
WHATSAPP_GROUP = "https://chat.whatsapp.com/FxaxT7vufZa1o9ouB4U6iV?mode=gi_t"
ADMIN_EMAILS = ["tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com", "josephgideon95@gmail.com"]
EMAILS = """adahraphael123@gmail.com, femidurojaye7.fd@gmail.com, okechukwusimone@gmail.com, ukanahpetersunday@gmail.com,
onyinyechiotum@gmail.com, favourolokungboye@gmail.com, abigealamusan3@gmail.com, sopurudavid01@gmail.com,
ayomidepraise011@gmail.com, olusegunboluwatife542@gmail.com, anjolaoluwa.olabisi190@gmail.com,
afolabiaanuoluwapo007@gmail.com, johnolawole@gmail.com, niffybabe2008@gmail.com, olutoyosiadeogun@gmail.com,
aladesuru_adewale@live.co.uk, aibhawoh@gmail.com, peacemojolaoluwa@gmail.com, quadrit272@gmail.com,
abuluoseh@gmail.com, 4evaernie@gmail.com, preciousokunwa73@gmail.com, ajayipriscilla7@gmail.com,
rae.tekateka@gmail.com, thomasesther290@gmail.com, adenibuyantosin608@gmail.com, tundeebabaa@gmail.com,
okunsanmifavour@gmail.com, aoluwatosin620@gmail.com, jesutofunmi.oyewole@studdnt.aul.edu.ng,
samuelsilver302@gmail.com, isaiahabolupe@gmail.com, haddylove08@gmail.com, theheuristics01@gmail.com"""

PUSH_TITLE = "🎉 Welcome to MyFund Ambassadors, Cohort 4!"
PUSH_BODY = "Hi {first}, your Ambassador access is now active. Tap to open your Ambassador page."
EMAIL_SUBJECT = "Welcome to MyFund Ambassadors, Cohort 4 🎉"
BUTTON = (
    f'<a href="{WHATSAPP_GROUP}" style="display:inline-block;background:#4C28BC;color:#ffffff;'
    'text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:10px;">'
    "Join the Cohort 4 WhatsApp group</a>"
)
EMAIL_BODY = (
    "Hi {first},<br><br>"
    "Congratulations! You're now a <b>MyFund Ambassador</b> in <b>Cohort 4</b>, "
    "and your Ambassador access is active on your MyFund account.<br><br>"
    "Open the MyFund app and tap <b>AMBASSADOR</b> on your home screen to see your Ambassador page.<br><br>"
    "If you haven't joined the Cohort 4 WhatsApp group yet, please join here:<br><br>"
    + BUTTON + "<br><br>"
    "Lioness<br>MyFund"
)


def first_name(user):
    return (user.first_name or "there").strip().split(" ")[0].title()


emails = [e.strip().lower() for e in EMAILS.replace("\n", " ").split(",") if e.strip()]
cohort = AmbassadorCohort.objects.get(cohort_number=4)
print(f"{'LIVE' if LIVE else 'DRY RUN'} - {len(emails)} emails, {cohort}")

activated, skipped, missing = [], [], []
for email in emails:
    user = CustomUser.objects.filter(email__iexact=email, is_deleted=False).first()
    if not user:
        missing.append(email)
        continue
    if user.is_ambassador and user.ambassador_cohort_id == cohort.id:
        skipped.append(user)
        continue
    has_device = bool(user.expo_push_tokens)
    row = {"user": user, "push": None, "email": None, "device": has_device}
    if LIVE:
        user.is_ambassador = True
        user.ambassador_cohort = cohort
        user.save(update_fields=["is_ambassador", "ambassador_cohort"])
        try:
            res = send_push_notification(
                user=user, title=PUSH_TITLE, message=PUSH_BODY.format(first=first_name(user)), notif_type="SYSTEM",
                data={"type": "AMBASSADOR_GRANTED", "is_ambassador": True, "ambassador_cohort": 4,
                      "deep_link": {"screen": "TopReferrals"}},
            )
            row["push"] = bool(res and res.get("sent"))
        except Exception as e:
            row["push"] = False
            print("  push failed", email, e)
        try:
            send_generic_email(subject=EMAIL_SUBJECT, message=EMAIL_BODY.format(first=html.escape(first_name(user))),
                               from_email="MyFund <info@myfundmobile.com>", recipient_list=[user.email])
            row["email"] = True
        except Exception as e:
            row["email"] = False
            print("  email failed", email, e)
    activated.append(row)
    print(f"  {'ACTIVATED' if LIVE else 'would activate'} {user.email} ({user.first_name} {user.last_name}) "
          f"device={'yes' if has_device else 'no'} push={row['push']} email={row['email']}")

if LIVE and cohort.status != "active":
    cohort.status = "active"
    cohort.save(update_fields=["status"])

print(f"\nActivated {len(activated)}, already done {len(skipped)}, no account {len(missing)}")
for m in missing:
    print("  NO ACCOUNT", m)

# ── Admin summary ─────────────────────────────────────────────────────────
pushed = sum(1 for r in activated if r["push"])
emailed = sum(1 for r in activated if r["email"])
summary_title = f"✅ Cohort 4 ambassadors activated: {len(activated)} of {len(emails)}"
summary_body = (f"{len(activated)} activated ({pushed} push, {emailed} email). "
                f"{len(missing)} have no MyFund account yet. Details in your email.")
def summary_row(r):
    u = r["user"]
    name = html.escape(f"{u.first_name} {u.last_name}")
    push = "Yes" if r["push"] else ("No device" if not r["device"] else "Failed")
    mail = "Yes" if r["email"] else "Failed"
    return f"<tr><td>{name}</td><td>{html.escape(u.email)}</td><td>{push}</td><td>{mail}</td></tr>"


rows = "".join(summary_row(r) for r in activated)
missing_html = "".join(f"<li>{html.escape(m)}</li>" for m in missing)
admin_email = (
    f"<b>{len(activated)} of {len(emails)}</b> Cohort 4 ambassadors were activated "
    f"({pushed} got the push, {emailed} got the email).<br><br>"
    "<table cellpadding='6' style='border-collapse:collapse' border='1'>"
    "<tr><th>Name</th><th>Email</th><th>Push</th><th>Email</th></tr>" + rows + "</table><br>"
    f"<b>{len(missing)} have no MyFund account under these emails</b> (not activated - they need to sign up "
    "with this email, or tell us the email they used):<ul>" + missing_html + "</ul>"
    "Possible matches already on MyFund: aladesuru_adewale@yahoo.co.uk, abolupeisaiah@gmail.com, "
    "thomasesther545@gmail.com.<br><br>Lioness<br>MyFund"
)
print("\nADMIN PUSH:", summary_title, "|", summary_body)
if LIVE:
    for admin in CustomUser.objects.filter(email__in=ADMIN_EMAILS, is_active=True):
        try:
            send_push_notification(user=admin, title=summary_title, message=summary_body,
                                   notif_type="ADMIN", data={"type": "ADMIN_ALERT"})
        except Exception as e:
            print("  admin push failed", admin.email, e)
    send_generic_email(subject=summary_title, message=admin_email,
                       from_email="MyFund <info@myfundmobile.com>", recipient_list=ADMIN_EMAILS)
    print("Admin summary sent.")
