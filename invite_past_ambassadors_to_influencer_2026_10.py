# invite_past_ambassadors_to_influencer_2026_10.py
#
# One-off: invites everyone who was ever a MyFund Ambassador - except the
# current Cohort 4 - to apply for the Influencer Programme
# (www.myfundmobile.com/influencer), by email and push.
#
#   python invite_past_ambassadors_to_influencer_2026_10.py --preview you@example.com
#       Sends the draft (email + push, if that address has an account) to
#       that one address only. Touches no one else.
#   python invite_past_ambassadors_to_influencer_2026_10.py --preview-push you@example.com
#       Just the draft push, to check that tapping it opens the page.
#   python invite_past_ambassadors_to_influencer_2026_10.py --count
#       Read-only: how many people would get it, and how many are excluded.
#   python invite_past_ambassadors_to_influencer_2026_10.py --send
#       Sends to the whole audience. Safe to re-run: addresses already sent
#       are logged to invite_influencer_2026_10_sent.txt and skipped.
#
# Audience: ever an ambassador (is_ambassador or any cohort assigned), minus
# Cohort 4, minus anyone already an influencer, deleted, banned or inactive.

import os
import sys

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myfundproject.settings")
django.setup()

from authentication.models import CustomUser
from authentication.utils import send_push_notification, send_transactional_email

APPLY_URL = "https://www.myfundmobile.com/influencer"
EXCLUDED_COHORT = 4
SENT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "invite_influencer_2026_10_sent.txt")

DEADLINE = "Friday, 7 November"
SUBJECT = "{first_name}, apply to become a MyFund Influencer by 7 November 🎬"

EMAIL = """
Hi {first_name},<br><br>
Thank you for everything you did as a <b>MyFund Ambassador</b>. You helped people around you start saving, and that matters.<br><br>
Now we'd love you to take the next step with us: the <b>MyFund Influencer Programme</b>. Here's what you get:<br><br>
&#9989; <b>&#8358;1,000 for every person</b> who signs up with your link and saves &#8358;10,000 or more. That's double the standard referral reward, paid straight into your MyFund wallet.<br>
&#9989; <b>Free MyFund merch</b>, sized for you.<br>
&#9989; <b>Your own Influencer Portal</b> to track your sign-ups, savers and earnings.<br>
&#9989; <b>Build your content creation career</b>: share your MyFund story your way and grow your reach while your audience builds real wealth.<br><br>
<b>Apply before {deadline}.</b> It takes about 10 minutes, and your draft saves as you go.<br><br>
<a href="{url}" style="display:inline-block;padding:13px 24px;border-radius:10px;background:#4C28BC;color:#ffffff;text-decoration:none;font-weight:bold">Apply to Become a MyFund Influencer</a><br><br>
We'd love to have you back on the team.<br><br>
&mdash; <b>MyFund</b>
"""

PUSH_TITLE = "Apply to Become a MyFund Influencer 🎬"
PUSH_MESSAGE = (
    "Hi {first_name}, earn ₦1,000 for every confirmed referral, get free merch and "
    "build your content creation career. Apply before 7 Nov. Tap to apply."
)


def audience():
    return (
        CustomUser.objects.ever_ambassador()
        .exclude(ambassador_cohort__cohort_number=EXCLUDED_COHORT)
        .filter(is_deleted=False, is_banned=False, is_active=True, is_influencer=False)
        .distinct()
        .order_by("pk")
    )


def send_one(email, first_name, user=None, subject_prefix=""):
    first_name = (first_name or "").strip() or "there"
    result = send_transactional_email(
        subject=subject_prefix + SUBJECT.format(first_name=first_name),
        message=EMAIL.format(first_name=first_name, url=APPLY_URL, deadline=DEADLINE),
        recipient_list=[email],
        from_email="MyFund <hello@myfundmobile.com>",
    )
    pushed = None
    if user:
        pushed = send_push_notification(
            user=user,
            title=PUSH_TITLE,
            message=PUSH_MESSAGE.format(first_name=first_name),
            # Tapping it opens the application page (NotificationDeepLink.js
            # opens deep_link.url in the browser).
            data={"type": "INFLUENCER_INVITE", "deep_link": {"url": APPLY_URL}},
            notif_type="SYSTEM",
        )
    return result, pushed


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--preview":
        email = sys.argv[2]
        user = CustomUser.objects.filter(email__iexact=email).first()
        result, pushed = send_one(email, user.first_name if user else "", user, subject_prefix="[DRAFT] ")
        print(f"Draft email to {email}: {result}")
        print(f"Draft push: {pushed if user else 'no account with that email, push skipped'}")
        return

    if len(sys.argv) >= 3 and sys.argv[1] == "--preview-push":
        user = CustomUser.objects.filter(email__iexact=sys.argv[2]).first()
        if not user:
            raise SystemExit("No account with that email.")
        print(send_push_notification(
            user=user, title="[DRAFT] " + PUSH_TITLE, message=PUSH_MESSAGE.format(first_name=user.first_name or "there"),
            data={"type": "INFLUENCER_INVITE", "deep_link": {"url": APPLY_URL}}, notif_type="SYSTEM"))
        return

    if sys.argv[1:] == ["--count"]:
        ever = CustomUser.objects.ever_ambassador().distinct()
        print(f"Ever an ambassador:            {ever.count()}")
        print(f"  in Cohort {EXCLUDED_COHORT} (excluded):    {ever.filter(ambassador_cohort__cohort_number=EXCLUDED_COHORT).count()}")
        print(f"  already influencers (excl.): {ever.filter(is_influencer=True).exclude(ambassador_cohort__cohort_number=EXCLUDED_COHORT).count()}")
        print(f"Will receive:                  {audience().count()}")
        return

    if sys.argv[1:] == ["--send"]:
        done = set()
        if os.path.exists(SENT_LOG):
            with open(SENT_LOG) as f:
                done = {line.strip().lower() for line in f if line.strip()}
        sent = skipped = failed = 0
        with open(SENT_LOG, "a") as log:
            for user in audience():
                if user.email.lower() in done:
                    skipped += 1
                    continue
                try:
                    result, _ = send_one(user.email, user.first_name, user)
                    if not result or not result.get("sent"):
                        raise RuntimeError(result)
                except Exception as exc:
                    failed += 1
                    print(f"FAILED {user.pk}: {exc}")
                    continue
                log.write(user.email.lower() + "\n")
                log.flush()
                sent += 1
        print(f"Sent {sent}, skipped (already sent) {skipped}, failed {failed}.")
        return

    raise SystemExit("Use --preview EMAIL, --count or --send.")


if __name__ == "__main__":
    main()
