"""Send the Active Saver story form now, by hand (email + push).

    python manage.py active_saver_invite ada@example.com bola@example.com

Anyone with a MyFund account can be invited this way - no streak needed.
Someone already invited this month gets the same form link again.
"""
from django.core.management.base import BaseCommand, CommandError

from authentication.active_saver_views import interview_link, invite_now
from authentication.models import CustomUser


class Command(BaseCommand):
    help = "Email + push the Active Saver story form to these MyFund accounts now."

    def add_arguments(self, parser):
        parser.add_argument("emails", nargs="+")

    def handle(self, *args, emails, **options):
        users = []
        for email in emails:
            user = CustomUser.objects.filter(email__iexact=email.strip(), is_deleted=False).first()
            if not user:
                raise CommandError(f"No MyFund account for {email} - nothing was sent.")
            users.append(user)
        for user in users:
            interview = invite_now(user)
            self.stdout.write(f"Sent to {user.email} ({interview.streak_months} months in a row): {interview_link(interview)}")
