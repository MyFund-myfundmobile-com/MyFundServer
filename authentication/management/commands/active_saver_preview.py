"""Read-only look at the Active Saver story invites. Sends nothing.

    python manage.py active_saver_preview                 # who'd be invited on the 1st
    python manage.py active_saver_preview ada@example.com # 7-day preview link of their form
"""
from django.core.management.base import BaseCommand, CommandError

from authentication.active_saver_views import MAX_INVITES_PER_MONTH, MIN_STREAK, candidates, preview_link, previous_month
from authentication.models import CustomUser


class Command(BaseCommand):
    help = "List who the Active Saver invite would go to, or print a preview link (nothing is saved or sent)."

    def add_arguments(self, parser):
        parser.add_argument("emails", nargs="*")

    def handle(self, *args, emails, **options):
        for email in emails:
            user = CustomUser.objects.filter(email__iexact=email.strip()).first()
            if not user:
                raise CommandError(f"No MyFund account for {email}")
            self.stdout.write(f"{user.email}: {preview_link(user)}")
        if emails:
            return
        month, year = previous_month()
        picked = candidates(month, year)
        self.stdout.write(f"{len(picked)} would be invited for {month}/{year} "
                          f"({MIN_STREAK}+ months in a row, outside the Top 3, max {MAX_INVITES_PER_MONTH}):")
        for user, streak, rank in picked:
            self.stdout.write(f"  {streak:>2} months  #{rank:<5} {user.first_name} {user.last_name}  {user.email}")
