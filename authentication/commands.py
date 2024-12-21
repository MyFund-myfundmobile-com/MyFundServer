# management/commands/send_birthday_emails.py
from django.core.management.base import BaseCommand
from django.utils.timezone import now
from django.core.mail import send_mail
from models import CustomUser


class Command(BaseCommand):
    help = "Send birthday emails to users"

    def handle(self, *args, **kwargs):
        today = now().date()
        birthday_users = CustomUser.objects.filter(
            date_of_birth__month=today.month, date_of_birth__day=today.day
        )

        for user in birthday_users:
            send_mail(
                subject="Happy Birthday!",
                message=f"Dear {user.first_name},\n\nHappy Birthday! 🎉\n\nBest regards,\nYour Team",
                from_email="your-email@example.com",
                recipient_list=[user.email],
            )
            self.stdout.write(f"Sent birthday email to {user.email}")
