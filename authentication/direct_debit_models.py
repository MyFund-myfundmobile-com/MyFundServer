"""Bank-account mandates (Paystack Direct Debit) - AutoSave without a card.

A user links one of their saved bank accounts; Paystack creates a mandate
that the customer activates (usually a one-off N50 transfer to a NIBSS
account). Once Paystack says it's active, its authorization_code works just
like a card's: AutoSave subscribes it to a plan. See direct_debit.py.
"""
from django.conf import settings
from django.db import models


class BankMandate(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending activation"),
        ("active", "Active"),
        ("inactive", "Inactive"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bank_mandates"
    )
    bank_account = models.ForeignKey(
        "authentication.BankAccount", on_delete=models.SET_NULL, null=True, blank=True
    )
    bank_name = models.CharField(max_length=100)
    bank_code = models.CharField(max_length=10)
    account_number = models.CharField(max_length=20)
    account_name = models.CharField(max_length=100, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    # From Initialize Authorization; the webhook's authorization_code arrives later.
    reference = models.CharField(max_length=100, unique=True)
    paystack_mandate_id = models.CharField(max_length=50, blank=True)
    authorization_code = models.CharField(max_length=100, blank=True, db_index=True)

    # What the customer has to send to activate it (shown in the app).
    transfer_amount = models.CharField(max_length=20, blank=True)
    transfer_account_number = models.CharField(max_length=20, blank=True)
    transfer_account_name = models.CharField(max_length=100, blank=True)
    transfer_bank_name = models.CharField(max_length=100, blank=True)

    # The AutoSave the user asked for; started as soon as the mandate is active.
    pending_amount = models.PositiveIntegerField(null=True, blank=True)
    pending_frequency = models.CharField(max_length=10, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    activated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def label(self):
        """'OPay account •••• 4821' for messages."""
        return f"{self.bank_name} account •••• {self.account_number[-4:]}"

    def __str__(self):
        return f"{self.user} - {self.label} ({self.status})"
