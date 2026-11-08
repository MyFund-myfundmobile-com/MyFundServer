import secrets

from django.conf import settings
from django.db import models

# No 0/O/1/I/L, so a code read out over the phone or typed in from paper
# can't be misread. 10 characters ≈ 50 bits: not guessable.
CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"


def new_statement_code():
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(10))
    return f"MFS-{raw[:5]}-{raw[5:]}"


class SavingsStatement(models.Model):
    """One issued savings statement. The PDF is regenerated on demand, but
    the figures printed on it are frozen here, so a lender or landlord can
    check a copy they were handed against what MyFund actually issued
    (www.myfundmobile.com/verify/<code>)."""

    code = models.CharField(max_length=20, unique=True, default=new_statement_code)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="savings_statements")
    months = models.PositiveSmallIntegerField()
    period_start = models.DateField()
    period_end = models.DateField()
    # Name, balances, period totals, WealthMap stage, saving record - exactly
    # what the PDF shows in its summary, as issued.
    summary = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    verify_count = models.PositiveIntegerField(default=0)
    last_verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.code} - {self.user_id} ({self.months} months)"
