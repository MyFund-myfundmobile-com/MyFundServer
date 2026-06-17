# authentication/action_views.py
#
# Two lightweight API endpoints that the mobile app can call when an admin
# taps a deep-linked push notification and confirms an action.
#
# Both require:  Authorization: Bearer <token>  +  is_staff=True
#
# Add to urls.py:
#   from .action_views import approve_bank_transfer_action, approve_withdrawal_action
#   path("admin-action/approve-bank-transfer/", approve_bank_transfer_action),
#   path("admin-action/approve-withdrawal/",    approve_withdrawal_action),

import logging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import CustomUser, Transaction

# from .admin_helpers import (
#     approve_quicksave_credit,
# )  # already used in BankTransferRequestAdmin

logger = logging.getLogger(__name__)


def _require_staff(request):
    """Return an error Response if the caller is not staff, else None."""
    if not request.user.is_staff:
        return Response(
            {"error": "Admin access required."},
            status=status.HTTP_403_FORBIDDEN,
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. Approve Bank Transfer
# ─────────────────────────────────────────────────────────────────────────────


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def approve_bank_transfer_action(request):
    """
    Approve a pending BankTransferRequest by transaction_id.

    POST body:
        { "transaction_id": "xxx" }
    """
    err = _require_staff(request)
    if err:
        return err

    from .models import BankTransferRequest  # local import to avoid circular

    transaction_id = request.data.get("transaction_id", "").strip()
    if not transaction_id:
        return Response(
            {"error": "transaction_id is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    transfer_request = BankTransferRequest.objects.filter(
        transaction_id=transaction_id,
        is_approved=False,
    ).first()

    if not transfer_request:
        return Response(
            {"error": "No pending transfer found with that transaction_id."},
            status=status.HTTP_404_NOT_FOUND,
        )

    user = transfer_request.user

    ok, msg = approve_quicksave_credit(
        user=user,
        amount=transfer_request.amount,
        transaction_id=transaction_id,
        description="QuickSave (Transfer)",
        source="BANK_TRANSFER",
    )

    if not ok:
        logger.warning(
            f"[action_view] approve_bank_transfer failed for {user.email}: {msg}"
        )
        return Response(
            {"error": msg},
            status=status.HTTP_400_BAD_REQUEST,
        )

    transfer_request.is_approved = True
    transfer_request.save(update_fields=["is_approved"])

    logger.info(
        f"[action_view] Bank transfer {transaction_id} approved by {request.user.email}"
    )

    return Response(
        {
            "message": f"✅ Transfer of ₦{transfer_request.amount:,} approved for {user.full_name}.",
            "transaction_id": transaction_id,
            "user_email": user.email,
        },
        status=status.HTTP_200_OK,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Approve Withdrawal
# ─────────────────────────────────────────────────────────────────────────────


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def approve_withdrawal_action(request):
    """
    Approve a pending withdrawal request by withdrawal_id.

    POST body:
        { "withdrawal_id": 123 }

    Mirrors whatever approval logic your WithdrawalsRequestToAdmin admin action uses.
    Adjust the import + function call below to match your actual withdrawal model.
    """
    err = _require_staff(request)
    if err:
        return err

    withdrawal_id = request.data.get("withdrawal_id")
    if not withdrawal_id:
        return Response(
            {"error": "withdrawal_id is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # ── Import your actual withdrawal model here ──────────────────────────
    # Adjust the model name to match whatever model backs
    # /admin/authentication/withdrawalsrequesttoadmin/
    try:
        from .models import WithdrawalsRequestToAdmin  # adjust if named differently
    except ImportError:
        logger.error(
            "[action_view] WithdrawalsRequestToAdmin model not found — update the import in action_views.py"
        )
        return Response(
            {
                "error": "Withdrawal model not configured. Please approve via Django Admin."
            },
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    withdrawal = WithdrawalsRequestToAdmin.objects.filter(
        id=withdrawal_id,
        is_approved=False,
    ).first()

    if not withdrawal:
        return Response(
            {"error": "No pending withdrawal found with that ID."},
            status=status.HTTP_404_NOT_FOUND,
        )

    user = withdrawal.user

    # ── Call your existing approval helper / logic here ───────────────────
    # Replace the block below with the actual approval call from your admin action.
    # Example:
    #   ok, msg = approve_withdrawal_transfer(user=user, withdrawal=withdrawal)
    #
    # For now we do a safe no-op and return a redirect-to-admin message:
    logger.info(
        f"[action_view] Withdrawal {withdrawal_id} approval requested by {request.user.email}"
    )

    # TODO: wire in your real approval helper (same as the Django admin action)
    return Response(
        {
            "message": "⚠️ Automatic approval not yet wired. Please complete in Django Admin.",
            "admin_url": "https://myfundapi-myfund-07ce351a.koyeb.app/admin/authentication/withdrawalsrequesttoadmin/?o=1.-12",
        },
        status=status.HTTP_200_OK,
    )
