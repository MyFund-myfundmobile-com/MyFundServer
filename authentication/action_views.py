# authentication/action_views.py
#
# New file — drop into authentication/ folder.
# Register in urls.py:
#
#   from .action_views import (
#       approve_bank_transfer_action,
#       approve_invest_transfer_action,
#       approve_withdrawal_action,
#   )
#   path("admin-action/approve-bank-transfer/",  approve_bank_transfer_action),
#   path("admin-action/approve-invest-transfer/", approve_invest_transfer_action),
#   path("admin-action/approve-withdrawal/",      approve_withdrawal_action),

import logging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)

ADMIN_BASE = "https://myfundapi-myfund-07ce351a.koyeb.app/admin"


def _require_staff(request):
    if not request.user.is_staff:
        return Response(
            {"error": "Admin access required."}, status=status.HTTP_403_FORBIDDEN
        )
    return None


# ── 1. Approve Bank Transfer ──────────────────────────────────────────────────


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def approve_bank_transfer_action(request):
    """
    POST { "transaction_id": "xxx" }
    Approves a pending BankTransferRequest. Mirrors BankTransferRequestAdmin.approve_bank_transfer.
    """
    err = _require_staff(request)
    if err:
        return err

    from .models import BankTransferRequest
    from .admin_helpers import approve_quicksave_credit

    transaction_id = request.data.get("transaction_id", "").strip()
    if not transaction_id:
        return Response({"error": "transaction_id is required."}, status=400)

    transfer = BankTransferRequest.objects.filter(
        transaction_id=transaction_id,
        is_approved=False,
    ).first()

    if not transfer:
        return Response(
            {"error": "No pending bank transfer found with that transaction_id."},
            status=404,
        )

    user = transfer.user
    ok, msg = approve_quicksave_credit(
        user=user,
        amount=transfer.amount,
        transaction_id=transaction_id,
        description="QuickSave (Transfer)",
        source="BANK_TRANSFER",
    )

    if not ok:
        logger.warning(f"[action] approve_bank_transfer failed for {user.email}: {msg}")
        return Response({"error": msg}, status=400)

    transfer.is_approved = True
    transfer.save(update_fields=["is_approved"])

    logger.info(
        f"[action] Bank transfer {transaction_id} approved by {request.user.email}"
    )
    return Response(
        {
            "message": f"Transfer of NGN {transfer.amount:,} approved for {user.full_name}.",
            "transaction_id": transaction_id,
            "user_email": user.email,
        }
    )


# ── 2. Approve Invest Transfer ────────────────────────────────────────────────


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def approve_invest_transfer_action(request):
    """
    POST { "transaction_id": "xxx" }
    Approves a pending InvestTransferRequest. Mirrors InvestTransferRequestAdmin.approve_invest_transfer.
    """
    err = _require_staff(request)
    if err:
        return err

    from .models import InvestTransferRequest
    from .admin_helpers import approve_quickinvest_credit

    transaction_id = request.data.get("transaction_id", "").strip()
    if not transaction_id:
        return Response({"error": "transaction_id is required."}, status=400)

    transfer = InvestTransferRequest.objects.filter(
        transaction_id=transaction_id,
        is_approved=False,
    ).first()

    if not transfer:
        return Response(
            {"error": "No pending invest transfer found with that transaction_id."},
            status=404,
        )

    user = transfer.user
    ok, msg = approve_quickinvest_credit(
        user=user,
        amount=transfer.amount,
        transaction_id=transaction_id,
        description="QuickInvest (Transfer)",
        source="BANK_TRANSFER",
    )

    if not ok:
        logger.warning(
            f"[action] approve_invest_transfer failed for {user.email}: {msg}"
        )
        return Response({"error": msg}, status=400)

    transfer.is_approved = True
    transfer.save(update_fields=["is_approved"])

    logger.info(
        f"[action] Invest transfer {transaction_id} approved by {request.user.email}"
    )
    return Response(
        {
            "message": f"Investment transfer of NGN {transfer.amount:,} approved for {user.full_name}.",
            "transaction_id": transaction_id,
            "user_email": user.email,
        }
    )


# ── 3. Approve Withdrawal ─────────────────────────────────────────────────────


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def approve_withdrawal_action(request):
    """
    POST { "withdrawal_id": "123" }
    Marks a WithdrawalsRequestToAdmin as approved and triggers Paystack payout.
    """
    err = _require_staff(request)
    if err:
        return err

    from .models import WithdrawalsRequestToAdmin, BankAccount
    from .utils import make_withdrawal_through_paystack

    withdrawal_id = request.data.get("withdrawal_id", "").strip()
    if not withdrawal_id:
        return Response({"error": "withdrawal_id is required."}, status=400)

    try:
        withdrawal = WithdrawalsRequestToAdmin.objects.select_related("user").get(
            id=withdrawal_id,
            is_approved=False,
        )
    except WithdrawalsRequestToAdmin.DoesNotExist:
        return Response(
            {"error": "No pending withdrawal found with that ID."},
            status=404,
        )

    user = withdrawal.user

    # Find the matching bank account for the target account number
    bank_account = BankAccount.objects.filter(
        account_number=withdrawal.target_account_number,
    ).first()

    if not bank_account:
        return Response(
            {
                "error": "Bank account not found locally. Please approve via Django Admin.",
                "admin_url": ADMIN_BASE
                + "/authentication/withdrawalsrequesttoadmin/?o=1.-12",
            },
            status=400,
        )

    # Attempt Paystack payout (same call as the original view)
    paystack_response = make_withdrawal_through_paystack(
        user,
        bank_account,
        withdrawal.amount,  # net amount after charges
        withdrawal.transaction_id,
    )

    if paystack_response.get("status"):
        withdrawal.is_approved = True
        withdrawal.save(update_fields=["is_approved"])

        logger.info(
            f"[action] Withdrawal {withdrawal_id} approved by {request.user.email}"
        )
        return Response(
            {
                "message": (
                    f"Withdrawal of NGN {withdrawal.amount:,} approved for {user.full_name}. "
                    f"Paystack payout initiated."
                ),
                "withdrawal_id": withdrawal_id,
                "user_email": user.email,
            }
        )
    else:
        logger.warning(
            f"[action] Paystack payout failed for withdrawal {withdrawal_id}: {paystack_response}"
        )
        return Response(
            {
                "error": "Paystack payout failed. Please retry via Django Admin.",
                "admin_url": ADMIN_BASE
                + "/authentication/withdrawalsrequesttoadmin/?o=1.-12",
                "paystack_message": paystack_response.get("message", ""),
            },
            status=400,
        )
