"""Founder-only approval queue; reuse the same operations as Django admin."""
from django.contrib import admin
from decimal import Decimal
from django.contrib.admin.models import LogEntry, CHANGE
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Exists, OuterRef, Subquery, Q
from django.utils import timezone
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from .models import CustomUser, BankTransferRequest, InvestTransferRequest, WithdrawalsRequestToAdmin, Transaction
from .utils import approve_quicksave_credit, approve_quickinvest_credit, process_scheduled_withdrawal

REQUEST_APPROVERS = {"tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com"}


class CanApproveRequests(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(user.is_authenticated and user.is_active and user.is_staff and user.email.lower() in REQUEST_APPROVERS)


MODELS = {"quicksave": BankTransferRequest, "quickinvest": InvestTransferRequest, "kyc": CustomUser, "withdrawal": WithdrawalsRequestToAdmin}


def queue(kind):
    if kind == "kyc":
        return CustomUser.objects.filter(kyc_status="submitted").order_by("-updated_at", "-pk")
    qs = MODELS[kind].objects.select_related("user").filter(is_approved=False)
    if kind == "withdrawal":
        return qs.filter(is_processed=False, status="pending").order_by("-created_at", "-pk")
    # Abandoned/failed transfers must not remain actionable.
    pending = Transaction.objects.filter(status="pending", user_id=OuterRef("user_id"), transaction_id=OuterRef("transaction_id"))
    return qs.annotate(has_pending=Exists(pending)).filter(has_pending=True).order_by("-created_at", "-pk")


def resolved_queue(kind):
    if kind == "kyc":
        return CustomUser.objects.filter(kyc_status__in=["approved", "rejected"]).order_by("-date_joined")
    qs = MODELS[kind].objects.select_related("user")
    if kind == "withdrawal":
        return qs.filter(Q(is_approved=True) | Q(is_processed=True) | ~Q(status="pending")).order_by("-created_at")
    linked = Transaction.objects.filter(user_id=OuterRef("user_id"), transaction_id=OuterRef("transaction_id")).order_by("-pk")
    return qs.annotate(linked_status=Subquery(linked.values("status")[:1])).filter(Q(is_approved=True) | Q(linked_status__in=["confirmed", "abandoned", "failed", "cancelled"])).order_by("-created_at")


def serialize(obj, kind, request):
    user = obj if kind == "kyc" else obj.user
    def image(field):
        value = getattr(user, field, None)
        if not value:
            return None
        # Some historical uploads store an absolute ImageKit URL inside
        # an ImageField; storage.url otherwise prefixes it with /media/.
        name = str(value)
        if name.startswith(("https://", "http://")):
            return name
        return request.build_absolute_uri(value.url if hasattr(value, "url") else name)
    data = {"id": obj.pk, "kind": kind, "name": f"{user.first_name} {user.last_name}".strip(), "email": user.email, "phone": user.phone_number, "avatar": image("profile_picture"), "created_at": user.updated_at if kind == "kyc" else obj.created_at}
    if kind == "kyc":
        data.update(identification_type=user.identification_type, id_document=image("id_upload"), address=user.address, date_of_birth=user.date_of_birth, actions=["approve", "reject"])
    else:
        data.update(amount=str(obj.amount), transaction_id=obj.transaction_id, actions=["approve", "abandon"])
    if kind == "withdrawal":
        data.update(total_amount=str(obj.total_amount), charge_amount=str(obj.charge_amount), charge_percentage=str(obj.charge_percentage), source_account=obj.source_account, bank=obj.target_bank, account_number=obj.target_account_number, account_name=obj.target_account_name, withdrawal_type=obj.withdrawal_type, scheduled_date=obj.scheduled_processing_date, actions=["credit_wallet"] if obj.withdrawal_type == "scheduled" else ["confirm_paid"])
    if kind == "kyc":
        status = "pending" if user.kyc_status == "submitted" else user.kyc_status
    elif kind == "withdrawal":
        status = "completed" if obj.is_approved or obj.is_processed else obj.status
    elif obj.is_approved:
        status = "approved"
    else:
        linked = Transaction.objects.filter(user=user, transaction_id=obj.transaction_id).order_by("-pk").values_list("status", flat=True).first()
        status = "approved" if linked == "confirmed" else linked or "pending"
    data.update(status=status, status_label=status.replace("_", " ").title())
    if status != "pending":
        data["actions"] = []
    return data


@api_view(["GET"])
@permission_classes([CanApproveRequests])
def requests_list(request):
    kind = request.query_params.get("kind", "quicksave")
    if kind not in MODELS and kind != "all":
        raise ValidationError("Invalid request type.")
    try:
        offset = max(0, int(request.query_params.get("offset", 0)))
    except ValueError:
        raise ValidationError("Invalid offset.")
    scope = request.query_params.get("scope", "pending")
    if scope not in ["all", "pending", "resolved"]:
        raise ValidationError("Invalid request scope.")
    sort = request.query_params.get("sort", "newest")
    if sort not in ["newest", "oldest", "amount_high", "amount_low"]:
        raise ValidationError("Invalid request sort.")
    def ordered(qs, request_kind):
        date_field = "updated_at" if request_kind == "kyc" else "created_at"
        if sort.startswith("amount") and request_kind != "kyc":
            return qs.order_by("-amount" if sort == "amount_high" else "amount", "-" + date_field, "-pk")
        return qs.order_by(date_field if sort == "oldest" else "-" + date_field, "pk" if sort == "oldest" else "-pk")
    if kind == "all":
        results = []
        total = 0
        for request_kind, model in MODELS.items():
            if scope == "all":
                qs = model.objects.filter(Q(pk__in=queue(request_kind).values("pk")) | Q(pk__in=resolved_queue(request_kind).values("pk")))
            else:
                qs = resolved_queue(request_kind) if scope == "resolved" else queue(request_kind)
            total += qs.count()
            qs = ordered(qs, request_kind)
            if request_kind != "kyc":
                qs = qs.select_related("user")
            results.extend(serialize(obj, request_kind, request) for obj in qs[:offset + 20])
        results.sort(key=lambda item: (item["created_at"], item["kind"], item["id"]), reverse=sort != "oldest")
        if sort.startswith("amount"):
            # Stable sorting keeps newest first for equal amounts; KYC has no amount.
            results.sort(key=lambda item: (item["kind"] == "kyc", -Decimal(item.get("amount", "0")) if sort == "amount_high" else Decimal(item.get("amount", "0"))))
        return Response({"results": results[offset:offset + 20], "count": total, "counts": {key: queue(key).count() for key in MODELS}})
    qs = resolved_queue(kind) if scope == "resolved" else queue(kind)
    if scope == "all":
        # Include only actual submitted requests, not users without KYC submissions.
        pending_ids = queue(kind).values("pk")
        resolved_ids = resolved_queue(kind).values("pk")
        qs = MODELS[kind].objects.filter(Q(pk__in=pending_ids) | Q(pk__in=resolved_ids))
        qs = qs.order_by("-updated_at", "-pk") if kind == "kyc" else qs.select_related("user").order_by("-created_at", "-pk")
    if request.query_params.get("request_id"):
        qs = qs.filter(pk=request.query_params["request_id"])
    if request.query_params.get("transaction_id") and kind != "kyc":
        qs = qs.filter(transaction_id=request.query_params["transaction_id"])
    qs = ordered(qs, kind)
    return Response({"results": [serialize(obj, kind, request) for obj in qs[offset:offset + 20]], "count": qs.count(), "counts": {key: queue(key).count() for key in MODELS}})


class ActionMessages:
    """Collect ModelAdmin messages without requiring browser sessions."""
    def add(self, *args, **kwargs):
        pass

    def update(self, response):
        return []


@api_view(["POST"])
@permission_classes([CanApproveRequests])
def request_action(request, kind, pk):
    if kind not in MODELS:
        raise ValidationError("Invalid request type.")
    action = request.data.get("action")
    with transaction.atomic():
        obj = get_object_or_404(MODELS[kind].objects.select_for_update(), pk=pk)
        user = obj if kind == "kyc" else obj.user
        if kind == "kyc":
            if obj.kyc_status != "submitted":
                raise ValidationError("This KYC request has already been reviewed.")
            if action not in {"approve", "reject"}:
                raise ValidationError("Choose approve or reject.")
            reason = str(request.data.get("reason", "")).strip()
            if action == "reject" and not reason:
                raise ValidationError("Enter a rejection reason.")
            obj.kyc_rejection_reason = reason
            # Registered admin handler is the source of truth for status,
            # timestamps and user email/push notifications.
            admin.site._registry[CustomUser].process_kyc_transition(obj, "approved" if action == "approve" else "rejected")
        elif kind in {"quicksave", "quickinvest"}:
            if obj.is_approved:
                raise ValidationError("This transfer has already been approved.")
            if action == "approve":
                helper = approve_quicksave_credit if kind == "quicksave" else approve_quickinvest_credit
                ok, message = helper(user=user, amount=obj.amount, transaction_id=obj.transaction_id, source="BANK_TRANSFER")
                if not ok:
                    raise ValidationError(message)
                obj.is_approved = True
                obj.save(update_fields=["is_approved"])
            elif action == "abandon":
                tx = Transaction.objects.select_for_update().filter(user=user, transaction_id=obj.transaction_id, status="pending").first()
                if not tx:
                    raise ValidationError("No pending transaction remains.")
                tx.status = "abandoned"
                tx.save(update_fields=["status"])
            else:
                raise ValidationError("Invalid transfer action.")
        else:
            if obj.is_approved or obj.is_processed or obj.status != "pending":
                raise ValidationError("This withdrawal is no longer pending.")
            if action == "credit_wallet" and obj.withdrawal_type == "scheduled":
                if not obj.scheduled_processing_date or obj.scheduled_processing_date > timezone.localdate():
                    raise ValidationError("Scheduled withdrawal is not due yet.")
                result = process_scheduled_withdrawal(obj, triggered_by="mobile_admin")
                obj.refresh_from_db()
                if not obj.is_processed or obj.status != "completed":
                    raise ValidationError("Withdrawal could not be credited.")
            elif action == "confirm_paid" and obj.withdrawal_type == "immediate":
                if request.data.get("bank_payment_confirmed") is not True:
                    raise ValidationError("Confirm that the bank payout has already been made.")
                raw_request = request._request
                raw_request._messages = ActionMessages()
                admin.site._registry[WithdrawalsRequestToAdmin].approve_withdrawal(raw_request, WithdrawalsRequestToAdmin.objects.filter(pk=obj.pk))
                obj.refresh_from_db()
                if not obj.is_approved or obj.status != "completed":
                    raise ValidationError("Could not confirm this withdrawal. Review its transaction record.")
            else:
                raise ValidationError("Invalid withdrawal action.")
        LogEntry.objects.log_action(user_id=request.user.pk, content_type_id=ContentType.objects.get_for_model(obj).pk, object_id=str(obj.pk), object_repr=str(obj)[:200], action_flag=CHANGE, change_message=f"Mobile requests: {action}")
    return Response({"message": "Request addressed successfully."})
