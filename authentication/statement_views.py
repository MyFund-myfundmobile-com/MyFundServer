from django.db.models import F
from django.http import HttpResponse
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from .savings_statement import ALLOWED_MONTHS, build_statement, issue_statement, public_summary, render_pdf
from .statement_models import SavingsStatement


class StatementIssueThrottle(UserRateThrottle):
    rate = "20/hour"


class StatementPreviewThrottle(UserRateThrottle):
    rate = "120/hour"


class StatementVerifyThrottle(AnonRateThrottle):
    rate = "60/hour"


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@throttle_classes([StatementIssueThrottle])
def download_savings_statement(request):
    """GET /api/savings-statement/?months=3|6|12 -> PDF. Each download is a
    new statement with its own verification code."""
    try:
        months = int(request.GET.get("months", 6))
    except ValueError:
        months = 0
    if months not in ALLOWED_MONTHS:
        return Response({"error": "months must be 3, 6 or 12"}, status=400)
    statement, data = issue_statement(request.user, months)
    pdf = render_pdf(data)
    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="MyFund-Statement-{statement.code}.pdf"'
    return response


def _months(request):
    try:
        months = int(request.GET.get("months", 6))
    except ValueError:
        return None
    return months if months in ALLOWED_MONTHS else None


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@throttle_classes([StatementPreviewThrottle])
def preview_savings_statement(request):
    """GET /api/savings-statement/preview/?months=3|6|12 -> what the PDF
    will say, for the in-app preview. Issues nothing: no code, no record."""
    months = _months(request)
    if not months:
        return Response({"error": "months must be 3, 6 or 12"}, status=400)
    data = build_statement(request.user, months)
    keep = ("name", "period_label", "months", "member_since", "kyc_verified", "balances", "totals", "record",
            "stage", "tenure", "top_saver_times", "discipline", "highlights", "monthly")
    return Response({**{k: data[k] for k in keep}, "transaction_count": len(data["transactions"])})


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([StatementVerifyThrottle])
def verify_savings_statement(request, code):
    """Public: the figures MyFund issued for a statement code."""
    statement = SavingsStatement.objects.filter(code__iexact=code.strip()).first()
    if not statement:
        return Response({"valid": False, "error": "No statement with this number was issued by MyFund."}, status=404)
    SavingsStatement.objects.filter(pk=statement.pk).update(
        verify_count=F("verify_count") + 1, last_verified_at=timezone.now())
    return Response(public_summary(statement))
