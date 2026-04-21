from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication

from .ai_queries import get_business_snapshot
from .ai_prompts import build_chat_prompt
from .ai_service import AIService


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_ai_chat(request):
    question = request.data.get("question", "").strip()
    days = int(request.data.get("days", 30))

    if not question:
        return Response(
            {"error": "Question is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        snapshot = get_business_snapshot(days=days)
        prompt = build_chat_prompt(question, snapshot)

        ai = AIService(provider="gemini")
        answer = ai.query(prompt)

        return Response(
            {
                "question": question,
                "period_days": days,
                "answer": answer,
            },
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        return Response(
            {"error": f"AI chat failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
