"""
In-app reader for the ambassador package books ("9 Steps to Financial
Freedom", "10 Laws of Academic Excellence").

The PDF ships with the server (authentication/books/), not MEDIA_ROOT, which
doesn't survive Koyeb redeploys - and not static/, which anyone could fetch.
The app asks for a short-lived signed link (the reader's WebView can't send
the JWT header) and reports reading progress, which admin can see.
"""
import hashlib
from functools import lru_cache
from pathlib import Path

from django.core import signing
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .book_models import BookReadingProgress
from .models import CustomUser

BOOKS = {
    "nine-steps": {
        "title": "9 Steps to Financial Freedom",
        "file": Path(__file__).resolve().parent / "books" / "nine-steps-to-financial-freedom.pdf",
    },
    "ten-laws": {
        "title": "10 Laws of Academic Excellence",
        "file": Path(__file__).resolve().parent / "books" / "ten-laws-of-academic-excellence.pdf",
    },
}
TOKEN_SALT = "book-reader"
TOKEN_MAX_AGE = 10 * 60


def can_read(user):
    # Current and past ambassadors (the books were in every cohort's package), plus staff.
    return bool(user.is_staff or user.is_ambassador or user.ambassador_cohort_id)


@lru_cache(maxsize=None)
def book_version(slug):
    # Changes when the PDF is replaced, so the app drops its cached copy.
    return hashlib.sha256(BOOKS[slug]["file"].read_bytes()).hexdigest()[:12]


def _book(slug):
    if slug not in BOOKS:
        raise Http404
    return BOOKS[slug]


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def book_access(request, slug):
    book = _book(slug)
    if not can_read(request.user):
        return Response({"detail": "This book is part of the ambassador package."}, status=403)
    token = signing.dumps({"u": request.user.pk, "b": slug}, salt=TOKEN_SALT)
    return Response({
        "title": book["title"],
        "version": book_version(slug),
        # Relative: the app joins it to its own API base (absolute URIs come
        # out as http:// behind Koyeb's proxy).
        "read_path": f"/api/books/{slug}/read/{token}/",
    })


@api_view(["GET"])
@permission_classes([AllowAny])
def book_read(request, slug, token):
    book = _book(slug)
    try:
        data = signing.loads(token, salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
    except signing.BadSignature:
        return HttpResponseForbidden("This reading link has expired. Open the book again from the app.")
    user = CustomUser.objects.filter(pk=data.get("u"), is_active=True).first()
    if data.get("b") != slug or not user or not can_read(user):
        return HttpResponseForbidden("You don't have access to this book.")
    response = FileResponse(book["file"].open("rb"), content_type="application/pdf")
    response["Content-Disposition"] = "inline"
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def book_progress(request, slug):
    _book(slug)
    if not can_read(request.user):
        return Response({"detail": "This book is part of the ambassador package."}, status=403)
    if request.method == "GET":
        progress = BookReadingProgress.objects.filter(user=request.user, book=slug).first()
        return Response({
            "last_page": progress.last_page if progress else 1,
            "max_page": progress.max_page if progress else 0,
            "total_pages": progress.total_pages if progress else 0,
            "completed": bool(progress and progress.completed_at),
        })
    try:
        last_page = int(request.data.get("last_page"))
        total_pages = int(request.data.get("total_pages"))
    except (TypeError, ValueError):
        return Response({"detail": "last_page and total_pages are required."}, status=400)
    if not 0 < last_page <= total_pages <= 5000:
        return Response({"detail": "Invalid page."}, status=400)
    progress, _ = BookReadingProgress.objects.get_or_create(user=request.user, book=slug)
    progress.last_page = last_page
    progress.total_pages = total_pages
    progress.max_page = max(progress.max_page, last_page)
    if progress.max_page >= total_pages and not progress.completed_at:
        progress.completed_at = timezone.now()
    progress.save()
    return Response({"last_page": progress.last_page, "max_page": progress.max_page,
                     "total_pages": progress.total_pages, "completed": bool(progress.completed_at)})
