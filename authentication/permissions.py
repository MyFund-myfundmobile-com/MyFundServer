# permissions.py
from rest_framework.permissions import BasePermission


class IsNotBannedUser(BasePermission):
    message = "Your account has been restricted."

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user and user.is_authenticated and user.is_active and not user.is_banned
        )
