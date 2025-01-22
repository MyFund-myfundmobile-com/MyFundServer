from django.contrib.auth.backends import ModelBackend
from .models import CustomUser, UserPassword
from django.contrib.auth.hashers import check_password


class CustomUserAuthBackend(ModelBackend):
    """
    Custom authentication backend that uses UserPassword model for authentication.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            # Get the user by email
            user = CustomUser.objects.get(email=username)

            # Find the corresponding UserPassword record for the user
            user_password = UserPassword.objects.filter(user=user).first()

            if user_password and check_password(password, user_password.password):
                return user

        except CustomUser.DoesNotExist:
            return None

        return None

    def get_user(self, user_id):
        try:
            return CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None


class CustomUserAdminAuthBackend(ModelBackend):
    """
    Custom authentication backend for admin users that verifies passwords
    from the UserPassword model directly.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(email=username)

            if not user.is_staff:
                return None

            # Find the corresponding UserPassword record for the user
            user_password = UserPassword.objects.filter(user=user).first()

            if user_password and check_password(password, user_password.password):
                return user

        except CustomUser.DoesNotExist:
            return None

        return None

    def get_user(self, user_id):
        try:
            return CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None
