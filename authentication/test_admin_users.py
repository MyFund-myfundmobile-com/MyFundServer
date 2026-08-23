"""
Tests for the Admin Users Management endpoints (authentication/admin_views.py:
all_users_list, admin_user_detail, update_user_status).
"""

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from .models import CustomUser


def _make_user(email, phone, **extra):
    extra.setdefault("first_name", "Test")
    extra.setdefault("last_name", "User")
    return CustomUser.objects.create_user(
        email=email,
        password="testpass123",
        phone_number=phone,
        **extra,
    )


class AdminUsersPermissionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.regular_user = _make_user("regular2@example.com", "90000000001")
        self.target_user = _make_user("target1@example.com", "90000000002")

    def test_non_staff_rejected(self):
        self.client.force_authenticate(user=self.regular_user)

        response = self.client.get(reverse("admin_all_users_list"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.get(
            reverse("admin_user_detail", args=[self.target_user.id])
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.post(
            reverse("admin_update_user_status", args=[self.target_user.id]),
            {"field": "is_ambassador", "value": True},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class AdminUsersListTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff10@example.com", "91000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

        _make_user(
            "jane.ambassador@example.com",
            "91000000002",
            first_name="Jane",
            last_name="Ambassador",
            is_ambassador=True,
        )
        _make_user(
            "john.banned@example.com",
            "91000000003",
            first_name="John",
            last_name="Banned",
            is_banned=True,
            is_active=False,
        )
        _make_user(
            "kyc.approved@example.com",
            "91000000004",
            first_name="Kyc",
            last_name="Approved",
            kyc_status="approved",
        )
        # A soft-deleted user must never appear in the list.
        _make_user(
            "deleted.user@example.com", "91000000005", is_deleted=True
        )

    def test_search_matches_name_email_phone(self):
        response = self.client.get(reverse("admin_all_users_list"), {"search": "Jane"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        emails = [u["email"] for u in response.data["data"]]
        self.assertIn("jane.ambassador@example.com", emails)
        self.assertEqual(response.data["total_count"], 1)

        response = self.client.get(
            reverse("admin_all_users_list"), {"search": "91000000003"}
        )
        emails = [u["email"] for u in response.data["data"]]
        self.assertEqual(emails, ["john.banned@example.com"])

    def test_boolean_filters(self):
        response = self.client.get(
            reverse("admin_all_users_list"), {"is_ambassador": "true"}
        )
        emails = [u["email"] for u in response.data["data"]]
        self.assertEqual(emails, ["jane.ambassador@example.com"])
        self.assertEqual(response.data["filters_applied"]["is_ambassador"], True)

        response = self.client.get(
            reverse("admin_all_users_list"), {"is_banned": "true"}
        )
        emails = [u["email"] for u in response.data["data"]]
        self.assertEqual(emails, ["john.banned@example.com"])

    def test_kyc_status_filter(self):
        response = self.client.get(
            reverse("admin_all_users_list"), {"kyc_status": "approved"}
        )
        emails = [u["email"] for u in response.data["data"]]
        self.assertEqual(emails, ["kyc.approved@example.com"])

    def test_soft_deleted_users_excluded(self):
        response = self.client.get(reverse("admin_all_users_list"), {"limit": 200})
        emails = [u["email"] for u in response.data["data"]]
        self.assertNotIn("deleted.user@example.com", emails)

    def test_pagination(self):
        response = self.client.get(
            reverse("admin_all_users_list"), {"page": 1, "limit": 2}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)
        self.assertEqual(response.data["limit"], 2)
        # staff + jane + john + kyc = 4 (the is_deleted=True user is
        # correctly excluded from the count too, not just the page).
        self.assertEqual(response.data["total_count"], 4)
        self.assertEqual(response.data["total_pages"], 2)

    def test_invalid_page_and_limit_dont_500(self):
        response = self.client.get(
            reverse("admin_all_users_list"), {"page": "not-a-number", "limit": "9999"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["page"], 1)  # falls back to default
        self.assertEqual(response.data["limit"], 200)  # clamped to the max

    def test_admin_only_fields_present(self):
        response = self.client.get(
            reverse("admin_all_users_list"), {"search": "John"}
        )
        user_data = response.data["data"][0]
        # These are deliberately absent from the base UserSerializer used
        # by self-profile endpoints - confirm the admin variant adds them.
        for field in ("is_banned", "is_active", "is_staff", "is_deleted"):
            self.assertIn(field, user_data)
        self.assertTrue(user_data["is_banned"])
        self.assertFalse(user_data["is_active"])


class AdminUserDetailTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff11@example.com", "92000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.user = _make_user(
            "detailuser@example.com", "92000000002", first_name="Detail"
        )

    def test_get_existing_user(self):
        response = self.client.get(reverse("admin_user_detail", args=[self.user.id]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "detailuser@example.com")
        self.assertIn("is_banned", response.data)

    def test_get_nonexistent_user(self):
        response = self.client.get(reverse("admin_user_detail", args=[999999]))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class UpdateUserStatusTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff12@example.com", "93000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.user = _make_user("statususer@example.com", "93000000002")

    def _post(self, field, value, user_id=None):
        return self.client.post(
            reverse("admin_update_user_status", args=[user_id or self.user.id]),
            {"field": field, "value": value},
            format="json",
        )

    @patch("authentication.utils.send_ambassador_status_notification")
    def test_grant_and_revoke_ambassador(self, mock_notify):
        self.assertFalse(self.user.is_ambassador)

        response = self._post("is_ambassador", True)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["value"], True)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_ambassador)

        response = self._post("is_ambassador", False)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["value"], False)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_ambassador)

    def test_ban_also_deactivates(self):
        response = self._post("is_banned", True)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_banned)
        self.assertFalse(self.user.is_active)

    def test_unban_does_not_force_reactivate(self):
        self._post("is_banned", True)
        response = self._post("is_banned", False)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_banned)
        # Matches CustomUserAdmin.unban_user's exact behavior - it only
        # clears is_banned, it doesn't also flip is_active back on.
        self.assertFalse(self.user.is_active)

    def test_unsupported_field_rejected(self):
        response = self._post("is_superuser", True)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_superuser)

    def test_non_boolean_value_rejected(self):
        response = self._post("is_ambassador", "yes")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_nonexistent_user_404(self):
        response = self._post("is_ambassador", True, user_id=999999)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AdminUserEmailsForSegmentTest(TestCase):
    """
    GET /api/admin/users/emails/ - backs the mobile Email tab's recipient
    picker. Reuses the same filter helper as all_users_list, so this only
    needs to check the parts that differ: count_only mode, the emails
    list, and users with no email being excluded.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = _make_user("staff20@example.com", "94000000001", is_staff=True)
        self.client.force_authenticate(user=self.staff)

        _make_user(
            "amb.segment@example.com",
            "94000000002",
            is_ambassador=True,
        )
        _make_user("plain.segment@example.com", "94000000003")

    def test_non_staff_rejected(self):
        regular = _make_user("regular20@example.com", "94000000004")
        self.client.force_authenticate(user=regular)
        response = self.client.get(reverse("admin_user_emails_for_segment"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_count_only_returns_no_email_list(self):
        response = self.client.get(
            reverse("admin_user_emails_for_segment"),
            {"is_ambassador": "true", "count_only": "true"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertNotIn("emails", response.data)

    def test_full_list_returns_matching_emails(self):
        response = self.client.get(reverse("admin_user_emails_for_segment"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # staff + ambassador + plain = 3
        self.assertEqual(response.data["count"], 3)
        self.assertIn("amb.segment@example.com", response.data["emails"])
        self.assertIn("plain.segment@example.com", response.data["emails"])
        self.assertFalse(response.data["truncated"])

    def test_users_without_email_excluded(self):
        # CustomUser.email is unique/required in practice, but guard the
        # endpoint itself against a blank email slipping into a send.
        blank_email_user = _make_user("placeholder1@example.com", "94000000005")
        blank_email_user.email = ""
        blank_email_user.save(update_fields=["email"])

        response = self.client.get(reverse("admin_user_emails_for_segment"))
        self.assertNotIn("", response.data["emails"])
