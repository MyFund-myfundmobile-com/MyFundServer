from unittest.mock import patch

from django.contrib.admin.sites import AdminSite
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, TestCase

from authentication.admin import EmployeeAdmin
from authentication.models import CustomUser, Employee


@patch("authentication.payroll.send_transactional_email")
@patch("authentication.payroll.send_push_notification")
class DeactivateEmployeeActionTests(TestCase):
    """The admin 'Set as INACTIVE' action takes employees off payroll and
    tells each one by email + push, inviting them to reach out if it's an error."""

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email="mykel@example.com", password="x", first_name="Michael", last_name="O", phone_number="08039000001")
        self.employee = Employee.objects.create(
            name="Michael O", email="mykel@example.com", monthly_amount=15000, department="Tech", is_active=True)
        request = RequestFactory().post("/")
        request.user = CustomUser(is_staff=True, is_superuser=True)
        setattr(request, "session", {})
        setattr(request, "_messages", FallbackStorage(request))
        self.request = request
        self.admin = EmployeeAdmin(Employee, AdminSite())

    def test_sets_inactive_and_notifies_with_error_contact(self, push, email):
        self.admin.deactivate_and_notify(self.request, Employee.objects.all())
        self.employee.refresh_from_db()
        self.assertFalse(self.employee.is_active)
        self.assertEqual(push.call_args.kwargs["user"], self.user)
        self.assertIn("error", push.call_args.kwargs["message"])
        self.assertEqual(email.call_args.kwargs["recipient_list"], ["mykel@example.com"])
        self.assertIn("If you believe this is an error", email.call_args.kwargs["message"])

    def test_already_inactive_is_left_alone(self, push, email):
        Employee.objects.update(is_active=False)
        self.admin.deactivate_and_notify(self.request, Employee.objects.all())
        push.assert_not_called()
        email.assert_not_called()
