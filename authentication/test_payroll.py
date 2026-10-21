from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from .models import CustomUser, Employee, PayrollEntry, Transaction
from .payroll import create_draft_entries, send_pending_entries


@patch("authentication.payroll.send_push_notification")
@patch("authentication.payroll.send_generic_email")
class PayrollDoublePayTest(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email="staff@example.com", password="x", first_name="S",
            last_name="T", phone_number="08000000000",
        )
        self.emp = Employee.objects.create(
            name="Staff", email="staff@example.com", monthly_amount=Decimal("10000.00")
        )

    def _credits(self):
        return Transaction.objects.filter(
            user=self.user, transaction_type="credit", description="October 2026 Allowance"
        ).count()

    def test_sending_live_twice_pays_once(self, *_):
        run = create_draft_entries(Employee.objects.all(), "October 2026")
        send_pending_entries(run.entries.all(), test=False)
        send_pending_entries(run.entries.all(), test=False)
        self.user.refresh_from_db()
        self.assertEqual(self._credits(), 1)
        self.assertEqual(self.user.wallet, Decimal("10000.00"))

    def test_repeat_pay_click_does_not_create_second_entry(self, *_):
        run1 = create_draft_entries(Employee.objects.all(), "October 2026")
        send_pending_entries(run1.entries.all(), test=False)
        run2 = create_draft_entries(Employee.objects.all(), "October 2026")
        self.assertEqual(run2.entries.count(), 0)
        self.assertEqual(self._credits(), 1)

    def test_test_send_does_not_credit(self, *_):
        run = create_draft_entries(Employee.objects.all(), "October 2026")
        send_pending_entries(run.entries.all(), test=True)
        self.user.refresh_from_db()
        self.assertEqual(self._credits(), 0)
        self.assertEqual(PayrollEntry.objects.get().status, "test_run")


@patch("authentication.payroll.send_transactional_email")
@patch("authentication.payroll.send_push_notification")
@patch("authentication.payroll.send_generic_email")
class AdminPayrollApiTest(TestCase):
    """Mobile admin payroll (Finance tab) - same behaviour as Django admin."""

    def setUp(self):
        from rest_framework.test import APIClient
        self.founder = CustomUser.objects.create_user(
            email="company@myfundmobile.com", password="x", phone_number="08000000001", is_staff=True)
        self.staff_user = CustomUser.objects.create_user(
            email="newstaff@example.com", password="x", first_name="New", phone_number="08000000002")
        self.client = APIClient()
        self.client.force_authenticate(self.founder)

    def test_only_founders_can_use_payroll(self, *_):
        from rest_framework.test import APIClient
        other = APIClient()
        other.force_authenticate(self.staff_user)
        for method, url in [("get", "/api/admin/payroll/employees"), ("get", "/api/admin/payroll/drafts"),
                            ("post", "/api/admin/payroll/drafts/pay")]:
            self.assertEqual(getattr(other, method)(url, {}, format="json").status_code, 403)

    def test_adding_employee_sends_welcome_like_django_admin(self, email, push, transactional):
        response = self.client.post("/api/admin/payroll/employees/create", {
            "name": "New Staff", "email": "NewStaff@example.com",
            "department": "Media and Communications", "monthly_amount": 25000}, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["has_account"])
        self.assertEqual(push.call_args.kwargs["title"], "🎉 Welcome to the MyFund Team!")
        transactional.assert_called_once()

    def test_pay_after_draft_pays_the_edited_draft(self, *_):
        emp = Employee.objects.create(name="New", email="newstaff@example.com", monthly_amount=Decimal("20000"))
        month = "October 2026"
        self.client.post("/api/admin/payroll/drafts/create", {"employee_ids": [emp.id], "month_label": month}, format="json")
        draft = self.client.get("/api/admin/payroll/drafts").json()["data"][0]
        self.client.patch(f"/api/admin/payroll/drafts/{draft['id']}", {"amount": "22500"}, format="json")
        response = self.client.post("/api/admin/payroll/pay", {"employee_ids": [emp.id], "month_label": month}, format="json")
        self.assertEqual(response.json()["paid_entries"], 1)
        self.staff_user.refresh_from_db()
        self.assertEqual(self.staff_user.wallet, Decimal("22500"))
        # Paying again pays nothing more.
        again = self.client.post("/api/admin/payroll/pay", {"employee_ids": [emp.id], "month_label": month}, format="json")
        self.assertEqual(again.json()["paid_entries"], 0)
        self.staff_user.refresh_from_db()
        self.assertEqual(self.staff_user.wallet, Decimal("22500"))

    def test_drafts_can_be_removed_or_paid_once(self, *_):
        emp = Employee.objects.create(name="New", email="newstaff@example.com", monthly_amount=Decimal("1000"))
        run = create_draft_entries(Employee.objects.filter(pk=emp.pk), "October 2026")
        entry = run.entries.get()
        self.assertEqual(self.client.patch(f"/api/admin/payroll/drafts/{entry.id}", {"amount": "0"}, format="json").status_code, 400)
        paid = self.client.post("/api/admin/payroll/drafts/pay", {"entry_ids": [entry.id]}, format="json")
        self.assertEqual(paid.json()["paid_entries"], 1)
        self.assertEqual(self.client.post("/api/admin/payroll/drafts/pay", {"entry_ids": [entry.id]}, format="json").status_code, 409)
        self.assertEqual(self.client.delete(f"/api/admin/payroll/drafts/{entry.id}").status_code, 404)
        other = create_draft_entries(Employee.objects.filter(pk=emp.pk), "November 2026").entries.get()
        self.assertEqual(self.client.delete(f"/api/admin/payroll/drafts/{other.id}").status_code, 204)
