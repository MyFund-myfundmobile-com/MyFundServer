from unittest.mock import patch
from django.test import TestCase
from rest_framework.test import APIClient
from .models import CustomUser, Employee, CxWeeklyReport

class EngagementReportsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.member = CustomUser.objects.create_user(email='engagement@example.com',phone_number='09000111001',password='test',is_staff=True)
        self.other = CustomUser.objects.create_user(email='other@example.com',phone_number='09000111002',password='test',is_staff=True)
        self.founder = CustomUser.objects.create_user(email='tolulopeahmed@gmail.com',phone_number='09000111003',password='test',is_staff=True)
        Employee.objects.create(name='Member',email=self.member.email,department='Engagement',monthly_amount=0)
    def login(self,user): self.client.force_authenticate(user)
    @patch('authentication.admin_views.send_admin_push_notification')
    def test_submit_and_read_only_own_department_reports(self,notify):
        self.login(self.member)
        response=self.client.post('/api/admin/engagement/weekly-reports/create/',{'report':'Community event: 12 signups','recommendation':'Follow up deposits','week_start':'2026-09-28'},format='json')
        self.assertEqual(response.status_code,201,response.data)
        self.assertEqual(response.data['department'],'Engagement')
        CxWeeklyReport.objects.create(submitted_by=self.other,department='Engagement',report='Other')
        CxWeeklyReport.objects.create(submitted_by=self.member,department='CX',report='Old CX')
        mine=self.client.get('/api/admin/engagement/weekly-reports/mine/')
        self.assertEqual(len(mine.data),1)
        self.assertEqual(self.client.get('/api/admin/engagement/weekly-reports/').status_code,403)
        self.login(self.founder)
        self.assertEqual(len(self.client.get('/api/admin/engagement/weekly-reports/').data),2)
        self.assertEqual(len(self.client.get('/api/admin/cx/weekly-reports/').data),1)
        notify.assert_called_once()
    def test_nonmember_inactive_employee_and_nonstaff_denied(self):
        self.login(self.other)
        self.assertEqual(self.client.post('/api/admin/engagement/weekly-reports/create/',{'report':'x'}).status_code,403)
        Employee.objects.filter(email=self.member.email).update(is_active=False)
        self.login(self.member)
        self.assertEqual(self.client.post('/api/admin/engagement/weekly-reports/create/',{'report':'x'}).status_code,403)
        self.member.is_staff=False;self.member.save()
        self.assertEqual(self.client.get('/api/admin/engagement/weekly-reports/mine/').status_code,403)
    @patch('authentication.admin_views.send_admin_push_notification')
    def test_validation_and_cx_backwards_compatibility(self,notify):
        self.login(self.member)
        self.assertEqual(self.client.post('/api/admin/engagement/weekly-reports/create/',{'report':' '}).status_code,400)
        self.assertEqual(self.client.post('/api/admin/engagement/weekly-reports/create/',{'report':'x','week_start':'bad'}).status_code,400)
        self.login(self.other)
        r=self.client.post('/api/admin/cx/weekly-reports/create/',{'report':'CX report'})
        self.assertEqual(r.status_code,201)
        self.assertEqual(r.data['department'],'CX')
