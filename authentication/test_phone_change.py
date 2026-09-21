from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase, SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from authentication.models import CustomUser, PhoneChangeRequest
from authentication.utils import send_sms_via_payless


class PhoneChangeFlowTests(TestCase):
    def setUp(self):
        self.owner = CustomUser.objects.create_user(email="phone-owner@example.com", password="test", phone_number="2348033952556")
        self.other = CustomUser.objects.create_user(email="phone-other@example.com", password="test", phone_number="2348033952557")
        self.admin = CustomUser.objects.create_user(email="tolulopeahmed@gmail.com", password="test", phone_number="2348033952558", is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(self.owner)
        self.sms = patch("authentication.services.phone_change.send_sms_via_payless", return_value=True).start()
        self.push = patch("authentication.services.phone_change.send_push_notification").start()
        self.addCleanup(patch.stopall)

    def start(self):
        return self.client.post('/api/request-phone-change/', {'new_phone': '08033952559'}, format='json')

    def verify(self, req, **kwargs):
        return self.client.post('/api/verify-phone-change/', {'request_id': req.pk, 'old_otp': req.old_phone_otp, 'new_otp': req.new_phone_otp, **kwargs}, format='json')

    def test_full_flow_and_repeat_approval(self):
        response = self.start()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.sms.call_count, 2)
        req = PhoneChangeRequest.objects.get(pk=response.data['request_id'])
        self.assertEqual(self.verify(req).status_code, 200)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.phone_number, req.old_phone)
        self.client.force_authenticate(self.admin)
        listing = self.client.get('/api/admin/requests/', {'kind': 'phone_change', 'scope': 'pending'})
        self.assertEqual(listing.status_code, 200, listing.data)
        self.assertEqual(listing.data['count'], 1)
        self.assertEqual(listing.data['results'][0]['new_phone'], req.new_phone)
        self.assertNotIn('old_phone_otp', listing.data['results'][0])
        for sort in ['newest', 'oldest', 'amount_high', 'amount_low']:
            self.assertEqual(self.client.get('/api/admin/requests/', {'kind': 'all', 'sort': sort}).status_code, 200)
        url = f'/api/admin/requests/phone_change/{req.pk}/action/'
        with self.captureOnCommitCallbacks(execute=True):
            result = self.client.post(url, {'action': 'approve'}, format='json')
        self.assertEqual(result.status_code, 200, result.data)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.phone_number, req.new_phone)
        self.push.assert_called_once()
        self.assertEqual(self.client.post(url, {'action': 'approve'}).status_code, 400)
        self.assertEqual(self.client.get('/api/admin/requests/', {'kind': 'phone_change'}).data['count'], 0)

    def test_sms_failure_is_not_success(self):
        self.sms.return_value = False
        self.assertEqual(self.start().status_code, 502)
        req = PhoneChangeRequest.objects.get(user=self.owner)
        self.assertEqual(req.status, 'rejected')
        self.assertIsNone(req.old_phone_otp)

    def test_partial_sms_failure(self):
        self.sms.side_effect = [True, False]
        self.assertEqual(self.start().status_code, 502)
        self.assertEqual(PhoneChangeRequest.objects.get(user=self.owner).status, 'rejected')

    def test_changed_or_taken_number_blocks_approval(self):
        self.start()
        req = PhoneChangeRequest.objects.get(user=self.owner)
        self.verify(req)
        self.client.force_authenticate(self.admin)
        url = f'/api/admin/requests/phone_change/{req.pk}/action/'
        CustomUser.objects.filter(pk=self.other.pk).update(phone_number='08033952559')
        self.assertEqual(self.client.post(url, {'action': 'approve'}).status_code, 400)
        CustomUser.objects.filter(pk=self.other.pk).update(phone_number='2348033952557')
        CustomUser.objects.filter(pk=self.owner.pk).update(phone_number='2348033952560')
        self.assertEqual(self.client.post(url, {'action': 'approve'}).status_code, 400)

    def test_pending_approval_blocks_new_request(self):
        self.start()
        req = PhoneChangeRequest.objects.get(user=self.owner)
        self.verify(req)
        PhoneChangeRequest.objects.filter(pk=req.pk).update(created_at=timezone.now()-timedelta(minutes=2))
        self.assertEqual(self.start().status_code, 400)
        self.assertEqual(self.sms.call_count, 2)

    def test_other_user_cannot_verify_or_approve(self):
        self.start()
        req = PhoneChangeRequest.objects.get(user=self.owner)
        self.client.force_authenticate(self.other)
        self.assertEqual(self.verify(req).status_code, 400)
        self.assertEqual(self.client.post('/api/approve-phone-change/', {'request_id': req.pk}).status_code, 403)
        self.assertEqual(self.client.post(f'/api/admin/requests/phone_change/{req.pk}/action/', {'action': 'approve'}).status_code, 403)

    def test_expired_and_attempt_limited_codes(self):
        self.start()
        req = PhoneChangeRequest.objects.get(user=self.owner)
        for _ in range(5):
            self.assertEqual(self.verify(req, old_otp='wrong').status_code, 400)
        req.refresh_from_db()
        self.assertEqual(req.otp_attempts, 5)
        self.assertEqual(req.status, 'rejected')
        PhoneChangeRequest.objects.filter(pk=req.pk).update(status='pending', otp_attempts=0, created_at=timezone.now()-timedelta(minutes=11))
        self.assertEqual(self.verify(req).status_code, 400)

    def test_validation_and_rate_limit(self):
        for number in ['bad', '08033952556', self.other.phone_number]:
            self.assertEqual(self.client.post('/api/request-phone-change/', {'new_phone': number}).status_code, 400)
        self.assertEqual(self.start().status_code, 200)
        self.assertEqual(self.start().status_code, 400)
        self.assertEqual(self.sms.call_count, 2)

    def test_unverified_not_approvable_and_rejection(self):
        self.start()
        req = PhoneChangeRequest.objects.get(user=self.owner)
        self.client.force_authenticate(self.admin)
        url = f'/api/admin/requests/phone_change/{req.pk}/action/'
        self.assertEqual(self.client.post(url, {'action': 'approve'}).status_code, 400)
        self.client.force_authenticate(self.owner)
        self.verify(req)
        self.client.force_authenticate(self.admin)
        self.assertEqual(self.client.post(url, {'action': 'reject'}).status_code, 400)
        self.assertEqual(self.client.post(url, {'action': 'reject', 'reason': 'Please contact support'}).status_code, 200)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.phone_number, req.old_phone)


class PaylessAdapterTests(SimpleTestCase):
    @override_settings(PAYLESS_SMS_API_TOKEN='test-token', PAYLESS_SMS_SEND_URL='https://sms.example.test/send', PAYLESS_SMS_SENDER_ID='MyFund')
    @patch('authentication.utils.requests.post')
    def test_acceptance_and_provider_rejection(self, post):
        post.return_value.status_code = 200
        post.return_value.json.return_value = {'status': 'success'}
        self.assertTrue(send_sms_via_payless('08033952556', 'Test message'))
        self.assertEqual(post.call_args.kwargs['json']['recipient'], '2348033952556')
        post.return_value.json.return_value = {'status': 'error'}
        self.assertFalse(send_sms_via_payless('08033952556', 'Test message'))
        post.side_effect = TimeoutError()
        self.assertFalse(send_sms_via_payless('08033952556', 'Test message'))
