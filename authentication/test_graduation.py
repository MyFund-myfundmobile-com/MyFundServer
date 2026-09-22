from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from authentication.models import CustomUser, AmbassadorCohort, AmbassadorCertificate, InfluencerApplication
from authentication.graduation_views import graduation_access

class GraduationTests(TestCase):
    def setUp(self):
        self.cohort = AmbassadorCohort.objects.create(cohort_number=3, send_forth_date=timezone.localdate()+timedelta(days=10), status='active')
        self.user = CustomUser.objects.create(email='graduate@example.test', phone_number='09000000011', first_name='Graduate', ambassador_cohort=self.cohort)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.payload = {'monthly_content':12,'monthly_signups':30,'monthly_savers':15,'social_links':'https://instagram.com/example','plan':'I will post weekly educational videos and host community sessions.'}

    def test_gate_and_individual_override(self):
        self.assertFalse(graduation_access(self.user))
        self.assertEqual(self.client.post('/api/ambassador/graduation/',self.payload).status_code,403)
        AmbassadorCertificate.objects.create(user=self.user,file='cert.png',early_access=True)
        self.user.refresh_from_db()
        self.assertTrue(graduation_access(self.user))
        other = CustomUser.objects.create(email='other@example.test',phone_number='09000000012',ambassador_cohort=self.cohort)
        self.assertFalse(graduation_access(other))

    def test_application_validation_and_duplicate(self):
        self.cohort.send_forth_date=timezone.localdate()-timedelta(days=1)
        self.cohort.save()
        self.user.refresh_from_db()
        self.assertEqual(self.client.post('/api/ambassador/graduation/',{**self.payload,'monthly_savers':100}).status_code,400)
        self.assertEqual(self.client.post('/api/ambassador/graduation/',self.payload).status_code,200)
        self.assertEqual(self.client.post('/api/ambassador/graduation/',self.payload).status_code,409)

    def test_admin_review_and_role(self):
        application = InfluencerApplication.objects.create(user=self.user,**self.payload)
        founder = CustomUser.objects.create(email='tolulopeahmed@gmail.com',phone_number='09000000013',is_staff=True)
        self.client.force_authenticate(founder)
        result = self.client.get('/api/admin/requests/?kind=influencer')
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.data['count'],1)
        result=self.client.post(f'/api/admin/requests/influencer/{application.pk}/action/',{'action':'approve'})
        self.assertEqual(result.status_code,200,result.data)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_influencer)
        self.assertEqual(self.client.post(f'/api/admin/requests/influencer/{application.pk}/action/',{'action':'approve'}).status_code,400)

    def test_christine_exception_is_exact_account_only(self):
        self.user.email = 'company@myfundmobile.com'
        self.user.save(update_fields=['email'])
        self.assertTrue(graduation_access(self.user))
        self.user.email = 'another@myfundmobile.com'
        self.assertFalse(graduation_access(self.user))
