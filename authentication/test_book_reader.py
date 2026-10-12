from django.test import TestCase
from rest_framework.test import APIClient
from authentication.book_models import BookReadingProgress
from authentication.models import CustomUser, AmbassadorCohort


class BookReaderTests(TestCase):
    def setUp(self):
        cohort = AmbassadorCohort.objects.create(cohort_number=4, status='active')
        self.ambassador = CustomUser.objects.create(email='amb@example.test', phone_number='09000000021', is_ambassador=True)
        self.former = CustomUser.objects.create(email='former@example.test', phone_number='09000000022', ambassador_cohort=cohort)
        self.saver = CustomUser.objects.create(email='saver@example.test', phone_number='09000000023')
        self.client = APIClient()

    def as_user(self, user):
        self.client.force_authenticate(user)
        return self.client

    def test_only_current_and_former_ambassadors_get_a_link(self):
        self.assertEqual(self.as_user(self.saver).get('/api/books/nine-steps/access/').status_code, 403)
        self.assertEqual(self.as_user(self.former).get('/api/books/nine-steps/access/').status_code, 200)
        self.assertEqual(self.as_user(self.ambassador).get('/api/books/unknown/access/').status_code, 404)
        self.assertEqual(self.as_user(self.ambassador).get('/api/books/ten-laws/access/').json()['title'], '10 Laws of Academic Excellence')

    def test_signed_link_serves_pdf_until_access_is_revoked(self):
        path = self.as_user(self.ambassador).get('/api/books/nine-steps/access/').json()['read_path']
        anon = APIClient()
        res = anon.get(path)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'application/pdf')
        self.assertTrue(b''.join(res.streaming_content).startswith(b'%PDF'))
        self.assertEqual(anon.get(path.replace('/read/', '/read/x')).status_code, 403)
        self.ambassador.is_ambassador = False
        self.ambassador.save()
        self.assertEqual(anon.get(path).status_code, 403)

    def test_progress_keeps_furthest_page_and_marks_completion(self):
        c = self.as_user(self.ambassador)
        self.assertEqual(c.get('/api/books/nine-steps/progress/').json()['last_page'], 1)
        self.assertEqual(c.post('/api/books/nine-steps/progress/', {'last_page': 0, 'total_pages': 133}).status_code, 400)
        c.post('/api/books/nine-steps/progress/', {'last_page': 90, 'total_pages': 133})
        body = c.post('/api/books/nine-steps/progress/', {'last_page': 12, 'total_pages': 133}).json()
        self.assertEqual((body['last_page'], body['max_page'], body['completed']), (12, 90, False))
        self.assertTrue(c.post('/api/books/nine-steps/progress/', {'last_page': 133, 'total_pages': 133}).json()['completed'])
        self.assertEqual(BookReadingProgress.objects.get(user=self.ambassador).percent, 100)
        self.assertEqual(self.as_user(self.saver).post('/api/books/nine-steps/progress/', {'last_page': 1, 'total_pages': 133}).status_code, 403)
