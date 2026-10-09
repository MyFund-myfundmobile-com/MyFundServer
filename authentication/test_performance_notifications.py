from unittest.mock import patch
from django.utils import timezone
from .test_cohort_performance import CohortPerformanceTest
from .ambassador_performance_notifications import notify_member
from .models import AmbassadorMonthlyReport, AmbassadorPerformanceNotificationState


class PerformanceNotificationTest(CohortPerformanceTest):
    @patch('authentication.ambassador_performance_notifications.send_push_notification', return_value={'success': True})
    @patch('authentication.ambassador_performance_notifications.send_transactional_email', return_value={'sent': 1})
    def test_baseline_change_and_weekly_deduplication(self, email, push):
        now = timezone.localtime()
        notify_member(self.me, False, now)
        email.assert_not_called()
        push.assert_not_called()
        AmbassadorMonthlyReport.objects.create(user=self.other, month=self.this_key, total_points_awarded=50)
        notify_member(self.me, False, now)
        self.assertEqual(email.call_count, 1)
        self.assertIn('Overall: #2 of 3 in Cohort 4', email.call_args.kwargs['message'])
        self.assertIn('2 sign-ups', email.call_args.kwargs['message'])
        notify_member(self.me, False, now)
        self.assertEqual(email.call_count, 1)
        notify_member(self.me, True, now)
        notify_member(self.me, True, now)
        self.assertEqual(email.call_count, 2)
        self.assertEqual(push.call_count, 2)

    @patch('authentication.ambassador_performance_notifications.send_push_notification', return_value={'success': True})
    @patch('authentication.ambassador_performance_notifications.send_transactional_email')
    def test_failed_email_retries_without_duplicate_successful_push(self, email, push):
        email.side_effect = [{'sent': 0}, {'sent': 1}]
        now = timezone.localtime()
        notify_member(self.me, True, now)
        notify_member(self.me, True, now)
        self.assertEqual(email.call_count, 2)
        self.assertEqual(push.call_count, 1)
        state = AmbassadorPerformanceNotificationState.objects.get(user=self.me)
        self.assertEqual(state.channels['email']['rank'], 1)
