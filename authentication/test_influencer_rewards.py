from decimal import Decimal
from unittest.mock import patch
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate
from .models import CustomUser, Transaction, AmbassadorMonthlyReport
from .views import AmbassadorPerformanceReportView


class InfluencerRewardsTest(TestCase):
    def setUp(self):
        for name in ("send_push_notification", "send_transactional_email"):
            mocked = patch("authentication.utils." + name)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.referrer = CustomUser.objects.create_user(
            email="influencer@example.com", phone_number="10000000001",
            password="testpass", is_influencer=True,
        )
        self.friend = CustomUser.objects.create_user(
            email="friend@example.com", phone_number="10000000002",
            password="testpass", referral=self.referrer,
        )

    def qualify(self, amount=10000):
        self.friend.savings = Decimal(amount)
        self.friend.save(update_fields=["savings"])
        self.friend.confirm_referral_rewards(False)

    def test_rewards_threshold_and_repeat_confirmation(self):
        self.friend.create_pending_referral_reward()
        self.friend.create_pending_referral_reward()
        self.assertEqual(Transaction.objects.filter(description="Referral Reward").count(), 2)
        self.qualify(9999)
        self.friend.refresh_from_db()
        self.assertFalse(self.friend.referral_reward_granted)
        self.qualify()
        # A second call from a separate model instance cannot pay again.
        CustomUser.objects.get(pk=self.friend.pk).confirm_referral_rewards(False)
        self.referrer.refresh_from_db()
        self.friend.refresh_from_db()
        self.assertEqual(self.referrer.wallet, 1000)
        self.assertEqual(self.friend.wallet, 500)
        self.assertEqual(self.referrer.pending_referral_reward, 0)
        self.assertEqual(self.friend.pending_referral_reward, 0)
        self.assertEqual(Transaction.objects.filter(status="confirmed").count(), 2)

    def test_existing_missing_influencer_pending_reward_is_created_at_confirmation(self):
        self.friend.create_pending_referral_reward()
        Transaction.objects.filter(user=self.referrer).delete()
        CustomUser.objects.filter(pk=self.referrer.pk).update(pending_referral_reward=0)
        self.qualify()
        self.referrer.refresh_from_db()
        self.assertEqual(self.referrer.wallet, 1000)
        self.assertEqual(self.referrer.pending_referral_reward, 0)

    def test_existing_500_pending_is_upgraded_without_negative_pending_balance(self):
        self.friend.create_pending_referral_reward()
        Transaction.objects.filter(user=self.referrer).update(amount=500, total_amount=500)
        CustomUser.objects.filter(pk=self.referrer.pk).update(pending_referral_reward=500)
        self.qualify()
        self.referrer.refresh_from_db()
        self.assertEqual(self.referrer.wallet, 1000)
        self.assertEqual(self.referrer.pending_referral_reward, 0)

    def test_regular_and_ambassador_rates_remain_500(self):
        for ambassador, threshold in [(False, 20000), (True, 10000)]:
            with self.subTest(ambassador=ambassador):
                CustomUser.objects.filter(pk=self.referrer.pk).update(
                    is_influencer=False, is_ambassador=ambassador, wallet=0, pending_referral_reward=0)
                CustomUser.objects.filter(pk=self.friend.pk).update(
                    referral_reward_granted=False, wallet=0, pending_referral_reward=0)
                Transaction.objects.all().delete()
                self.friend.refresh_from_db()
                self.friend.create_pending_referral_reward()
                self.qualify(threshold)
                self.referrer.refresh_from_db()
                self.assertEqual(self.referrer.wallet, 500)

    def test_performance_counts_confirmation_month_even_for_older_signup(self):
        self.friend.create_pending_referral_reward()
        previous_month = timezone.now().replace(day=1) - timedelta(days=2)
        CustomUser.objects.filter(pk=self.friend.pk).update(date_joined=previous_month)
        self.qualify()
        request = APIRequestFactory().get("/api/ambassador/performance-report/", {"period": "last_6_months"})
        force_authenticate(request, user=self.referrer)
        response = AmbassadorPerformanceReportView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["is_influencer"])
        self.assertIsNone(response.data["cohort"])
        self.assertEqual(response.data["months"][-1]["signups"], 0)
        self.assertEqual(response.data["months"][-1]["confirmed"], 1)
        self.assertEqual(Decimal(response.data["months"][-1]["earned"]), 1000)
        self.assertEqual(response.data["months"][-2]["signups"], 1)

    def test_unsaved_deposit_balance_is_preserved(self):
        self.friend.create_pending_referral_reward()
        self.friend.savings = Decimal("10000")
        with self.captureOnCommitCallbacks(execute=True):
            self.friend.confirm_referral_rewards(False)
        self.assertEqual(self.friend.savings, 10000)
        self.assertTrue(self.friend.referral_reward_granted)
        self.friend.save()
        self.referrer.refresh_from_db()
        self.assertEqual(self.referrer.wallet, 1000)
        self.friend.refresh_from_db()
        self.assertEqual(self.friend.savings, 10000)

    def test_influencer_content_updates_from_monthly_submission(self):
        AmbassadorMonthlyReport.objects.create(
            user=self.referrer, month=timezone.now().strftime("%Y-%m"),
            social_media_submitted=4,
        )
        request = APIRequestFactory().get("/api/ambassador/performance-report/", {"period": "last_6_months"})
        force_authenticate(request, user=self.referrer)
        response = AmbassadorPerformanceReportView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["months"][-1]["content"], 4)
