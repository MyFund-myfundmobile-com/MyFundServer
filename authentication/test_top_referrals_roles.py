from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from .models import CustomUser
from .views import TopReferralsAPIView


class TopReferralsRoleTest(TestCase):
    def setUp(self):
        self.referrers = []
        for index, flags in enumerate([
            {},
            {"is_ambassador": True},
            {"is_influencer": True},
            {"is_ambassador": True, "is_influencer": True},
        ]):
            user = CustomUser.objects.create_user(
                email=f"referrer{index}@example.com",
                phone_number=f"1000000000{index}",
                password="testpass123",
                **flags,
            )
            self.referrers.append(user)
            CustomUser.objects.create_user(
                email=f"signup{index}@example.com",
                phone_number=f"2000000000{index}",
                password="testpass123",
                referral=user,
            )

    def leaderboard(self, user):
        request = APIRequestFactory().get("/api/top-referrals/")
        force_authenticate(request, user=user)
        with patch.object(TopReferralsAPIView, "send_rank_notification"):
            response = TopReferralsAPIView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        return response.data["top_referrers"]

    def test_influencers_include_every_referrer_role_even_with_ambassador_flag(self):
        for viewer in self.referrers[2:]:
            rows = self.leaderboard(viewer)
            self.assertEqual({row["id"] for row in rows}, {user.id for user in self.referrers})
            for row in rows:
                user = next(user for user in self.referrers if user.id == row["id"])
                self.assertEqual(row["is_ambassador"], user.is_ambassador)
                self.assertEqual(row["is_influencer"], user.is_influencer)

    def test_ambassador_only_view_keeps_ambassador_scope(self):
        rows = self.leaderboard(self.referrers[1])
        self.assertEqual({row["id"] for row in rows}, {self.referrers[1].id, self.referrers[3].id})

    def test_historical_period_counts_and_does_not_send_rank_notifications(self):
        from datetime import timedelta
        from django.utils import timezone
        previous = timezone.now().replace(day=1) - timedelta(days=2)
        friend = CustomUser.objects.get(email="signup0@example.com")
        CustomUser.objects.filter(pk=friend.pk).update(
            date_joined=previous, referral_reward_granted=True,
            referral_reward_confirmed_at=timezone.now(),
        )
        viewer = self.referrers[3]
        factory = APIRequestFactory()
        for period, expected_signups, expected_confirmed in [
            ("last_month", 1, 0), ("last_3_months", 1, 1), ("last_6_months", 1, 1), ("all_time", 1, 1),
        ]:
            request = factory.get("/", {"period": period})
            force_authenticate(request, user=viewer)
            with patch.object(TopReferralsAPIView, "send_rank_notification") as notify:
                response = TopReferralsAPIView.as_view()(request)
                notify.assert_not_called()
            self.assertEqual(response.status_code, 200)
            row = next(r for r in response.data["top_referrers"] if r["id"] == self.referrers[0].id)
            self.assertEqual((row["monthly_signups"], row["monthly_confirmed"]),
                             (expected_signups, expected_confirmed))
        rows = self.leaderboard(viewer)
        row = next(r for r in rows if r["id"] == self.referrers[0].id)
        self.assertEqual((row["monthly_signups"], row["monthly_confirmed"]), (0, 1))

    @patch("authentication.performance_periods.timezone.localdate")
    def test_three_month_window_counts_signup_and_confirmation_dates_independently(self, localdate):
        from datetime import date, datetime
        from django.utils import timezone
        localdate.return_value = date(2026, 1, 15)
        viewer = self.referrers[2]
        friend = CustomUser.objects.get(email="signup2@example.com")
        cases = [
            ((2025, 10, 31), (2025, 11, 1), 0, 1),
            ((2025, 11, 1), (2026, 1, 31), 1, 1),
            ((2026, 1, 31), (2026, 2, 1), 1, 0),
            ((2026, 2, 1), (2026, 2, 1), 0, 0),
        ]
        for joined, confirmed, signups, confirmations in cases:
            CustomUser.objects.filter(pk=friend.pk).update(
                date_joined=timezone.make_aware(datetime(*joined)),
                referral_reward_granted=True,
                referral_reward_confirmed_at=timezone.make_aware(datetime(*confirmed)),
            )
            request = APIRequestFactory().get("/api/top-referrals/", {"period": "last_3_months"})
            force_authenticate(request, user=viewer)
            with patch.object(TopReferralsAPIView, "send_rank_notification") as notify:
                response = TopReferralsAPIView.as_view()(request)
                notify.assert_not_called()
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data["period_label"], "Last 3 months")
            self.assertEqual(response.data["current_user"]["monthly_signups"], signups)
            self.assertEqual(response.data["current_user"]["monthly_confirmed"], confirmations)


class PrivatePersonalityEndpointTest(TestCase):
    def setUp(self):
        from .models import AmbassadorCohort
        cohort = AmbassadorCohort.objects.create(cohort_number=4)
        self.owner = CustomUser.objects.create_user(email='profile-owner@example.com', phone_number='909000001', password='testpass123', is_ambassador=True, ambassador_cohort=cohort)
        self.other = CustomUser.objects.create_user(email='profile-other@example.com', phone_number='909000002', password='testpass123', is_ambassador=True, ambassador_cohort=cohort, referral=self.owner)

    def test_private_profile_is_only_returned_to_owner(self):
        from .ambassador_personality import _RECORDS
        record = dict(_RECORDS[0], user_id=self.owner.pk)
        with patch('authentication.ambassador_personality._PROFILES', {self.owner.pk: record}):
            for viewer in [self.owner, self.other]:
                request = APIRequestFactory().get('/api/top-referrals/', {'user_id': self.owner.pk})
                force_authenticate(request, user=viewer)
                with patch.object(TopReferralsAPIView, 'send_rank_notification'):
                    response = TopReferralsAPIView.as_view()(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data['personality_profile_owner_id'], viewer.pk)
                if viewer == self.owner:
                    self.assertEqual(response.data['personality_profile']['type'], record['type'])
                else:
                    self.assertIsNone(response.data['personality_profile'])
                    self.assertNotIn('personality_profile', response.data['current_user'])
                    self.assertNotIn('Google AI Professional Certificate', str(response.data['top_referrers']))

    def test_anonymous_access_is_denied(self):
        response = TopReferralsAPIView.as_view()(APIRequestFactory().get('/api/top-referrals/'))
        self.assertIn(response.status_code, [401, 403])
