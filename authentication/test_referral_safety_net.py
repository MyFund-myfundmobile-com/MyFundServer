from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from authentication.models import (
    AmbassadorCohort,
    CustomUser,
    Transaction,
    confirmed_referral_counts,
    first_deposit_referral_counts,
)
from authentication.utils import check_stuck_referrals


class ReferralTestBase(TestCase):
    def setUp(self):
        self.n = iter(range(1000))

    def mk(self, email, **extra):
        return CustomUser.objects.create_user(
            email=email, password="x", first_name=email.split("@")[0].title(), last_name="T",
            phone_number=f"0803600{next(self.n):04d}", **extra)

    def pending_rewards(self, referred, times=1):
        for owner, other in ((referred, referred.referral), (referred.referral, referred)):
            Transaction.objects.filter(user=owner, referral_email__iexact=other.email).delete()
            for i in range(times):
                Transaction.objects.create(
                    user=owner, referral_email=other.email, transaction_type="credit",
                    status="pending", amount=Decimal("500"), description="Referral Reward",
                    transaction_id=f"r-{owner.pk}-{other.pk}-{i}")
            CustomUser.objects.filter(pk=owner.pk).update(pending_referral_reward=Decimal("500") * times)


class StuckReferralCheckTests(ReferralTestBase):
    """The daily check confirms referrals that saved enough but were missed,
    and emails the founder the ones whose records need a human."""

    @patch("authentication.utils.send_push_notification")
    @patch("authentication.utils.send_transactional_email")
    def test_confirms_clean_ones_and_reports_ambiguous_ones(self, email, _push):
        amb = self.mk("amb@example.com", is_ambassador=True)
        clean = self.mk("clean@example.com", referral=amb)
        doubled = self.mk("doubled@example.com", referral=amb)
        not_yet = self.mk("small@example.com", referral=amb)
        self.pending_rewards(clean)
        self.pending_rewards(doubled, times=2)
        self.pending_rewards(not_yet)
        CustomUser.objects.filter(pk__in=[clean.pk, doubled.pk]).update(savings=Decimal("10000"))
        CustomUser.objects.filter(pk=not_yet.pk).update(savings=Decimal("9999"))

        with self.captureOnCommitCallbacks(execute=False):
            confirmed, stuck = check_stuck_referrals()

        self.assertEqual([u.pk for u in confirmed], [clean.pk])
        self.assertEqual([u.pk for u in stuck], [doubled.pk])
        clean.refresh_from_db()
        self.assertEqual(clean.wallet, Decimal("500"))
        report = next(c for c in email.call_args_list if "manual check" in c.kwargs["subject"])
        self.assertEqual(report.kwargs["recipient_list"], ["tolulopeahmed@gmail.com"])
        self.assertIn("doubled@example.com", report.kwargs["message"])
        self.assertNotIn("small@example.com", report.kwargs["message"])

    @patch("authentication.utils.send_transactional_email")
    def test_quiet_when_nothing_is_stuck(self, email):
        amb = self.mk("amb@example.com", is_ambassador=True)
        self.mk("new@example.com", referral=amb)
        self.assertEqual(check_stuck_referrals(), ([], []))
        email.assert_not_called()


class PreAmbassadorReferralTests(ReferralTestBase):
    """People referred before someone became an ambassador don't earn
    ambassador points; those referred since their cohort started do."""

    def setUp(self):
        super().setUp()
        cohort = AmbassadorCohort.objects.create(
            cohort_number=4, start_date=date(2026, 8, 1), status="active")
        self.amb = self.mk("amb@example.com", is_ambassador=True, ambassador_cohort=cohort)
        self.before = self.mk("before@example.com", referral=self.amb)
        self.since = self.mk("since@example.com", referral=self.amb)
        CustomUser.objects.filter(pk=self.before.pk).update(
            date_joined=timezone.make_aware(timezone.datetime(2025, 3, 1)))
        CustomUser.objects.filter(pk=self.since.pk).update(
            date_joined=timezone.make_aware(timezone.datetime(2026, 8, 1, 9)))

    def test_confirmed_counts_only_referrals_since_joining(self):
        confirmed_at = timezone.make_aware(timezone.datetime(2026, 10, 20))
        CustomUser.objects.filter(pk__in=[self.before.pk, self.since.pk]).update(
            referral_reward_granted=True, referral_reward_confirmed_at=confirmed_at)
        self.assertEqual(confirmed_referral_counts([self.amb.id], "2026-10"), {self.amb.id: 1})

    def test_first_deposits_count_only_referrals_since_joining(self):
        for user in (self.before, self.since):
            Transaction.objects.create(
                user=user, transaction_type="credit", status="confirmed", amount=Decimal("5000"),
                description="QuickSave", credited_to="SAVINGS", transaction_id=f"qs-{user.pk}",
                date=timezone.make_aware(timezone.datetime(2026, 10, 5)))
        self.assertEqual(
            first_deposit_referral_counts([self.amb.id], "2026-10", Decimal("2000")), {self.amb.id: 1})

    def test_no_cohort_start_date_means_no_cut_off(self):
        AmbassadorCohort.objects.update(start_date=None)
        CustomUser.objects.filter(pk__in=[self.before.pk, self.since.pk]).update(
            referral_reward_granted=True,
            referral_reward_confirmed_at=timezone.now() - timedelta(days=1))
        key = (timezone.now() - timedelta(days=1)).strftime("%Y-%m")
        self.assertEqual(confirmed_referral_counts([self.amb.id], key), {self.amb.id: 2})
