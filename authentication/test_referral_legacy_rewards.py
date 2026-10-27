from decimal import Decimal

from django.test import TestCase

from authentication.models import CustomUser, Transaction


class LegacyReferralRewardTests(TestCase):
    """Referral rewards created in 2025 as "Referral Reward . . ." still
    confirm once the referred user qualifies."""

    def test_legacy_titled_rewards_confirm_and_pay_both_sides(self):
        ambassador = CustomUser.objects.create_user(
            email="amb@example.com", password="x", first_name="Eni", last_name="A",
            phone_number="08035000001", is_ambassador=True)
        referred = CustomUser.objects.create_user(
            email="old@example.com", password="x", first_name="Tayo", last_name="B",
            phone_number="08035000002", referral=ambassador)
        Transaction.objects.filter(user__in=[ambassador, referred]).delete()
        for owner, other in ((referred, ambassador), (ambassador, referred)):
            Transaction.objects.create(
                user=owner, referral_email=other.email, transaction_type="credit",
                status="pending", amount=Decimal("500"), description="Referral Reward . . .",
                transaction_id=f"legacy-{owner.pk}")
            CustomUser.objects.filter(pk=owner.pk).update(pending_referral_reward=Decimal("500"))
        CustomUser.objects.filter(pk=referred.pk).update(savings=Decimal("50000"))

        referred.refresh_from_db()
        referred.confirm_referral_rewards(is_referrer=True)

        referred.refresh_from_db()
        ambassador.refresh_from_db()
        self.assertTrue(referred.referral_reward_granted)
        self.assertEqual((referred.wallet, ambassador.wallet), (Decimal("500"), Decimal("500")))
        self.assertEqual(
            set(Transaction.objects.filter(user__in=[ambassador, referred]).values_list("description", "status")),
            {("Referral Reward", "confirmed")},
        )
