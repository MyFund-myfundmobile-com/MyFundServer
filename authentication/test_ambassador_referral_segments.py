"""
Tests for CustomUserQuerySet.users_referred_never_ambassador/
users_referred_and_ambassador (models.py) - the two segments behind the
Ambassador Cohort 4 outreach campaign (2026-09). A bug here means someone
gets the wrong message (an ex-ambassador told to "apply" instead of
"forward"), so this asserts both mutual exclusivity and full coverage of
every referred user, not just that each segment returns something.
"""

from django.test import TestCase

from .models import AmbassadorCohort, CustomUser


def _make_user(email, phone, **extra):
    extra.setdefault("first_name", "Test")
    extra.setdefault("last_name", "User")
    return CustomUser.objects.create_user(
        email=email,
        password="testpass123",
        phone_number=phone,
        **extra,
    )


class AmbassadorReferralSegmentTest(TestCase):
    def setUp(self):
        self.cohort = AmbassadorCohort.objects.create(cohort_number=99)

        # Referrer with no referrals at all - in neither segment.
        self.no_referrals = _make_user("noref@example.com", "97000000010")

        # Referred someone, never an ambassador - Segment A.
        self.segment_a_user = _make_user("segmenta@example.com", "97000000011")
        _make_user("a_referred1@example.com", "97000000012", referral=self.segment_a_user)

        # Referred someone, currently an ambassador - Segment B.
        self.current_ambassador = _make_user(
            "currentamb@example.com", "97000000013",
            is_ambassador=True, ambassador_cohort=self.cohort,
        )
        _make_user("b_referred1@example.com", "97000000014", referral=self.current_ambassador)

        # Referred someone, FORMER ambassador (is_ambassador now False, but
        # still has an ambassador_cohort record) - must land in Segment B,
        # never Segment A. This is the exact regression the spec called out.
        self.former_ambassador = _make_user(
            "formeramb@example.com", "97000000015",
            is_ambassador=False, ambassador_cohort=self.cohort,
        )
        _make_user("b_referred2@example.com", "97000000016", referral=self.former_ambassador)

        # Never an ambassador and never referred anyone - in neither segment.
        _make_user("plain@example.com", "97000000017")

    def test_segment_a_is_referred_never_ambassador(self):
        segment_a = CustomUser.objects.users_referred_never_ambassador()
        self.assertIn(self.segment_a_user, segment_a)
        self.assertNotIn(self.no_referrals, segment_a)
        self.assertNotIn(self.current_ambassador, segment_a)
        self.assertNotIn(self.former_ambassador, segment_a)

    def test_segment_b_is_referred_and_ever_ambassador(self):
        segment_b = CustomUser.objects.users_referred_and_ambassador()
        self.assertIn(self.current_ambassador, segment_b)
        self.assertIn(self.former_ambassador, segment_b)
        self.assertNotIn(self.segment_a_user, segment_b)
        self.assertNotIn(self.no_referrals, segment_b)

    def test_segments_are_mutually_exclusive(self):
        a_ids = set(CustomUser.objects.users_referred_never_ambassador().values_list("id", flat=True))
        b_ids = set(CustomUser.objects.users_referred_and_ambassador().values_list("id", flat=True))
        self.assertEqual(a_ids & b_ids, set())

    def test_segments_together_cover_every_referred_user(self):
        from django.db.models import Exists, OuterRef

        referred_exists = CustomUser.objects.filter(is_deleted=False, referral=OuterRef("pk"))
        all_referred_ids = set(
            CustomUser.objects.annotate(hr=Exists(referred_exists))
            .filter(hr=True)
            .values_list("id", flat=True)
        )
        a_ids = set(CustomUser.objects.users_referred_never_ambassador().values_list("id", flat=True))
        b_ids = set(CustomUser.objects.users_referred_and_ambassador().values_list("id", flat=True))
        self.assertEqual(a_ids | b_ids, all_referred_ids)

    def test_ever_ambassador_includes_members_without_referrals(self):
        current = _make_user("currentonly@example.com", "97000000018", is_ambassador=True)
        former = _make_user("formeronly@example.com", "97000000019", ambassador_cohort=self.cohort)
        expected = {self.current_ambassador.pk, self.former_ambassador.pk, current.pk, former.pk}
        self.assertEqual(set(CustomUser.objects.ever_ambassador().values_list("pk", flat=True)), expected)
        self.assertFalse(CustomUser.objects.filter(pk=self.no_referrals.pk).ever_ambassador().exists())

    def test_mobile_filter_and_apply_are_disjoint(self):
        from .admin_views import _build_admin_user_queryset

        recipients, _ = _build_admin_user_queryset({"ever_ambassador": "true"})
        self.assertEqual(set(recipients.values_list("pk", flat=True)),
                         {self.current_ambassador.pk, self.former_ambassador.pk})
        apply, _ = _build_admin_user_queryset({"ever_ambassador": "true", "referral_segment": "apply"})
        self.assertFalse(apply.exists())

    def test_brevo_referral_segment_excludes_former_ambassadors_from_apply(self):
        from .services.brevo_service import determine_referral_segment

        self.assertEqual(determine_referral_segment(self.current_ambassador, 1), "forward")
        self.assertEqual(determine_referral_segment(self.former_ambassador, 1), "forward")
        self.assertEqual(determine_referral_segment(self.segment_a_user, 1), "apply")
        self.assertIsNone(determine_referral_segment(self.former_ambassador, 0))

    def test_brevo_sync_sends_boolean_history_attribute(self):
        from unittest.mock import patch
        from .services import brevo_service

        with patch.object(brevo_service, "get_brevo_client"), \
             patch.object(brevo_service.sib_api_v3_sdk, "ContactsApi") as api, \
             patch.object(brevo_service, "get_transaction_metrics", return_value={
                 "last_date": None, "count": 0, "total": 0,
                 "last_type": "", "last_source": "",
             }), patch("builtins.print"):
            for user, expected in [(self.current_ambassador, True),
                                   (self.former_ambassador, True),
                                   (self.segment_a_user, False)]:
                with self.subTest(user=user.pk):
                    api.return_value.create_contact.reset_mock()
                    brevo_service.sync_contact_to_brevo(user)
                    api.return_value.create_contact.assert_called_once()
                    contact = api.return_value.create_contact.call_args.args[0]
                    self.assertIs(contact.attributes["EVER_AMBASSADOR"], expected)
                    self.assertIs(contact.attributes["IS_AMBASSADOR"], user.is_ambassador)
