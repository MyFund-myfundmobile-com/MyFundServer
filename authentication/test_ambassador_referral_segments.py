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
