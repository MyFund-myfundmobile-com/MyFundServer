from types import SimpleNamespace
from unittest import TestCase
from .ambassador_personality import get_own_personality_profile, personality_test_pending, _RECORDS, _PROFILES


class PersonalityProfileTests(TestCase):
    def user(self, pk=460, **changes):
        values = dict(pk=pk, is_authenticated=True, is_ambassador=True,
                      ambassador_cohort_id=4, ambassador_cohort=SimpleNamespace(cohort_number=4))
        values.update(changes)
        return SimpleNamespace(**values)

    def test_owner_receives_exact_recommendations(self):
        profile = get_own_personality_profile(self.user())
        self.assertEqual(profile['type'], 'ENTJ-A')
        self.assertEqual(profile['name'], 'Commander')
        self.assertEqual(profile['courses'], ['Google AI Professional Certificate', 'Google Prompting Essentials'])
        self.assertIn('Webinar host', profile['role'])
        self.assertNotIn('source_name', profile)
        self.assertNotIn('user_id', profile)

    def test_other_accounts_cannot_receive_assigned_profile(self):
        for changes in [dict(pk=999999), dict(is_authenticated=False), dict(is_ambassador=False),
                        dict(ambassador_cohort_id=None), dict(ambassador_cohort=SimpleNamespace(cohort_number=3))]:
            self.assertIsNone(get_own_personality_profile(self.user(**changes)))

    def test_all_confirmed_matches_are_assigned(self):
        self.assertEqual(len(_RECORDS), 19)
        ids = [row['user_id'] for row in _RECORDS if row['user_id'] is not None]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(_PROFILES), 19)
        self.assertNotIn(None, _PROFILES)
        for pk, code in [(389, 'ENFJ-A'), (655, 'INFJ'), (1108, 'INTP-A')]:
            self.assertEqual(get_own_personality_profile(self.user(pk=pk))['type'], code)
        praise = next(row for row in _RECORDS if row['source_name'] == 'Olowookere Praise')
        self.assertEqual(praise['type'], 'INFJ')
        self.assertFalse(praise['subtype_confirmed'])

    def test_result_does_not_mutate_source_courses(self):
        get_own_personality_profile(self.user())['courses'].clear()
        self.assertEqual(len(get_own_personality_profile(self.user())['courses']), 2)

    def test_christine_has_commander_without_invented_recommendations(self):
        profile = get_own_personality_profile(self.user(pk=1443))
        self.assertEqual(profile['type'], 'ENTJ-A')
        self.assertEqual(profile['name'], 'Commander')
        self.assertTrue(profile['subtype_confirmed'])
        self.assertEqual(profile['courses'], [])
        self.assertEqual(profile['role'], '')

    def test_breakdown_title_and_pending_flag(self):
        profile = get_own_personality_profile(self.user(pk=1443))
        self.assertEqual(profile['title'], 'Assertive Commander')
        self.assertIn('Assertive type', profile['breakdown'][-1])
        praise = get_own_personality_profile(self.user(pk=655))
        self.assertEqual(praise['title'], 'Advocate')
        self.assertNotIn('Assertive type', praise['breakdown'][-1])
        self.assertFalse(personality_test_pending(self.user(pk=1443)))
        self.assertTrue(personality_test_pending(self.user(pk=999999)))
        self.assertFalse(personality_test_pending(self.user(pk=999999, ambassador_cohort=SimpleNamespace(cohort_number=3))))
