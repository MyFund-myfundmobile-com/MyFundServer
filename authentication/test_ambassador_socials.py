from django.test import SimpleTestCase
from .ambassador_application_schema import fields_for, errors_for, MYFUND_SOCIALS
from .test_ambassador_application import COMPLETE


class AmbassadorSocialTest(SimpleTestCase):
    def test_follow_buttons_and_selected_profile_validation(self):
        fields = fields_for('ambassador')
        self.assertEqual(fields['follow_confirmed']['follow_all'], MYFUND_SOCIALS)
        for platform, url in MYFUND_SOCIALS.items():
            self.assertEqual(fields[f'link_{platform.lower()}']['follow'], url)
        answers = {**COMPLETE, 'platforms': ['Instagram']}
        self.assertIn('link_instagram', errors_for(answers, complete=True))
        answers['link_instagram'] = 'https://instagram.com/ada'
        self.assertEqual(errors_for(answers, complete=True), {})
        answers['follow_confirmed'] = False
        self.assertIn('follow_confirmed', errors_for(answers, complete=True))
        self.assertEqual(errors_for(answers), {})  # Incomplete drafts can still save.
