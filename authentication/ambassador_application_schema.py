"""One question catalogue used for draft validation, UI and review/export."""

def field(key, label, kind='text', required=True, **kwargs):
    return dict(key=key, label=label, type=kind, required=required, **kwargs)


STEPS = [
    dict(title='About you', subtitle='The basics.', fields=[
        field('full_name', 'Full name', autocomplete='name', maxLength=120),
        field('age', 'Age', 'number', min=18, max=100),
        field('phone', 'WhatsApp number', 'tel', autocomplete='tel', maxLength=20),
        field('location', 'City and state', autocomplete='address-level2', maxLength=120, help='e.g. Ikeja, Lagos. Helps us plan local activities.'),
        field('occupation', 'What do you do?', 'select', options=['Working Professional', 'Business Owner', 'Entrepreneur', 'Corper', 'Undergraduate', 'Postgraduate', 'Freelancer']),
        field('organisation', 'Company, business or school', required=False, maxLength=200),
        field('has_account', 'Do you have a MyFund account?', 'choice', options=['Yes', 'No']),
        field('account_email', 'MyFund account email', 'email', required=False, when=['has_account', 'Yes'], help='Use the email above to receive personalised guidance. Another email here is self-reported, not verified.'),
        field('has_saved', 'Have you ever saved with MyFund?', 'choice', options=['Yes', 'No']),
        field('saved_band', 'Approximately how much have you saved?', 'select', required=False, when=['has_saved', 'Yes'], options=['Under ₦10,000', '₦10,000–₦50,000', 'Over ₦50,000']),
    ]),
    dict(title='Your community', subtitle='Who you can reach.', fields=[
        field('communities', 'Where are your communities?', 'multi', options=['Church', 'Workplace', 'Professional Association', 'Business Community', 'Campus', 'WhatsApp', 'Telegram', 'LinkedIn', 'Facebook', 'Instagram', 'X', 'Other']),
        field('community_other', 'Tell us about your other community', required=False, when=['communities', 'Other'], maxLength=200),
        field('weekly_reach', 'How many people can you reach each week?', 'select', options=['Under 50', '50–100', '100–300', '300–1,000', 'Over 1,000']),
        field('social_link', 'Link to your most active social profile', 'url', required=False, maxLength=300, help='Helps us understand your audience. https:// link, e.g. your Instagram, LinkedIn or X profile.'),
        field('has_promoted', 'Have you promoted or sold something before?', 'choice', options=['Yes', 'No']),
        field('promotion_experience', 'What did you promote and what happened?', 'textarea', required=False, when=['has_promoted', 'Yes'], maxLength=1500),
    ]),
    dict(title='Your growth plan', subtitle='Your plan, in your own words.', fields=[
        field('motivation', 'Why do you want to be a MyFund Ambassador?', 'textarea', maxLength=2000, help='What draws you to helping others save and invest?'),
        field('saving_habits', 'Which best describes your saving habits?', 'select', options=['I save consistently every month', 'I save occasionally', 'I am just starting', 'I do not currently save']),
        field('products', 'Which MyFund products would you introduce?', 'multi', options=['Savings', 'Target Savings', 'Investments', 'Rental Income', 'Referral Programme', 'I am still learning']),
        field('signup_target', 'Your first-month confirmed-user target', 'choice', options=['10', '20', '30', '50', '100+']),
        field('growth_plan', 'How will you reach that target?', 'textarea', maxLength=2500, help='Mention your audience, the channels you will use and your first practical steps. Please use your own words.'),
    ]),
    dict(title='Your commitment', subtitle='What you can commit to.', fields=[
        field('six_months', 'Can you commit to the six-month programme?', 'choice', options=['Yes', 'No']),
        field('weekly_meetings', 'Can you attend Saturday virtual meetings?', 'choice', options=['Yes', 'No']),
        field('monthly_targets', 'Can you work towards monthly referral targets?', 'choice', options=['Yes', 'No']),
    ]),
    dict(title='Say hello', subtitle='Optional: a short intro video.', fields=[
        field('video_link', 'Video link', 'url', required=False, maxLength=1000),
        field('video_shared', 'Anyone with the link can watch', 'boolean', required=False),
    ]),
]
FIELDS = {f['key']: f for step in STEPS for f in step['fields']}

# MyFund's own accounts (same list as the app's influencer form,
# GraduationBanner.js MYFUND_SOCIAL_LINKS). Influencers must follow MyFund;
# the web form shows a "Follow MyFund" button beside each link field.
MYFUND_SOCIALS = {
    'Instagram': 'https://instagram.com/myfundmobile1',
    'TikTok': 'https://www.tiktok.com/@myfundmobile',
    'YouTube': 'https://youtube.com/@myfundmobile',
    'X': 'https://x.com/myfundmobile',
    'LinkedIn': 'https://linkedin.com/company/myfundmobile',
    'Facebook': 'https://facebook.com/myfundmobile',
    'Threads': 'https://threads.net/@myfundmobile',
}

# Influencer programme (www.myfundmobile.com/influencer). Same five-step
# shape as STEPS - the web form treats step 5 as the optional video - built
# from the in-app influencer application (GraduationBanner.js), opened to
# creators who were never ambassadors.
INFLUENCER_STEPS = [
    dict(title='About you', subtitle='The basics.', fields=[
        field('full_name', 'Full name', autocomplete='name', maxLength=120),
        field('age', 'Age', 'number', min=18, max=100),
        field('phone', 'WhatsApp number', 'tel', autocomplete='tel', maxLength=20),
        field('location', 'City and state', autocomplete='address-level2', maxLength=120, help='e.g. Ikeja, Lagos.'),
        field('has_account', 'Do you have a MyFund account?', 'choice', options=['Yes', 'No']),
        field('account_email', 'MyFund account email', 'email', required=False, when=['has_account', 'Yes'], help='Only if it differs from the email you signed in with.'),
        field('was_ambassador', 'Have you been a MyFund Ambassador?', 'choice', options=['Yes', 'No']),
    ]),
    dict(title='Your platforms', subtitle='Where your audience is. Follow MyFund on each so we can follow you back.', fields=[
        field('platforms', 'Where do you create content?', 'multi', options=['Instagram', 'TikTok', 'YouTube', 'X', 'LinkedIn', 'Facebook', 'Threads', 'Snapchat'], help='Pick every platform you post on. We\'ll ask for each link.'),
        field('link_instagram', 'Your Instagram link', 'url', when=['platforms', 'Instagram'], maxLength=300, follow=MYFUND_SOCIALS['Instagram'], help='e.g. https://instagram.com/yourhandle'),
        field('link_tiktok', 'Your TikTok link', 'url', when=['platforms', 'TikTok'], maxLength=300, follow=MYFUND_SOCIALS['TikTok'], help='e.g. https://tiktok.com/@yourhandle'),
        field('link_youtube', 'Your YouTube link', 'url', when=['platforms', 'YouTube'], maxLength=300, follow=MYFUND_SOCIALS['YouTube'], help='e.g. https://youtube.com/@yourchannel'),
        field('link_x', 'Your X link', 'url', when=['platforms', 'X'], maxLength=300, follow=MYFUND_SOCIALS['X'], help='e.g. https://x.com/yourhandle'),
        field('link_linkedin', 'Your LinkedIn link', 'url', when=['platforms', 'LinkedIn'], maxLength=300, follow=MYFUND_SOCIALS['LinkedIn'], help='e.g. https://linkedin.com/in/yourname'),
        field('link_facebook', 'Your Facebook link', 'url', when=['platforms', 'Facebook'], maxLength=300, follow=MYFUND_SOCIALS['Facebook'], help='e.g. https://facebook.com/yourpage'),
        field('link_threads', 'Your Threads link', 'url', when=['platforms', 'Threads'], maxLength=300, follow=MYFUND_SOCIALS['Threads'], help='e.g. https://threads.net/@yourhandle'),
        field('link_snapchat', 'Your Snapchat link', 'url', when=['platforms', 'Snapchat'], maxLength=300, help='e.g. https://snapchat.com/add/yourhandle'),
        field('total_followers', 'Total followers across all platforms', 'select', options=['Under 1K', '1K–5K', '5K–10K', '10K–50K', '50K–100K', '100K–500K', '500K+']),
        field('niche', 'Your content niche', maxLength=150, help='e.g. personal finance, lifestyle, comedy, tech, faith, campus life.'),
        field('engagement', 'Typical engagement or reach', required=False, maxLength=150, help='e.g. 5% engagement, or 10K average views per post.'),
        field('follow_confirmed', 'I confirm I follow MyFund on all our social media platforms.', 'boolean',
              follow_all=MYFUND_SOCIALS, help='Tap each button to follow MyFund, so we can follow you back.'),
    ]),
    dict(title='Your content plan', subtitle='How you would tell the MyFund story.', fields=[
        field('why_influencer', 'Why do you want to be a MyFund Influencer?', 'textarea', maxLength=2000),
        field('content_ideas', 'What content would you make about MyFund?', 'textarea', maxLength=2500, help='Formats, series ideas or angles that suit your audience. Please use your own words.'),
        field('monthly_content', 'Posts about MyFund per month', 'choice', options=['4', '8', '12', '20', '30+']),
        field('monthly_signups', 'Target signups per month', 'choice', options=['5', '10', '20', '50', '100+']),
        field('monthly_savers', 'Target new savers per month', 'choice', options=['5', '10', '20', '50', '100+']),
        field('portfolio_link', 'Link to a post you are proud of', 'url', required=False, maxLength=300, help='Optional. Any https:// link to your best recent content.'),
        field('has_brand_deals', 'Have you worked with brands before?', 'choice', options=['Yes', 'No']),
        field('brand_experience', 'Which brands, and what did you create?', 'textarea', required=False, when=['has_brand_deals', 'Yes'], maxLength=1500),
    ]),
    dict(title='Your commitment', subtitle='How we work together.', fields=[
        field('ongoing_role', 'The role is ongoing until either side ends it. Are you in?', 'choice', options=['Yes', 'No']),
        field('disclose_partnership', 'Will you label MyFund posts as a partnership (e.g. #ad)?', 'choice', options=['Yes', 'No']),
        field('contact_method', 'Best way to reach you', 'choice', options=['WhatsApp', 'Email']),
        field('tshirt_size', 'T-shirt size for your merch', 'choice', options=['S', 'M', 'L', 'XL', 'XXL']),
    ]),
    dict(title='Say hello', subtitle='Optional: a short intro video.', fields=[
        field('video_link', 'Video link', 'url', required=False, maxLength=1000),
        field('video_shared', 'Anyone with the link can watch', 'boolean', required=False),
    ]),
]
STEPS_BY_PROGRAMME = {'ambassador': STEPS, 'influencer': INFLUENCER_STEPS}


def steps_for(programme):
    return STEPS_BY_PROGRAMME.get(programme, STEPS)


def fields_for(programme):
    return {f['key']: f for step in steps_for(programme) for f in step['fields']}


def visible(f, answers):
    if not f.get('when'):
        return True
    key, value = f['when']
    return value in answers.get(key, []) if isinstance(answers.get(key), list) else answers.get(key) == value


def errors_for(answers, complete=False, programme='ambassador'):
    from django.core.validators import validate_email, URLValidator
    from django.core.exceptions import ValidationError
    import re
    fields = fields_for(programme)
    errors = {}
    for key, value in answers.items():
        f = fields.get(key)
        if not f:
            errors[key] = 'Unknown question.'
            continue
        if value in ('', None, []):
            continue
        kind = f['type']
        if kind == 'multi':
            valid = isinstance(value, list) and all(isinstance(v, str) and v in f['options'] for v in value) and len(value) == len(set(value))
        elif kind == 'boolean':
            valid = isinstance(value, bool)
        elif kind == 'number':
            valid = isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).isdigit() and f['min'] <= int(value) <= f['max']
        else:
            valid = isinstance(value, str) and len(value) <= f.get('maxLength', 2000)
            if valid and kind in ('select', 'choice'):
                valid = value in f['options']
            if valid and kind == 'tel':
                valid = bool(re.fullmatch(r'\+?[\d ()-]{7,20}', value)) and len(re.sub(r'\D', '', value)) >= 7
            if valid and kind in ('email', 'url'):
                try:
                    (validate_email if kind == 'email' else URLValidator(schemes=['https']))(value)
                except ValidationError:
                    valid = False
        if not valid:
            errors[key] = 'Please enter a valid answer.'
    if complete:
        for key, f in fields.items():
            value = answers.get(key)
            if f['required'] and visible(f, answers) and (value in ('', None, []) or isinstance(value, str) and not value.strip()):
                errors[key] = 'Please answer this question.'
            elif f['required'] and f['type'] == 'boolean' and visible(f, answers) and value is not True:
                errors[key] = 'Please confirm to continue.'
        if answers.get('video_link') and answers.get('video_shared') is not True:
            errors['video_shared'] = 'Confirm that reviewers can open your video without requesting access.'
    return errors


def progress_for(answers, programme='ambassador'):
    required = [f['key'] for f in fields_for(programme).values() if f['required'] and visible(f, answers)]
    errors = errors_for(answers, complete=True, programme=programme)
    return round(100 * sum(key not in errors for key in required) / len(required))
