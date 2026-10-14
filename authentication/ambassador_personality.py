"""Private Cohort 4 recommendations, transcribed from the supplied workbook.

Account IDs were checked against the cohort roster. Unconfirmed name matches
remain unassigned. Never include this data in public user serializers.
"""
import json
from pathlib import Path


# name, Ionicons icon, breakdown paragraphs (written in the founder's voice,
# as shared with each ambassador on WhatsApp).
PERSONALITIES = {
    "ENTJ": ("Commander", "flag-outline", [
        "You set direction and bring people together around a clear goal. Where others see a problem, you see a plan.",
        "You're decisive and you like to see things done well and on time, so people naturally look to you to lead.",
        "You'll do well building and leading teams - turning a big vision like MyFund's into targets, systems and results.",
        "Just remember to make room for other people's ideas as you lead. The best commanders listen as well as they direct.",
    ]),
    "ENFJ": ("Protagonist", "people-outline", [
        "You inspire people. You can see the potential in others and you love helping them become their best.",
        "You're warm, persuasive and great with people, so they trust you and follow your lead.",
        "You'll do well growing communities - bringing people into a vision like MyFund and helping them start saving and investing.",
        "Just make sure you take care of your own goals too, not only everyone else's.",
    ]),
    "ISTJ": ("Logistician", "clipboard-outline", [
        "You're dependable. When you say you'll do something, it gets done - properly and on time.",
        "You like clear steps, facts and structure, and you notice the details others miss.",
        "You'll do well wherever accuracy and trust matter - like helping new savers get started on MyFund the right way.",
        "You also make a great team player, because the team can always count on you to follow through.",
    ]),
    "INFJ": ("Advocate", "leaf-outline", [
        "You think long term and can see the big picture compared to the average person. You can be patient, and you have a long-term perspective and delayed gratification.",
        "You'll do well as an investor - building daily for years until you've built something so great that others can only imagine.",
        "So you'll do well with a vision like MyFund, where instant gratification isn't your thing but long-term perspective is.",
        "You'll also make a great team player, because you always consider the bigger picture and not just the task given to you.",
    ]),
    "ENFP": ("Campaigner", "sparkles-outline", [
        "You bring energy and fresh ideas everywhere you go. People enjoy being around you and catch your enthusiasm.",
        "You're creative and curious, and you're great at starting conversations and connecting with people.",
        "You'll do well spreading the word about a vision like MyFund - through content, campaigns and community.",
        "A simple plan will help you carry your many ideas all the way through to results.",
    ]),
    "INTJ": ("Architect", "construct-outline", [
        "You think strategically. You like to understand how things work and then find a better way to do them.",
        "You plan ahead and think long term, so you can see where things are going before others do.",
        "You'll do well designing systems and strategies - the kind of thinking that helps a vision like MyFund scale.",
        "Share your reasoning with your team, so they can build with you and not just follow.",
    ]),
    "ISFJ": ("Defender", "shield-checkmark-outline", [
        "You're caring and reliable. You quietly look out for people and make sure nobody is left behind.",
        "You're patient and thorough, and people feel safe trusting you with what matters to them.",
        "You'll do well supporting people - helping savers on MyFund feel confident about their money and their next step.",
        "Just remember to set clear boundaries, so you can keep caring for others without wearing yourself out.",
    ]),
    "INTP": ("Logician", "bulb-outline", [
        "You're a thinker. You love asking questions and understanding how complex things really work.",
        "You're analytical and original, and you can solve problems in ways others wouldn't think of.",
        "You'll do well with research, data and problem-solving - the kind of thinking that helps a vision like MyFund make better decisions.",
        "Test your ideas with real feedback and examples, so your best thinking turns into real results.",
    ]),
}
SUBTYPES = {
    "A": ("Assertive", "As an Assertive type, you tend to stay calm under pressure and trust your own decisions."),
    "T": ("Turbulent", "As a Turbulent type, you keep pushing yourself to improve - just remember to celebrate how far you've come."),
}

_RECORDS = json.loads((Path(__file__).parent / "data" / "cohort4_personality_profiles.json").read_text())
_PROFILES = {row["user_id"]: row for row in _RECORDS if row["user_id"] is not None}


def _in_scope(user):
    return bool(
        user.is_authenticated and user.is_ambassador and user.ambassador_cohort_id
        and user.ambassador_cohort.cohort_number == 4
    )


def get_own_personality_profile(user):
    """Call only with request.user; never accept a target ID from the client."""
    if not _in_scope(user):
        return None
    row = _PROFILES.get(user.pk)
    if not row:
        return None
    name, icon, breakdown = PERSONALITIES[row["type"][:4]]
    subtype = SUBTYPES.get(row["type"][5:]) if row["subtype_confirmed"] else None
    return {
        "type": row["type"], "name": name, "icon": icon,
        "title": f"{subtype[0]} {name}" if subtype else name,
        "breakdown": list(breakdown) + ([subtype[1]] if subtype else []),
        "courses": list(row["courses"]),
        "role": row["role"], "subtype_confirmed": row["subtype_confirmed"],
    }


def personality_test_pending(user):
    """Cohort 4 ambassadors who haven't had a result recorded yet."""
    return _in_scope(user) and user.pk not in _PROFILES
