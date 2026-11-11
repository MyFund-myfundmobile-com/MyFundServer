"""Best-effort city from a one-line address, for users who did KYC before
it had a separate City field ("13, Gbajabiamila Street, off Camp Davies
Road, Ipaja, Lagos" -> "Ipaja"). Only ever used to pre-fill a field the
user can still edit."""
import re

STATES = {
    "abia", "adamawa", "akwa ibom", "anambra", "bauchi", "bayelsa", "benue", "borno",
    "cross river", "delta", "ebonyi", "edo", "ekiti", "enugu", "gombe", "imo", "jigawa",
    "kaduna", "kano", "katsina", "kebbi", "kogi", "kwara", "lagos", "nasarawa", "niger",
    "ogun", "ondo", "osun", "oyo", "plateau", "rivers", "sokoto", "taraba", "yobe",
    "zamfara", "fct", "abuja fct", "federal capital territory",
}
COUNTRY = {"nigeria", "ng"}
# Words that mark a part as a street/landmark, not a town.
STREET_WORDS = re.compile(
    r"\b(street|str|st|road|rd|close|avenue|ave|crescent|cres|way|lane|drive|off|"
    r"estate|plot|block|house|flat|junction|bus\s*stop|opposite|opp|beside|behind|"
    r"along|by|no\.?|layout|phase|quarters|expressway|highway|zone)\b",
    re.I,
)


def _clean(part):
    part = re.sub(r"\bstate\b", "", part, flags=re.I)
    return re.sub(r"\s+", " ", part).strip(" .-")


def guess_city(address, state=""):
    if not address or address.strip().lower() == "enter address":
        return ""
    state = (state or "").strip().lower()
    parts = [_clean(p) for p in re.split(r"[,\n]", address)]
    parts = [p for p in parts if p]
    while parts:
        last = parts[-1]
        low = last.lower()
        if low in COUNTRY or low in STATES or (state and low == state) or re.fullmatch(r"[\d\s]+", low):
            parts.pop()
            continue
        break
    if len(parts) < 2:  # nothing but the street left
        return ""
    candidate = parts[-1]
    if STREET_WORDS.search(candidate) or re.search(r"\d", candidate) or len(candidate) > 40:
        return ""
    return candidate.title() if candidate.islower() or candidate.isupper() else candidate
