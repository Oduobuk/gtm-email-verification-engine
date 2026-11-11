import re
from typing import Tuple, Optional

# RFC 5322 compliant email regular expression (practical subset avoiding catastrophic backtracking)
EMAIL_REGEX = re.compile(
    r"^(?P<local>[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@"
    r"(?P<domain>(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})$"
)

# Common role-based prefixes targeted for B2B outreach classification
ROLE_PREFIXES = frozenset({
    "admin", "administrator", "billing", "compliance", "contact", "enquiries",
    "enquiry", "finance", "hello", "help", "hr", "info", "inquiries", "jobs",
    "legal", "mail", "marketing", "media", "noreply", "no-reply", "office",
    "operations", "press", "privacy", "recruiting", "sales", "security",
    "service", "support", "team", "tech", "webmaster"
})

# High-frequency disposable / burner email domains
DISPOSABLE_DOMAINS = frozenset({
    "10minutemail.com", "10minutemail.net", "burnermail.io", "discard.email",
    "dispostable.com", "dropmail.me", "emailondeck.com", "fakeinbox.com",
    "getairmail.com", "getnada.com", "guerrillamail.biz", "guerrillamail.com",
    "guerrillamail.de", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "harakirimail.com", "inboxkitten.com", "mailcatch.com", "maildrop.cc",
    "mailinator.com", "mailinator.net", "mailnesia.com", "mintemail.com",
    "mohmal.com", "moakt.com", "mytemp.email", "nada.email", "sharklasers.com",
    "spam4.me", "spamgourmet.com", "temp-mail.io", "temp-mail.org", "tempail.com",
    "tempinbox.com", "tempmail.com", "tempmail.net", "tempmailo.com",
    "throwawaymail.com", "trashmail.com", "trashmail.net", "yopmail.com",
    "yopmail.fr", "yopmail.net"
})

# Common domain typo corrections for GTM lead cleaning
DOMAIN_TYPO_SUGGESTIONS = {
    "gmial.com": "gmail.com",
    "gmai.com": "gmail.com",
    "gamil.com": "gmail.com",
    "gnail.com": "gmail.com",
    "gmail.co": "gmail.com",
    "gmaill.com": "gmail.com",
    "yaho.com": "yahoo.com",
    "yahooo.com": "yahoo.com",
    "yhoo.com": "yahoo.com",
    "hotmial.com": "hotmail.com",
    "hotmal.com": "hotmail.com",
    "hotmai.com": "hotmail.com",
    "outlok.com": "outlook.com",
    "outllok.com": "outlook.com",
    "outloook.com": "outlook.com",
    "icoud.com": "icloud.com",
    "iclod.com": "icloud.com",
}


def validate_syntax(email: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate email address against RFC 5322 rules.
    Returns (is_valid, local_part, domain).
    """
    if not isinstance(email, str):
        return False, None, None
    cleaned = email.strip().lower()
    if len(cleaned) > 254 or ".." in cleaned:
        return False, None, None
    match = EMAIL_REGEX.match(cleaned)
    if not match:
        return False, None, None
    local = match.group("local")
    domain = match.group("domain")
    if local.startswith(".") or local.endswith("."):
        return False, None, None
    if any(label.startswith("-") or label.endswith("-") for label in domain.split(".")):
        return False, None, None
    return True, local, domain


def is_role_based(local_part: str) -> bool:
    """Detect generic role-based addresses (e.g. info@, sales@)."""
    return local_part.lower() in ROLE_PREFIXES


def is_disposable(domain: str) -> bool:
    """Check whether domain is a known burner/disposable provider."""
    domain_lower = domain.lower()
    if domain_lower in DISPOSABLE_DOMAINS:
        return True
    # Check subdomain match (e.g. sub.mailinator.com)
    parts = domain_lower.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in DISPOSABLE_DOMAINS:
            return True
    return False


def suggest_domain_fix(domain: str) -> Optional[str]:
    """Return suggested correction if domain is a frequent typo."""
    return DOMAIN_TYPO_SUGGESTIONS.get(domain.lower())
