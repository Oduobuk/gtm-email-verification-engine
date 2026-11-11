"""Unit tests for syntax, disposable domain, role-based, and typo checks."""

from gtm_verifier.syntax_disposable import (
    is_disposable,
    is_role_based,
    suggest_domain_fix,
    validate_syntax,
)


def test_validate_syntax_accepts_standard_and_plus_addresses() -> None:
    ok, local, domain = validate_syntax("  Alex.Mercer+gtm@Stripe.COM ")
    assert ok is True
    assert local == "alex.mercer+gtm"
    assert domain == "stripe.com"


def test_validate_syntax_rejects_malformed_addresses() -> None:
    malformed = [
        "",
        "no-at-sign.com",
        "two@@example.com",
        "bad..dots@example.com",
        ".leading@example.com",
        "trailing.@example.com",
        "user@-badhost.com",
        "user@localhost",
    ]
    for email in malformed:
        ok, _, _ = validate_syntax(email)
        assert ok is False, f"Expected syntax failure for {email}"


def test_disposable_and_role_based_detection() -> None:
    assert is_disposable("mailinator.com") is True
    assert is_disposable("yopmail.com") is True
    assert is_disposable("acme.io") is False

    assert is_role_based("support") is True
    assert is_role_based("noreply") is True
    assert is_role_based("david") is False


def test_typo_suggestion() -> None:
    assert suggest_domain_fix("gmial.com") == "gmail.com"
    assert suggest_domain_fix("outlok.com") == "outlook.com"
    assert suggest_domain_fix("gmail.com") is None
