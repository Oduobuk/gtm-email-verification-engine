"""High-throughput asynchronous email verification engine for internal GTM infrastructure."""

from .dns_resolver import AsyncDNSResolver, DomainDNSResult
from .smtp_handshake import AsyncSMTPVerifier, SMTPVerificationResult
from .syntax_disposable import (
    is_disposable,
    is_role_based,
    suggest_domain_fix,
    validate_syntax,
)
from .worker_pool import (
    ProxyRotator,
    VerificationEngine,
    VerificationReport,
    VerificationStatus,
)

__all__ = [
    "AsyncDNSResolver",
    "AsyncSMTPVerifier",
    "DomainDNSResult",
    "ProxyRotator",
    "SMTPVerificationResult",
    "VerificationEngine",
    "VerificationReport",
    "VerificationStatus",
    "is_disposable",
    "is_role_based",
    "suggest_domain_fix",
    "validate_syntax",
]
