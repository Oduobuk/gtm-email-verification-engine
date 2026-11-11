"""Async verification worker pool with proxy rotation, per-domain rate limits, and scoring."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .dns_resolver import AsyncDNSResolver, DomainDNSResult
from .smtp_handshake import AsyncSMTPVerifier, SMTPVerificationResult
from .syntax_disposable import (
    is_disposable,
    is_role_based,
    suggest_domain_fix,
    validate_syntax,
)


class VerificationStatus(str, Enum):
    """Canonical verification classification."""

    VALID = "valid"
    INVALID = "invalid"
    CATCH_ALL = "catch_all"
    DISPOSABLE = "disposable"
    ROLE_BASED = "role_based"
    RISKY = "risky"
    UNKNOWN = "unknown"


@dataclass
class VerificationReport:
    """Structured output for a single email verification check."""

    email: str
    status: VerificationStatus
    confidence_score: float
    is_valid_syntax: bool
    is_disposable: bool = False
    is_role_based: bool = False
    is_catch_all: bool = False
    suggested_fix: Optional[str] = None
    mx_hosts: List[str] = field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False
    smtp_code: Optional[int] = None
    reason: str = ""
    latency_ms: float = 0.0
    proxy_used: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        """Serialize report to plain JSON-compatible dictionary."""
        return {
            "email": self.email,
            "status": self.status.value,
            "confidence_score": self.confidence_score,
            "is_valid_syntax": self.is_valid_syntax,
            "is_disposable": self.is_disposable,
            "is_role_based": self.is_role_based,
            "is_catch_all": self.is_catch_all,
            "suggested_fix": self.suggested_fix,
            "mx_hosts": list(self.mx_hosts),
            "has_spf": self.has_spf,
            "has_dmarc": self.has_dmarc,
            "smtp_code": self.smtp_code,
            "reason": self.reason,
            "latency_ms": self.latency_ms,
            "proxy_used": self.proxy_used,
        }


class ProxyRotator:
    """Thread/async-safe round-robin proxy rotator with failure cooldown backoff."""

    def __init__(self, proxies: Optional[List[str]] = None, cooldown_seconds: float = 60.0) -> None:
        self._proxies: List[str] = list(proxies or [])
        self._cooldown_seconds = cooldown_seconds
        self._unhealthy_until: Dict[str, float] = {}
        self._index = 0

    def next_proxy(self) -> Optional[str]:
        """Return next healthy proxy URL, or None if no proxies are configured/healthy."""
        if not self._proxies:
            return None
        now = time.monotonic()
        total = len(self._proxies)
        for _ in range(total):
            candidate = self._proxies[self._index % total]
            self._index += 1
            if now >= self._unhealthy_until.get(candidate, 0.0):
                return candidate
        return None

    def mark_unhealthy(self, proxy_url: str) -> None:
        """Temporarily quarantine a proxy that hit connection/greylist throttling."""
        self._unhealthy_until[proxy_url] = time.monotonic() + self._cooldown_seconds


class VerificationEngine:
    """Orchestrates syntax -> disposable -> DNS MX -> zero-send SMTP handshakes at scale."""

    def __init__(
        self,
        dns_resolver: Optional[AsyncDNSResolver] = None,
        smtp_verifier: Optional[AsyncSMTPVerifier] = None,
        proxy_rotator: Optional[ProxyRotator] = None,
        per_domain_concurrency: int = 3,
        smtp_timeout: float = 5.0,
    ) -> None:
        self.dns_resolver = dns_resolver or AsyncDNSResolver()
        self.smtp_verifier = smtp_verifier or AsyncSMTPVerifier()
        self.proxy_rotator = proxy_rotator or ProxyRotator()
        self.per_domain_concurrency = per_domain_concurrency
        self.smtp_timeout = smtp_timeout
        self._domain_semaphores: Dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self.per_domain_concurrency)
        )

    async def verify_email(self, email: str, skip_smtp: bool = False) -> VerificationReport:
        """Verify a single email through layered syntax, domain, DNS, and SMTP checks."""
        started = time.perf_counter()
        normalized = email.strip()

        is_valid, local_part, domain = validate_syntax(normalized)
        if not is_valid or not local_part or not domain:
            return VerificationReport(
                email=normalized,
                status=VerificationStatus.INVALID,
                confidence_score=0.0,
                is_valid_syntax=False,
                reason="INVALID_SYNTAX",
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        typo_fix = suggest_domain_fix(domain)
        disposable = is_disposable(domain)
        role_based = is_role_based(local_part)

        if disposable:
            return VerificationReport(
                email=f"{local_part}@{domain}",
                status=VerificationStatus.DISPOSABLE,
                confidence_score=0.1,
                is_valid_syntax=True,
                is_disposable=True,
                is_role_based=role_based,
                suggested_fix=f"{local_part}@{typo_fix}" if typo_fix else None,
                reason="DISPOSABLE_DOMAIN",
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        dns_result: DomainDNSResult = await self.dns_resolver.resolve_domain(domain)
        if not dns_result.mx_hosts:
            return VerificationReport(
                email=f"{local_part}@{domain}",
                status=VerificationStatus.INVALID,
                confidence_score=0.05,
                is_valid_syntax=True,
                is_role_based=role_based,
                suggested_fix=f"{local_part}@{typo_fix}" if typo_fix else None,
                mx_hosts=[],
                has_spf=dns_result.has_spf,
                has_dmarc=dns_result.has_dmarc,
                reason=dns_result.error or "NO_MX_HOSTS",
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        if skip_smtp:
            status = VerificationStatus.ROLE_BASED if role_based else VerificationStatus.RISKY
            score = 0.65 if role_based else 0.75
            return VerificationReport(
                email=f"{local_part}@{domain}",
                status=status,
                confidence_score=score,
                is_valid_syntax=True,
                is_role_based=role_based,
                suggested_fix=f"{local_part}@{typo_fix}" if typo_fix else None,
                mx_hosts=dns_result.mx_hosts,
                has_spf=dns_result.has_spf,
                has_dmarc=dns_result.has_dmarc,
                reason="DNS_MX_VERIFIED_SMTP_SKIPPED",
                latency_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        proxy_url = self.proxy_rotator.next_proxy()
        domain_sem = self._domain_semaphores[domain]
        async with domain_sem:
            smtp_res: SMTPVerificationResult = await self.smtp_verifier.verify_mailbox(
                email=f"{local_part}@{domain}",
                mx_host=dns_result.mx_hosts[0],
                proxy_url=proxy_url,
                timeout=self.smtp_timeout,
            )

        if smtp_res.greylisted and proxy_url:
            self.proxy_rotator.mark_unhealthy(proxy_url)

        status, score = _classify_smtp_outcome(
            smtp_res=smtp_res,
            role_based=role_based,
            has_spf=dns_result.has_spf,
            has_dmarc=dns_result.has_dmarc,
        )

        return VerificationReport(
            email=f"{local_part}@{domain}",
            status=status,
            confidence_score=score,
            is_valid_syntax=True,
            is_disposable=False,
            is_role_based=role_based,
            is_catch_all=smtp_res.is_catch_all,
            suggested_fix=f"{local_part}@{typo_fix}" if typo_fix else None,
            mx_hosts=dns_result.mx_hosts,
            has_spf=dns_result.has_spf,
            has_dmarc=dns_result.has_dmarc,
            smtp_code=smtp_res.smtp_code,
            reason=smtp_res.reason,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            proxy_used=proxy_url,
        )

    async def verify_batch(
        self,
        emails: List[str],
        concurrency: int = 50,
        skip_smtp: bool = False,
    ) -> List[VerificationReport]:
        """Verify thousands of emails concurrently using a bounded worker semaphore."""
        sem = asyncio.Semaphore(max(1, concurrency))

        async def _bounded_verify(target: str) -> VerificationReport:
            async with sem:
                return await self.verify_email(target, skip_smtp=skip_smtp)

        return await asyncio.gather(*(_bounded_verify(e) for e in emails))


def _classify_smtp_outcome(
    smtp_res: SMTPVerificationResult,
    role_based: bool,
    has_spf: bool,
    has_dmarc: bool,
) -> tuple[VerificationStatus, float]:
    """Compute canonical status and confidence score in [0.0, 1.0]."""
    auth_bonus = (0.05 if has_spf else 0.0) + (0.05 if has_dmarc else 0.0)

    if smtp_res.deliverable is False:
        return VerificationStatus.INVALID, 0.02

    if smtp_res.deliverable is True:
        if smtp_res.is_catch_all:
            return VerificationStatus.CATCH_ALL, round(min(0.65 + auth_bonus, 0.75), 2)
        if role_based:
            return VerificationStatus.ROLE_BASED, round(min(0.75 + auth_bonus, 0.85), 2)
        return VerificationStatus.VALID, round(min(0.90 + auth_bonus, 0.99), 2)

    if smtp_res.greylisted:
        return VerificationStatus.RISKY, 0.45

    return VerificationStatus.UNKNOWN, round(0.35 + auth_bonus, 2)
