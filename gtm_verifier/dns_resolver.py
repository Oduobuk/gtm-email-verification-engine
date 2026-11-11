"""Asynchronous DNS resolver with TTL caching for MX, SPF, and DMARC checks."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver


@dataclass(frozen=True)
class DomainDNSResult:
    """Immutable DNS inspection result for a target domain."""

    domain: str
    mx_hosts: List[str] = field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False
    error: Optional[str] = None
    cached: bool = False


class AsyncDNSResolver:
    """High-throughput async DNS resolver with per-domain TTL memoization."""

    def __init__(
        self,
        ttl_seconds: int = 3600,
        timeout: float = 3.0,
        nameservers: Optional[List[str]] = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.timeout = timeout
        self._cache: Dict[str, Tuple[float, DomainDNSResult]] = {}
        self._inflight: Dict[str, asyncio.Future[DomainDNSResult]] = {}

        self._resolver = dns.asyncresolver.Resolver(configure=True)
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    def clear_cache(self) -> None:
        """Clear all cached DNS records."""
        self._cache.clear()

    async def resolve_domain(self, domain: str) -> DomainDNSResult:
        """Resolve MX, SPF, and DMARC records for a domain with TTL caching & single-flight dedup."""
        normalized = domain.strip().lower()
        now = time.monotonic()

        cached_entry = self._cache.get(normalized)
        if cached_entry is not None:
            expires_at, result = cached_entry
            if now < expires_at:
                return DomainDNSResult(
                    domain=result.domain,
                    mx_hosts=list(result.mx_hosts),
                    has_spf=result.has_spf,
                    has_dmarc=result.has_dmarc,
                    error=result.error,
                    cached=True,
                )

        # Single-flight deduplication prevents thundering-herd DNS lookups on batch domains
        if normalized in self._inflight:
            return await self._inflight[normalized]

        loop = asyncio.get_running_loop()
        future: asyncio.Future[DomainDNSResult] = loop.create_future()
        self._inflight[normalized] = future

        try:
            result = await self._lookup_records(normalized)
            self._cache[normalized] = (time.monotonic() + self.ttl_seconds, result)
            if not future.done():
                future.set_result(result)
            return result
        except Exception as exc:  # pragma: no cover - defensive fallback
            fallback = DomainDNSResult(domain=normalized, error=str(exc))
            if not future.done():
                future.set_result(fallback)
            return fallback
        finally:
            self._inflight.pop(normalized, None)

    async def _lookup_records(self, domain: str) -> DomainDNSResult:
        mx_task = self._query_mx(domain)
        spf_task = self._query_spf(domain)
        dmarc_task = self._query_dmarc(domain)

        mx_hosts, mx_error = await mx_task
        has_spf, has_dmarc = await asyncio.gather(spf_task, dmarc_task)

        return DomainDNSResult(
            domain=domain,
            mx_hosts=mx_hosts,
            has_spf=has_spf,
            has_dmarc=has_dmarc,
            error=mx_error,
            cached=False,
        )

    async def _query_mx(self, domain: str) -> Tuple[List[str], Optional[str]]:
        try:
            answers = await self._resolver.resolve(domain, "MX")
            sorted_records = sorted(answers, key=lambda r: int(r.preference))
            hosts = [str(r.exchange).rstrip(".").lower() for r in sorted_records if str(r.exchange).rstrip(".")]
            return hosts, None
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return [], "NO_MX_RECORD"
        except dns.exception.Timeout:
            return [], "DNS_TIMEOUT"
        except Exception as exc:
            return [], f"DNS_ERROR:{type(exc).__name__}"

    async def _query_spf(self, domain: str) -> bool:
        try:
            answers = await self._resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in getattr(rdata, "strings", [str(rdata)])
                ).lower()
                if txt.startswith("v=spf1"):
                    return True
            return False
        except Exception:
            return False

    async def _query_dmarc(self, domain: str) -> bool:
        try:
            answers = await self._resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in getattr(rdata, "strings", [str(rdata)])
                ).lower()
                if "v=dmarc1" in txt:
                    return True
            return False
        except Exception:
            return False
