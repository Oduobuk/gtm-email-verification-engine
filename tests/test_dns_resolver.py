"""Unit tests for AsyncDNSResolver caching and single-flight deduplication."""

import asyncio
from dataclasses import dataclass

from gtm_verifier.dns_resolver import AsyncDNSResolver


@dataclass
class _FakeMX:
    preference: int
    exchange: str


@dataclass
class _FakeTXT:
    strings: list[bytes]


class _CountingFakeDNSBackend:
    def __init__(self) -> None:
        self.calls: dict[tuple[str, str], int] = {}

    async def resolve(self, qname: str, rdtype: str):
        key = (qname, rdtype)
        self.calls[key] = self.calls.get(key, 0) + 1
        await asyncio.sleep(0.01)
        if rdtype == "MX" and qname == "acme.com":
            return [_FakeMX(20, "mx2.acme.com."), _FakeMX(10, "mx1.acme.com.")]
        if rdtype == "TXT" and qname == "acme.com":
            return [_FakeTXT([b"v=spf1 include:_spf.acme.com ~all"])]
        if rdtype == "TXT" and qname == "_dmarc.acme.com":
            return [_FakeTXT([b"v=DMARC1; p=reject"])]
        raise RuntimeError("NXDOMAIN")


def test_dns_resolver_sorts_mx_parses_spf_dmarc_and_caches() -> None:
    async def _run() -> None:
        resolver = AsyncDNSResolver(ttl_seconds=60)
        fake_backend = _CountingFakeDNSBackend()
        resolver._resolver = fake_backend  # type: ignore[assignment]

        first, second = await asyncio.gather(
            resolver.resolve_domain("ACME.com"),
            resolver.resolve_domain("acme.com"),
        )

        assert first.mx_hosts == ["mx1.acme.com", "mx2.acme.com"]
        assert first.has_spf is True
        assert first.has_dmarc is True
        assert fake_backend.calls[("acme.com", "MX")] == 1
        assert second.mx_hosts == ["mx1.acme.com", "mx2.acme.com"]

        third = await resolver.resolve_domain("acme.com")
        assert third.cached is True
        assert fake_backend.calls[("acme.com", "MX")] == 1

    asyncio.run(_run())
