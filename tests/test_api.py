"""API & VerificationEngine end-to-end tests using FastAPI TestClient."""

from fastapi.testclient import TestClient

from gtm_verifier.api import app, set_engine
from gtm_verifier.dns_resolver import AsyncDNSResolver, DomainDNSResult
from gtm_verifier.smtp_handshake import AsyncSMTPVerifier, SMTPVerificationResult
from gtm_verifier.worker_pool import ProxyRotator, VerificationEngine


class _MockDNS(AsyncDNSResolver):
    async def resolve_domain(self, domain: str) -> DomainDNSResult:
        if domain == "dead-domain.invalid":
            return DomainDNSResult(domain=domain, mx_hosts=[], error="NXDOMAIN")
        return DomainDNSResult(
            domain=domain,
            mx_hosts=["mx.mock.internal"],
            has_spf=True,
            has_dmarc=True,
        )


class _MockSMTP(AsyncSMTPVerifier):
    async def verify_mailbox(self, email: str, mx_host: str, proxy_url=None, timeout: float = 5.0, check_catch_all: bool = True):
        if email.startswith("catchall"):
            return SMTPVerificationResult(deliverable=True, is_catch_all=True, smtp_code=250, reason="CATCH_ALL_ACCEPTED")
        if email.startswith("greylist"):
            return SMTPVerificationResult(deliverable=None, greylisted=True, smtp_code=450, reason="TEMP_FAIL_GREYLIST")
        if email.startswith("bounce"):
            return SMTPVerificationResult(deliverable=False, smtp_code=550, reason="MAILBOX_REJECTED")
        return SMTPVerificationResult(deliverable=True, is_catch_all=False, smtp_code=250, reason="MAILBOX_EXISTS")


def test_api_health_and_verification_endpoints() -> None:
    rotator = ProxyRotator(proxies=["socks5://10.0.0.1:1080", "socks5://10.0.0.2:1080"])
    set_engine(
        VerificationEngine(
            dns_resolver=_MockDNS(),
            smtp_verifier=_MockSMTP(),
            proxy_rotator=rotator,
        )
    )
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok"}

    single = client.post("/v1/verify", json={"email": "founder@acme.com"}).json()
    assert single["status"] == "valid"
    assert single["confidence_score"] == 0.99
    assert single["proxy_used"] == "socks5://10.0.0.1:1080"

    batch = client.post(
        "/v1/verify-batch",
        json={
            "emails": [
                "support@acme.com",
                "junk@mailinator.com",
                "bounce@acme.com",
                "catchall@acme.com",
                "nope@dead-domain.invalid",
            ],
            "concurrency": 10,
        },
    ).json()

    assert batch["total"] == 5
    statuses = [item["status"] for item in batch["results"]]
    assert statuses == ["role_based", "disposable", "invalid", "catch_all", "invalid"]
