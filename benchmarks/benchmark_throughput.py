"""Throughput benchmark for GTM Async Email Verification Engine using a local loopback SMTP server."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gtm_verifier.dns_resolver import AsyncDNSResolver, DomainDNSResult
from gtm_verifier.smtp_handshake import AsyncSMTPVerifier
from gtm_verifier.worker_pool import ProxyRotator, VerificationEngine


class _FastStubDNSResolver(AsyncDNSResolver):
    """Cached DNS stub simulating populated MX/SPF/DMARC lookup latency."""

    async def resolve_domain(self, domain: str) -> DomainDNSResult:
        return DomainDNSResult(
            domain=domain,
            mx_hosts=["127.0.0.1"],
            has_spf=True,
            has_dmarc=True,
            cached=True,
        )


async def _handle_smtp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(b"220 bench-mx.internal ESMTP Ready\r\n")
    await writer.drain()
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break
            cmd = raw.decode("utf-8", errors="ignore").strip()
            upper = cmd.upper()
            if upper.startswith(("EHLO", "HELO")):
                writer.write(b"250-bench-mx.internal\r\n250 OK\r\n")
            elif upper.startswith("MAIL FROM"):
                writer.write(b"250 2.1.0 Originator OK\r\n")
            elif upper.startswith("RCPT TO"):
                if "catchall_probe_" in cmd:
                    writer.write(b"550 5.1.1 User unknown\r\n")
                elif "bounce" in cmd:
                    writer.write(b"550 5.1.1 Mailbox unavailable\r\n")
                else:
                    writer.write(b"250 2.1.5 Recipient OK\r\n")
            elif upper.startswith("QUIT"):
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 OK\r\n")
            await writer.drain()
    finally:
        writer.close()


async def run_benchmark(total_emails: int = 1000, concurrency: int = 100) -> None:
    server = await asyncio.start_server(_handle_smtp_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    emails = []
    for i in range(total_emails):
        if i % 20 == 0:
            emails.append(f"bad..email{i}@acme.com")
        elif i % 15 == 0:
            emails.append(f"temp{i}@mailinator.com")
        elif i % 10 == 0:
            emails.append(f"bounce{i}@corp-{i % 25}.com")
        else:
            emails.append(f"lead{i}@corp-{i % 25}.com")

    engine = VerificationEngine(
        dns_resolver=_FastStubDNSResolver(),
        smtp_verifier=AsyncSMTPVerifier(smtp_port=port),
        proxy_rotator=ProxyRotator(),
        per_domain_concurrency=10,
    )

    try:
        started = time.perf_counter()
        reports = await engine.verify_batch(emails, concurrency=concurrency)
        elapsed = time.perf_counter() - started
        throughput = len(reports) / elapsed
        valid_count = sum(1 for r in reports if r.status.value == "valid")
        invalid_count = sum(1 for r in reports if r.status.value == "invalid")
        disposable_count = sum(1 for r in reports if r.status.value == "disposable")

        print("=== GTM Email Verification Throughput Benchmark ===")
        print(f"Total Emails   : {len(reports)}")
        print(f"Concurrency    : {concurrency}")
        print(f"Elapsed Time   : {elapsed:.3f}s")
        print(f"Throughput     : {throughput:.1f} emails/sec")
        print(f"Valid          : {valid_count}")
        print(f"Invalid        : {invalid_count}")
        print(f"Disposable     : {disposable_count}")
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(run_benchmark())
