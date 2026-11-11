"""Real-world batch email dataset check against live DNS (plus optional port-25 probe)."""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gtm_verifier import AsyncDNSResolver, VerificationEngine

REAL_TEST_LEADS = [
    # Major consumer & enterprise B2B domains (live MX + SPF + DMARC lookup)
    "founder@stripe.com",
    "engineering@github.com",
    "team@anthropic.com",
    "support@cloudflare.com",
    "officialoduobuk@gmail.com",
    "alex.mercer@outlook.com",
    "contact@shopify.com",
    "hello@vercel.com",
    "sales@hubspot.com",
    "info@linear.app",
    # Duplicates testing single-flight + TTL DNS caching speed
    "billing@stripe.com",
    "security@github.com",
    "press@cloudflare.com",
    "leads@shopify.com",
    # Typos & malformed syntax
    "david@gmial.com",
    "sarah@outlok.com",
    "bad..syntax@stripe.com",
    "missing-at.com",
    "user@-invalidhost.com",
    # Disposable / burner domains
    "throwaway@mailinator.com",
    "temp123@yopmail.com",
    "test@10minutemail.com",
    # Non-existent NXDOMAIN domains
    "ceo@nonexistent-gtm-domain-99182736.com",
    "founder@dead-startup-0009182.io",
]


def _is_port_25_reachable(timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection(("gmail-smtp-in.l.google.com", 25), timeout=timeout):
            return True
    except OSError:
        return False


async def run_real_domain_check(force_smtp: bool = False) -> None:
    smtp_available = force_smtp or _is_port_25_reachable()
    skip_smtp = not smtp_available

    engine = VerificationEngine(dns_resolver=AsyncDNSResolver(timeout=5.0))
    started = time.perf_counter()
    reports = await engine.verify_batch(REAL_TEST_LEADS, concurrency=20, skip_smtp=skip_smtp)
    elapsed = time.perf_counter() - started

    counts = Counter(r.status.value for r in reports)
    print("=== Real-World GTM Dataset Verification ===")
    print(f"Network Mode : {'LIVE DNS + LIVE SMTP (port 25)' if not skip_smtp else 'LIVE DNS ONLY (outbound port 25 blocked by local ISP/network)'}")
    print(f"Total Leads  : {len(reports)}")
    print(f"Elapsed      : {elapsed:.2f}s")
    print(f"Breakdown    : {dict(counts)}\n")

    for r in reports:
        mx_preview = r.mx_hosts[0] if r.mx_hosts else "-"
        fix_note = f" | suggest={r.suggested_fix}" if r.suggested_fix else ""
        print(
            f"{r.email:<42} | {r.status.value:<11} | SPF={str(r.has_spf):<5} | DMARC={str(r.has_dmarc):<5} "
            f"| MX={mx_preview:<32} | {r.latency_ms:>7.1f}ms | {r.reason}{fix_note}"
        )


if __name__ == "__main__":
    run_smtp = "--live-smtp" in sys.argv
    asyncio.run(run_real_domain_check(force_smtp=run_smtp))
