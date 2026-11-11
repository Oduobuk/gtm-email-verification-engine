# GTM Email Verification Engine

High-throughput asynchronous email verification microservice and CLI built for high-volume outbound GTM infrastructure (1M+ address pipelines). Performs layered RFC syntax & typo checks, disposable/role filtering, cached async DNS MX/SPF/DMARC resolution, zero-send raw TCP SMTP `RCPT TO` handshakes, catch-all probing, and proxy-rotated worker pools.

## Architecture Overview

```text
  Email Batch ──▶ [Worker Pool & Per-Domain Semaphores]
                        │
                        ├── 1. Syntax / Typo / Disposable / Role Filter
                        │
                        ├── 2. Async DNS Resolver (TTL Cache + Single-Flight)
                        │      └─ MX priority sort + SPF + DMARC TXT records
                        │
                        └── 3. Zero-Send Raw TCP SMTP Handshake
                               ├─ ProxyRotator (Direct / SOCKS5 / HTTP CONNECT)
                               ├─ EHLO -> MAIL FROM -> RCPT TO -> QUIT (no DATA)
                               └─ Randomized Catch-All Probe + Greylist Backoff
```

## Key Features

- **Zero-Send SMTP Verification (`gtm_verifier/smtp_handshake.py`)**: Raw `asyncio` socket dialogue executing `EHLO` -> `MAIL FROM` -> `RCPT TO` -> `QUIT` without dispatching any email payload.
- **Catch-All Detection**: Sends a secondary random `RCPT TO` (`catchall_probe_<hex>@domain`) on the same SMTP session to detect domains that accept arbitrary addresses.
- **Single-Flight TTL DNS Cache (`gtm_verifier/dns_resolver.py`)**: Deduplicates concurrent MX, SPF, and DMARC queries across thousands of shared-domain leads.
- **Proxy Rotation & Per-Domain Rate Limiting (`gtm_verifier/worker_pool.py`)**: Round-robin SOCKS5/HTTP CONNECT tunnel rotation with automatic greylist cooldown and per-domain concurrency semaphores.
- **FastAPI Microservice & Batch CLI**: Ready for containerized deployment (`Dockerfile`) or direct CSV/TXT batch pipelines.

## Quick Start

```bash
pip install -e ".[dev]"

# Run unit & loopback SMTP integration tests
make test

# Run 1,000-email async throughput benchmark
make benchmark

# Verify a CSV list via CLI (DNS + syntax mode)
python3 -m gtm_verifier.cli --input leads.csv --output verified.json --skip-smtp

# Start FastAPI server
make serve
```

## API Endpoints

- `GET /health` — Service liveness probe
- `POST /v1/verify` — Verify a single email (`{"email": "alex@acme.com", "skip_smtp": false}`)
- `POST /v1/verify-batch` — Verify up to 10,000 emails concurrently (`{"emails": [...], "concurrency": 100}`)
