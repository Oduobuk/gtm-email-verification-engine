"""CLI runner for high-throughput batch CSV/TXT email verification."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
from pathlib import Path
from typing import List, Optional

from .worker_pool import ProxyRotator, VerificationEngine


def _load_emails(input_path: Path) -> List[str]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        emails: List[str] = []
        with input_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames and "email" in {f.strip().lower() for f in reader.fieldnames}:
                key = next(f for f in reader.fieldnames if f.strip().lower() == "email")
                for row in reader:
                    val = (row.get(key) or "").strip()
                    if val:
                        emails.append(val)
            else:
                fh.seek(0)
                for row in csv.reader(fh):
                    if row and row[0].strip():
                        emails.append(row[0].strip())
        return emails

    with input_path.open("r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]


async def _run(args: argparse.Namespace) -> int:
    proxies = [p.strip() for p in args.proxies.split(",") if p.strip()] if args.proxies else []
    engine = VerificationEngine(proxy_rotator=ProxyRotator(proxies=proxies))
    emails = _load_emails(Path(args.input))
    reports = await engine.verify_batch(
        emails,
        concurrency=args.concurrency,
        skip_smtp=args.skip_smtp,
    )

    rows = [r.to_dict() for r in reports]
    if args.output:
        out_path = Path(args.output)
        if out_path.suffix.lower() == ".csv":
            fieldnames = list(rows[0].keys()) if rows else []
            with out_path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        else:
            out_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    else:
        print(json.dumps(rows, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GTM Async Email Verification CLI")
    parser.add_argument("--input", required=True, help="Path to .txt or .csv list of email addresses")
    parser.add_argument("--output", default=None, help="Output file (.json or .csv). Defaults to stdout JSON.")
    parser.add_argument("--concurrency", type=int, default=50, help="Worker pool concurrency")
    parser.add_argument("--skip-smtp", action="store_true", help="Run syntax + disposable + DNS MX checks only")
    parser.add_argument("--proxies", default="", help="Comma-separated SOCKS5/HTTP proxy URLs")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
