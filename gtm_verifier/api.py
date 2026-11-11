"""FastAPI microservice interface for real-time and batch email verification."""

from __future__ import annotations

from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .worker_pool import VerificationEngine

app = FastAPI(
    title="GTM Email Verification Engine",
    version="0.1.0",
    description="High-throughput async email verification microservice (syntax, MX/SPF/DMARC, zero-send SMTP).",
)

_engine = VerificationEngine()


def set_engine(engine: VerificationEngine) -> None:
    """Override module-level VerificationEngine (used by tests & dependency injection)."""
    global _engine
    _engine = engine


class VerifySingleRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    skip_smtp: bool = False


class VerifyBatchRequest(BaseModel):
    emails: List[str] = Field(..., min_length=1, max_length=10000)
    concurrency: int = Field(default=50, ge=1, le=500)
    skip_smtp: bool = False


class VerificationResponse(BaseModel):
    email: str
    status: str
    confidence_score: float
    is_valid_syntax: bool
    is_disposable: bool
    is_role_based: bool
    is_catch_all: bool
    suggested_fix: Optional[str] = None
    mx_hosts: List[str]
    has_spf: bool
    has_dmarc: bool
    smtp_code: Optional[int] = None
    reason: str
    latency_ms: float
    proxy_used: Optional[str] = None


class BatchVerificationResponse(BaseModel):
    total: int
    results: List[VerificationResponse]


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "ok"}


@app.post("/v1/verify", response_model=VerificationResponse)
async def verify_single(payload: VerifySingleRequest) -> VerificationResponse:
    """Verify a single email address."""
    report = await _engine.verify_email(payload.email, skip_smtp=payload.skip_smtp)
    return VerificationResponse(**report.to_dict())


@app.post("/v1/verify-batch", response_model=BatchVerificationResponse)
async def verify_batch(payload: VerifyBatchRequest) -> BatchVerificationResponse:
    """Verify up to 10,000 emails concurrently with bounded worker semaphores."""
    reports = await _engine.verify_batch(
        payload.emails,
        concurrency=payload.concurrency,
        skip_smtp=payload.skip_smtp,
    )
    return BatchVerificationResponse(
        total=len(reports),
        results=[VerificationResponse(**r.to_dict()) for r in reports],
    )
