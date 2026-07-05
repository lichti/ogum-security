"""Pydantic models for the Admin API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AdminJobStatus(StrEnum):
    PENDING = "PENDING"
    STARTED = "STARTED"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    RETRY = "RETRY"
    REVOKED = "REVOKED"
    # Ogum-specific statuses stored in scan_jobs
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobSummary(BaseModel):
    job_id: str
    task_name: str
    tenant_id: str
    status: str
    created_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    retries: int = 0
    worker: str | None = None
    provider: str | None = None
    provider_id: str | None = None


class JobDetail(JobSummary):
    args: list[Any] | None = None
    kwargs: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    traceback: str | None = None
    logs: list[str] = Field(default_factory=list)
    error_message: str | None = None
    findings_found: int | None = None
    findings_fail: int | None = None
    checks_total: int | None = None
    checks_completed: int | None = None


class RetryRequest(BaseModel):
    actor_email: str
    tenant_id: str


class WorkerInfo(BaseModel):
    hostname: str
    status: str
    active_tasks: int = 0
    processed: int = 0
    uptime_seconds: float | None = None


class QueueDepth(BaseModel):
    queue: str
    depth: int


class AdminAuditEntry(BaseModel):
    action: str
    actor_id: str
    actor_email: str
    target_type: str
    target_id: str
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    timestamp: datetime
