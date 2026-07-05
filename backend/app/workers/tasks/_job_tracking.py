"""
Lightweight helpers to track discovery task execution in scan_jobs.

All functions swallow exceptions so a tracking failure never aborts discovery.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def start_discovery_job(
    db: Any,
    tenant_id: str,
    provider: str,
    provider_key: str | None,
    regions: list[str] | None = None,
) -> str:
    """Insert a scan_job doc with status=running. Returns job_id."""
    job_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    doc = {
        "_key": job_id,
        "job_id": job_id,
        "task_name": f"discovery/{provider}",
        "tenant_id": tenant_id,
        "provider_id": provider_key or "",
        "provider": provider,
        "frameworks": [],
        "regions": regions or [],
        "status": "running",
        "checks_total": 0,
        "checks_completed": 0,
        "findings_found": 0,
        "findings_fail": 0,
        "started_at": now,
        "created_at": now,
    }
    try:
        if db.has_collection("scan_jobs"):
            db.collection("scan_jobs").insert(doc)
    except Exception:
        logger.debug("Failed to create discovery job record for tenant=%s provider=%s", tenant_id, provider)
    return job_id


def complete_discovery_job(db: Any, job_id: str, resources_discovered: int) -> None:
    """Update scan_job to status=completed with resource count."""
    try:
        if db.has_collection("scan_jobs"):
            db.collection("scan_jobs").update({
                "_key": job_id,
                "status": "completed",
                "checks_total": resources_discovered,
                "checks_completed": resources_discovered,
                "completed_at": datetime.now(UTC).isoformat(),
            })
    except Exception:
        logger.debug("Failed to complete discovery job record job_id=%s", job_id)


def fail_discovery_job(db: Any, job_id: str, error_message: str) -> None:
    """Update scan_job to status=failed with error message."""
    try:
        if db.has_collection("scan_jobs"):
            db.collection("scan_jobs").update({
                "_key": job_id,
                "status": "failed",
                "error_message": error_message[:2000],
                "completed_at": datetime.now(UTC).isoformat(),
            })
    except Exception:
        logger.debug("Failed to fail discovery job record job_id=%s", job_id)
