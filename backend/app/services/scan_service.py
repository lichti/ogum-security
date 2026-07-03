"""Business logic for CSPM scan jobs."""

from __future__ import annotations

from arango.database import StandardDatabase

from app.models.finding import ScanJob


def get_scan_job(db: StandardDatabase, job_id: str) -> ScanJob | None:
    try:
        doc = db.collection("scan_jobs").get(job_id)
        if doc is None:
            return None
        return ScanJob(**{k: v for k, v in doc.items() if not k.startswith("_")})
    except Exception:
        return None


def list_scan_jobs(db: StandardDatabase, tenant_id: str, limit: int = 20) -> list[ScanJob]:
    cursor = db.aql.execute(
        """
        FOR j IN scan_jobs
            FILTER j.tenant_id == @tenant_id
            SORT j.created_at DESC
            LIMIT @limit
            RETURN j
        """,
        bind_vars={"tenant_id": tenant_id, "limit": limit},
    )
    return [ScanJob(**{k: v for k, v in doc.items() if not k.startswith("_")}) for doc in cursor]
