"""Business logic for CSPM scan jobs."""

from __future__ import annotations

import base64
import json
from typing import Any

from arango.database import StandardDatabase

from app.models.finding import ScanJob


def _encode_cursor(created_at: str, key: str) -> str:
    payload = json.dumps({"created_at": created_at, "_key": key})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _decode_cursor(cursor: str) -> dict[str, str] | None:
    try:
        result = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return result if isinstance(result, dict) else None
    except Exception:
        return None


def _is_cspm_job(doc: dict[str, Any]) -> bool:
    """`scan_jobs` is shared with side-scanning (`task_name` "side_scan/*", no
    `frameworks` field — a different document shape entirely, already surfaced
    on its own Side Scanning page). The Scans page (US-14.23) is CSPM-only."""
    return str(doc.get("task_name") or "").startswith("cspm_scan/")


def get_scan_job(db: StandardDatabase, job_id: str) -> ScanJob | None:
    try:
        doc = db.collection("scan_jobs").get(job_id)
        if doc is None or not _is_cspm_job(doc):
            return None
        return ScanJob(**{k: v for k, v in doc.items() if not k.startswith("_")})
    except Exception:
        return None


def get_scan_job_logs(db: StandardDatabase, job_id: str) -> list[str] | None:
    """Raw log lines captured by JobLogHandler during the run, or None if the
    job doesn't exist. A job still running/queued simply has an empty list —
    `flush_to_db` only writes once the task's `finally` block runs."""
    try:
        doc = db.collection("scan_jobs").get(job_id)
        if doc is None or not _is_cspm_job(doc):
            return None
        return doc.get("logs", [])
    except Exception:
        return None


def list_scan_jobs(
    db: StandardDatabase,
    tenant_id: str,
    *,
    status: list[str] | None = None,
    provider_id: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> tuple[list[ScanJob], str | None]:
    """Return (jobs, next_cursor). Keyset pagination on (created_at DESC, _key DESC).

    CSPM-only (see `_is_cspm_job`) — side-scan jobs sharing this collection are
    filtered out in AQL, not just in the Python validation step, so they don't
    silently eat a page slot without appearing in the result.
    """
    filters = ["j.tenant_id == @tenant_id", 'STARTS_WITH(j.task_name, "cspm_scan/")']
    bind: dict[str, Any] = {"tenant_id": tenant_id, "fetch_limit": limit + 1}

    if status:
        filters.append("j.status IN @status")
        bind["status"] = status
    if provider_id:
        filters.append("j.provider_id == @provider_id")
        bind["provider_id"] = provider_id

    cursor_clause = ""
    if cursor:
        c = _decode_cursor(cursor)
        if c:
            cursor_clause = "FILTER (j.created_at < @cur_date) OR (j.created_at == @cur_date AND j._key < @cur_key)"
            bind["cur_date"] = c["created_at"]
            bind["cur_key"] = c["_key"]

    filter_block = "\n            ".join(f"FILTER {f}" for f in filters)

    aql = f"""
        FOR j IN scan_jobs
            {filter_block}
            {cursor_clause}
            SORT j.created_at DESC, j._key DESC
            LIMIT @fetch_limit
            RETURN j
    """
    rows = list(db.aql.execute(aql, bind_vars=bind))

    next_cursor: str | None = None
    if len(rows) == limit + 1:
        last = rows[limit - 1]
        next_cursor = _encode_cursor(last["created_at"], last["_key"])
        rows = rows[:limit]

    jobs = [ScanJob(**{k: v for k, v in doc.items() if not k.startswith("_")}) for doc in rows]
    return jobs, next_cursor
