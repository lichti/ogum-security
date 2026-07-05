"""Admin service — cross-tenant job inspection, worker health, and queue depth."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import redis as redis_lib
from arango import ArangoClient
from arango.database import StandardDatabase

from app.core.config import settings
from app.db.init import init_admin_schema, init_tenant_schema
from app.models.admin import AdminAuditEntry, JobDetail, JobSummary, QueueDepth, WorkerInfo
from app.workers.celery_app import celery_app

_KNOWN_QUEUES = ["celery", "default", "discovery", "scanning", "iac"]


# ── Database helpers ──────────────────────────────────────────────────────────


def _arango_client() -> ArangoClient:
    return ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")


def get_system_db() -> StandardDatabase:
    client = _arango_client()
    return client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)


def get_admin_db() -> StandardDatabase:
    client = _arango_client()
    sys_db = client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
    if not sys_db.has_database("ogum_admin"):
        sys_db.create_database("ogum_admin")
    db = client.db("ogum_admin", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
    init_admin_schema(db)
    return db


def get_tenant_db_direct(tenant_id: str) -> StandardDatabase:
    client = _arango_client()
    db_name = f"ogum_{tenant_id}"
    return client.db(db_name, username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)


def _all_tenant_ids() -> list[str]:
    sys_db = get_system_db()
    return [
        db_name[len("ogum_") :]
        for db_name in sys_db.databases()
        if db_name.startswith("ogum_") and db_name != "ogum_admin"
    ]


# ── Job helpers ───────────────────────────────────────────────────────────────


def _doc_to_job_summary(doc: dict[str, Any]) -> JobSummary:
    return JobSummary(
        job_id=doc.get("job_id", doc.get("_key", "")),
        task_name=doc.get("task_name", f"cspm_scan/{doc.get('provider', '')}"),
        tenant_id=doc.get("tenant_id", ""),
        status=doc.get("status", ""),
        created_at=doc.get("created_at"),
        started_at=doc.get("started_at"),
        completed_at=doc.get("completed_at"),
        retries=doc.get("retries", 0),
        worker=doc.get("worker"),
        provider=doc.get("provider"),
        provider_id=doc.get("provider_id"),
    )


def _doc_to_job_detail(doc: dict[str, Any]) -> JobDetail:
    return JobDetail(
        job_id=doc.get("job_id", doc.get("_key", "")),
        task_name=doc.get("task_name", f"cspm_scan/{doc.get('provider', '')}"),
        tenant_id=doc.get("tenant_id", ""),
        status=doc.get("status", ""),
        created_at=doc.get("created_at"),
        started_at=doc.get("started_at"),
        completed_at=doc.get("completed_at"),
        retries=doc.get("retries", 0),
        worker=doc.get("worker"),
        provider=doc.get("provider"),
        provider_id=doc.get("provider_id"),
        result=None,
        traceback=None,
        logs=doc.get("logs", []),
        error_message=doc.get("error_message"),
        findings_found=doc.get("findings_found"),
        findings_fail=doc.get("findings_fail"),
        checks_total=doc.get("checks_total"),
        checks_completed=doc.get("checks_completed"),
    )


# ── Public API ────────────────────────────────────────────────────────────────


def list_jobs(
    tenant_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    """List scan jobs across all tenants or scoped to one tenant."""
    target_tenants = [tenant_id] if tenant_id else _all_tenant_ids()

    status_filter = "FILTER j.status == @status" if status else ""
    cursor_filter = "FILTER j.created_at < @cursor" if cursor else ""
    bind_vars: dict[str, Any] = {"limit": limit}
    if status:
        bind_vars["status"] = status
    if cursor:
        bind_vars["cursor"] = cursor

    aql = f"""
        FOR j IN scan_jobs
            {status_filter}
            {cursor_filter}
            SORT j.created_at DESC
            LIMIT @limit
            RETURN j
    """

    items: list[JobSummary] = []
    for tid in target_tenants:
        try:
            db = get_tenant_db_direct(tid)
            if not db.has_collection("scan_jobs"):
                init_tenant_schema(db)
            result = db.aql.execute(aql, bind_vars=bind_vars)
            items.extend(_doc_to_job_summary(doc) for doc in result)
        except Exception:
            continue

    items.sort(key=lambda j: j.created_at or datetime.min.replace(tzinfo=UTC), reverse=True)
    items = items[:limit]

    next_cursor = items[-1].created_at.isoformat() if items and len(items) == limit else None
    return {"items": items, "next_cursor": next_cursor}


def get_job(job_id: str, tenant_id: str) -> JobDetail | None:
    """Fetch a single job detail from a specific tenant's database."""
    try:
        db = get_tenant_db_direct(tenant_id)
        doc = db.collection("scan_jobs").get(job_id)
        if doc is None:
            return None
        return _doc_to_job_detail(doc)
    except Exception:
        return None


def retry_job(job_id: str, tenant_id: str, actor_email: str) -> str | None:
    """Re-enqueue a failed job. Returns the new job_id or None if original not found."""
    from app.workers.tasks.cspm_scan import run_cspm_scan

    job = get_job(job_id, tenant_id)
    if job is None:
        return None

    task = run_cspm_scan.delay(
        tenant_id=tenant_id,
        provider_id=job.provider_id or "",
        provider=job.provider or "",
        frameworks=[],
        credentials={},
        account_id="",
    )

    _write_audit_log(
        action="job.retry",
        actor_email=actor_email,
        target_type="scan_job",
        target_id=job_id,
        before_state={"job_id": job_id, "status": job.status},
        after_state={"new_job_id": task.id},
        tenant_id=tenant_id,
    )

    return task.id


def revoke_job(job_id: str, tenant_id: str, actor_email: str) -> bool:
    """Cancel a queued or running job via Celery revoke."""
    celery_app.control.revoke(job_id, terminate=False)

    _write_audit_log(
        action="job.revoke",
        actor_email=actor_email,
        target_type="scan_job",
        target_id=job_id,
        before_state={"job_id": job_id},
        after_state={"revoked": True},
        tenant_id=tenant_id,
    )

    return True


def get_workers() -> list[WorkerInfo]:
    """Return info about active Celery workers."""
    try:
        inspector = celery_app.control.inspect(timeout=3.0)
        active = inspector.active() or {}
        stats = inspector.stats() or {}
    except Exception:
        return []

    workers: list[WorkerInfo] = []
    all_hosts = set(active.keys()) | set(stats.keys())
    for hostname in all_hosts:
        host_active = active.get(hostname, [])
        host_stats = stats.get(hostname, {})
        total_tasks = host_stats.get("total", {})
        processed = sum(total_tasks.values()) if isinstance(total_tasks, dict) else 0
        clock = host_stats.get("clock", None)
        workers.append(
            WorkerInfo(
                hostname=hostname,
                status="online",
                active_tasks=len(host_active),
                processed=processed,
                uptime_seconds=float(clock) if clock is not None else None,
            )
        )

    return workers


def get_queue_depths() -> list[QueueDepth]:
    """Return the number of pending messages in each known Celery queue."""
    try:
        r = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
        return [QueueDepth(queue=q, depth=r.llen(q)) for q in _KNOWN_QUEUES]
    except Exception:
        return [QueueDepth(queue=q, depth=0) for q in _KNOWN_QUEUES]


# ── Internal ──────────────────────────────────────────────────────────────────


def _write_audit_log(
    action: str,
    actor_email: str,
    target_type: str,
    target_id: str,
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    tenant_id: str = "",
) -> None:
    try:
        db = get_admin_db()
        entry = AdminAuditEntry(
            action=action,
            actor_id=actor_email,
            actor_email=actor_email,
            target_type=target_type,
            target_id=target_id,
            before_state=before_state,
            after_state=after_state,
            timestamp=datetime.now(UTC),
        )
        doc = entry.model_dump(mode="json")
        doc["tenant_id"] = tenant_id
        db.collection("admin_audit_log").insert(doc)
    except Exception:
        pass
