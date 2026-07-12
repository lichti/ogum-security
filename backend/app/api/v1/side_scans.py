"""Side-scanning API — K8s DaemonSet webhook, ECR webhook, jobs management, manual trigger."""

from __future__ import annotations

import time
from typing import Any

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from app.api.v1.inventory import get_tenant_db
from app.services.provider_service import _make_key, get_provider, get_provider_credentials
from app.services.side_scanning.trigger import SCANNABLE_RESOURCE_TYPES, enqueue_side_scan
from app.workers.tasks.side_scanning import scan_container_image, scan_k8s_container

router = APIRouter(prefix="/api/v1/side-scans", tags=["side-scans"])


# ─── Token validation ─────────────────────────────────────────────────────────


def _validate_scanner_token(db: StandardDatabase, tenant_id: str, token: str) -> None:
    """Raise 401 if the scanner token does not match tenant_config."""
    try:
        cursor = db.aql.execute(
            "FOR c IN tenant_config FILTER c.tenant_id == @tid LIMIT 1 RETURN c",
            bind_vars={"tid": tenant_id},
        )
        docs = list(cursor)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not docs:
        raise HTTPException(status_code=401, detail="Unauthorized")

    expected: str | None = docs[0].get("scanner_token")
    if not expected or expected != token:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ─── K8s DaemonSet webhook ───────────────────────────────────────────────────


class K8sScanWebhookPayload(BaseModel):
    pod_name: str
    pod_namespace: str
    container_name: str
    pid: int
    node_name: str
    resource_id: str
    provider_id: str
    job_id: str | None = None


@router.post("/webhooks/k8s-scan", status_code=202)
async def receive_k8s_scan_trigger(
    payload: K8sScanWebhookPayload,
    x_ogum_tenant_id: str = Header(...),
    x_ogum_token: str = Header(...),
    db: StandardDatabase = Depends(get_tenant_db),
) -> dict:
    """
    Receive a scan trigger from the ogum-scanner DaemonSet.
    Validates scanner token, enqueues scan_k8s_container task, returns 202.
    """
    _validate_scanner_token(db, x_ogum_tenant_id, x_ogum_token)

    job_id = payload.job_id or f"k8s-{payload.pod_namespace}-{payload.pod_name}-{int(time.time())}"

    job_doc = {
        "_key": job_id,
        "tenant_id": x_ogum_tenant_id,
        "type": "k8s_container",
        "status": "queued",
        "resource_id": payload.resource_id,
        "pod_name": payload.pod_name,
        "pod_namespace": payload.pod_namespace,
        "container_name": payload.container_name,
        "node_name": payload.node_name,
        "created_at": str(int(time.time())),
    }
    try:
        if not db.collection("scan_jobs").has(job_id):
            db.collection("scan_jobs").insert(job_doc)
    except Exception:
        pass  # key collision acceptable

    scan_k8s_container.delay(
        tenant_id=x_ogum_tenant_id,
        pod_name=payload.pod_name,
        pod_namespace=payload.pod_namespace,
        container_name=payload.container_name,
        pid=payload.pid,
        node_name=payload.node_name,
        resource_id=payload.resource_id,
        provider_id=payload.provider_id,
        job_id=job_id,
    )

    return {"job_id": job_id, "status": "queued"}


# ─── ECR push webhook ─────────────────────────────────────────────────────────


class ECRWebhookPayload(BaseModel):
    image_uri: str
    image_digest: str
    repository_name: str
    registry_id: str
    provider_id: str
    job_id: str | None = None


@router.post("/webhooks/ecr", status_code=202)
async def receive_ecr_push_event(
    payload: ECRWebhookPayload,
    x_ogum_tenant_id: str = Header(...),
    x_ogum_token: str = Header(...),
    db: StandardDatabase = Depends(get_tenant_db),
) -> dict:
    """Receive an ECR push event, enqueue scan_container_image. Returns 202 Accepted."""
    _validate_scanner_token(db, x_ogum_tenant_id, x_ogum_token)

    job_id = payload.job_id or f"ecr-{payload.registry_id}-{int(time.time())}"

    job_doc = {
        "_key": job_id,
        "tenant_id": x_ogum_tenant_id,
        "type": "ecr",
        "status": "queued",
        "image_uri": payload.image_uri,
        "image_digest": payload.image_digest,
        "repository_name": payload.repository_name,
        "registry_id": payload.registry_id,
        "provider_id": payload.provider_id,
        "created_at": str(int(time.time())),
    }
    try:
        if not db.collection("scan_jobs").has(job_id):
            db.collection("scan_jobs").insert(job_doc)
    except Exception:
        pass

    scan_container_image.delay(
        tenant_id=x_ogum_tenant_id,
        image_uri=payload.image_uri,
        image_digest=payload.image_digest,
        provider_id=payload.provider_id,
        job_id=job_id,
    )

    return {"job_id": job_id, "status": "queued"}


# ─── Manual scan trigger (Inventory "Scan Now") ──────────────────────────────


class TriggerScanRequest(BaseModel):
    resource_key: str


@router.post("/trigger", status_code=202)
async def trigger_resource_scan(
    body: TriggerScanRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """Manually trigger a side-scan for an EC2 instance or Lambda function resource."""
    try:
        raw = db.collection("resources").get(body.resource_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to retrieve resource")

    resource_doc: dict[str, Any] = raw if isinstance(raw, dict) else {}
    if not resource_doc or resource_doc.get("tenant_id") != x_tenant_id:
        raise HTTPException(status_code=404, detail="Resource not found")

    if resource_doc.get("resource_type") not in SCANNABLE_RESOURCE_TYPES:
        raise HTTPException(status_code=422, detail="Resource type is not scannable via side-scanning")
    if resource_doc.get("status") == "deleted":
        raise HTTPException(status_code=422, detail="Resource is deleted")

    provider_id = _make_key(resource_doc.get("provider", ""), resource_doc.get("account_id", ""))
    provider = get_provider(db, provider_id)
    if provider is None:
        raise HTTPException(status_code=400, detail="Provider not found for this resource")

    credentials = get_provider_credentials(db, provider_id)
    full_credentials = {
        **credentials,
        "role_arn": provider.role_arn,
        "external_id": getattr(provider, "external_id", None),
    }

    job_id = enqueue_side_scan(db, x_tenant_id, resource_doc, provider_id, full_credentials)
    if job_id is None:
        raise HTTPException(status_code=422, detail="Resource could not be resolved to a scannable target")

    return {"job_id": job_id, "status": "queued", "resource_key": body.resource_key}


# ─── Jobs API ─────────────────────────────────────────────────────────────────


@router.get("/jobs")
async def list_scan_jobs(
    status: str | None = Query(None),
    job_type: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """List scan jobs for the tenant with optional status/type filters."""
    filters = "FILTER j.tenant_id == @tid"
    bind_vars: dict[str, Any] = {"tid": x_tenant_id, "limit": limit, "offset": offset}

    if status:
        filters += " AND j.status == @status"
        bind_vars["status"] = status
    if job_type:
        filters += " AND j.type == @job_type"
        bind_vars["job_type"] = job_type

    aql = f"""
        LET total = LENGTH(FOR j IN scan_jobs {filters} RETURN 1)
        LET items = (
            FOR j IN scan_jobs
            {filters}
            SORT j.created_at DESC
            LIMIT @offset, @limit
            RETURN j
        )
        RETURN {{total, items}}
    """
    try:
        result = list(db.aql.execute(aql, bind_vars=bind_vars))
        if not result:
            return {"items": [], "total": 0, "limit": limit, "offset": offset}
        row = result[0]
        return {"items": row.get("items", []), "total": row.get("total", 0), "limit": limit, "offset": offset}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to query scan jobs")


@router.get("/jobs/{job_id}")
async def get_scan_job(
    job_id: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """Get a specific scan job by ID. Returns 404 if not found or belongs to another tenant."""
    try:
        if not db.collection("scan_jobs").has(job_id):
            raise HTTPException(status_code=404, detail="Scan job not found")
        raw = db.collection("scan_jobs").get(job_id)
        doc: dict[str, Any] = raw if isinstance(raw, dict) else {}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to retrieve scan job")

    if not doc or doc.get("tenant_id") != x_tenant_id:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return doc


@router.post("/jobs/{job_id}/retry")
async def retry_scan_job(
    job_id: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """Re-enqueue a failed scan job. Returns 404 if not found, 422 if not in failed state."""
    try:
        if not db.collection("scan_jobs").has(job_id):
            raise HTTPException(status_code=404, detail="Scan job not found")
        raw = db.collection("scan_jobs").get(job_id)
        doc: dict[str, Any] = raw if isinstance(raw, dict) else {}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to retrieve scan job")

    if doc.get("tenant_id") != x_tenant_id:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if doc.get("status") != "failed":
        raise HTTPException(
            status_code=422,
            detail=f"Job status is '{doc.get('status')}', only 'failed' jobs can be retried",
        )

    job_type = doc.get("type", "")

    # ec2/lambda retries need fresh resource metadata (region, arn, and — for EC2 —
    # a live volume_id/availability_zone lookup), so they go through the same
    # enqueue_side_scan() path as a manual trigger rather than replaying the
    # original job doc's fields, which don't carry that data at all.
    if job_type in ("ec2", "lambda"):
        try:
            raw_resource = db.collection("resources").get(doc.get("resource_id", ""))
        except Exception:
            raw_resource = None
        resource_doc: dict[str, Any] = raw_resource if isinstance(raw_resource, dict) else {}
        if not resource_doc or resource_doc.get("tenant_id") != x_tenant_id:
            raise HTTPException(status_code=404, detail="Resource for this job no longer exists")

        provider_id = doc.get("provider_id", "")
        provider = get_provider(db, provider_id)
        if provider is None:
            raise HTTPException(status_code=400, detail="Provider not found for this resource")
        credentials = get_provider_credentials(db, provider_id)
        full_credentials = {
            **credentials,
            "role_arn": provider.role_arn,
            "external_id": getattr(provider, "external_id", None),
        }

        new_job_id = enqueue_side_scan(db, x_tenant_id, resource_doc, provider_id, full_credentials)
        if new_job_id is None:
            raise HTTPException(status_code=422, detail="Resource could not be resolved to a scannable target")
        return {"job_id": new_job_id, "status": "queued", "original_job_id": job_id}

    new_job_id = f"retry-{job_id}-{int(time.time())}"

    # Create new queued job record
    new_doc = {
        **doc,
        "_key": new_job_id,
        "status": "queued",
        "created_at": str(int(time.time())),
        "error_message": None,
    }
    new_doc.pop("_id", None)
    new_doc.pop("_rev", None)
    try:
        db.collection("scan_jobs").insert(new_doc)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to create retry job")

    # Dispatch appropriate task based on job type
    if job_type == "ecr":
        scan_container_image.delay(
            tenant_id=x_tenant_id,
            image_uri=doc.get("image_uri", ""),
            image_digest=doc.get("image_digest", ""),
            provider_id=doc.get("provider_id", ""),
            job_id=new_job_id,
        )
    elif job_type == "k8s_container":
        scan_k8s_container.delay(
            tenant_id=x_tenant_id,
            pod_name=doc.get("pod_name", ""),
            pod_namespace=doc.get("pod_namespace", ""),
            container_name=doc.get("container_name", ""),
            pid=doc.get("pid", 0),
            node_name=doc.get("node_name", ""),
            resource_id=doc.get("resource_id", ""),
            provider_id=doc.get("provider_id", ""),
            job_id=new_job_id,
        )
    else:
        # Generic retry — update status to queued, caller must handle
        pass

    return {"job_id": new_job_id, "status": "queued", "original_job_id": job_id}


# ─── Image security badge ────────────────────────────────────────────────────


@router.get("/images/{image_digest}/security")
async def get_image_security_status(
    image_digest: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """
    Badge endpoint for CI/CD pipelines.
    Returns overall_status (pass|fail) and CVE counts by severity.
    """
    digest_resource_id = image_digest.replace(":", "_").replace("/", "_")[:120]

    aql = """
        FOR f IN findings
        FILTER f.tenant_id == @tid
        AND f.resource_id == @resource_id
        AND f.status == "FAIL"
        COLLECT severity = f.severity WITH COUNT INTO cnt
        RETURN {severity, cnt}
    """
    try:
        rows = list(db.aql.execute(aql, bind_vars={"tid": x_tenant_id, "resource_id": digest_resource_id}))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to query findings")

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in rows:
        sev = row.get("severity", "")
        if sev in counts:
            counts[sev] = row.get("cnt", 0)

    has_critical_or_high = counts["CRITICAL"] > 0 or counts["HIGH"] > 0
    return {
        "overall_status": "fail" if has_critical_or_high else "pass",
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "image_digest": image_digest,
    }
