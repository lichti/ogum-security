"""Side-scanning API — trigger K8s container scans from DaemonSet webhook."""

from __future__ import annotations

import time

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from app.api.v1.inventory import get_tenant_db
from app.workers.tasks.side_scanning import scan_k8s_container

router = APIRouter(prefix="/api/v1/side-scans", tags=["side-scans"])


class K8sScanWebhookPayload(BaseModel):
    pod_name: str
    pod_namespace: str
    container_name: str
    pid: int
    node_name: str
    resource_id: str
    provider_id: str
    job_id: str | None = None


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

    # Create a queued scan_jobs record
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
