"""Admin Jobs API — cross-tenant job inspection and control."""

# TODO(epic-06): add @require_role(["PlatformAdmin"]) to all routes once Auth/RBAC is implemented.

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.models.admin import JobDetail, QueueDepth, RetryRequest, TriggerRequest, WorkerInfo
from app.models.api_responses import ApiResponse
from app.services import admin_service

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/jobs", response_model=ApiResponse[dict])
async def list_jobs(
    tenant_id: str | None = Query(default=None, description="Filter to a specific tenant. Omit for all tenants."),
    status: str | None = Query(default=None, description="Filter by job status (e.g. queued, running, failed)"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, description="Keyset cursor (created_at ISO timestamp of last item)"),
) -> ApiResponse[dict]:
    """List scan jobs across all tenants or scoped to a specific tenant."""
    result = admin_service.list_jobs(tenant_id=tenant_id, status=status, limit=limit, cursor=cursor)
    items = [j.model_dump(mode="json") for j in result["items"]]
    return ApiResponse(data={"items": items, "next_cursor": result["next_cursor"]})


@router.get("/jobs/{job_id}", response_model=ApiResponse[JobDetail])
async def get_job(
    job_id: str,
    tenant_id: str = Query(..., description="Tenant that owns this job"),
) -> ApiResponse[JobDetail]:
    """Get full detail for a single scan job."""
    job = admin_service.get_job(job_id, tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return ApiResponse(data=job)


@router.post("/jobs/{job_id}/retry", response_model=ApiResponse[dict], status_code=202)
async def retry_job(job_id: str, body: RetryRequest) -> ApiResponse[dict]:
    """Re-enqueue a failed job. Returns the new job_id."""
    new_job_id = admin_service.retry_job(job_id, tenant_id=body.tenant_id, actor_email=body.actor_email)
    if new_job_id is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return ApiResponse(data={"original_job_id": job_id, "new_job_id": new_job_id})


@router.post("/jobs/trigger", response_model=ApiResponse[dict], status_code=202)
async def trigger_job(body: TriggerRequest) -> ApiResponse[dict]:
    # TODO(epic-06): add @require_role(["PlatformAdmin"])
    """Immediately dispatch a new scan job, bypassing the scheduled queue."""
    job_id = admin_service.trigger_job(
        tenant_id=body.tenant_id,
        task_type=body.task_type,
        provider_id=body.provider_id,
        provider=body.provider,
        frameworks=body.frameworks,
        actor_email=body.actor_email,
    )
    return ApiResponse(data={"job_id": job_id, "task_type": body.task_type, "tenant_id": body.tenant_id})


@router.get("/jobs/{job_id}/logs")
async def stream_job_logs(
    job_id: str,
    tenant_id: str = Query(..., description="Tenant that owns this job"),
) -> StreamingResponse:
    # TODO(epic-06): add @require_role(["PlatformAdmin"])
    """Stream stored log lines for a job via Server-Sent Events."""

    async def _generate() -> AsyncGenerator[str, None]:
        logs = admin_service.get_job_logs(job_id, tenant_id)
        if not logs:
            yield f"data: {json.dumps({'line': '[no logs]', 'index': 0})}\n\n"
        else:
            for i, line in enumerate(logs):
                yield f"data: {json.dumps({'line': line, 'index': i})}\n\n"
                await asyncio.sleep(0)
        yield "data: [DONE]\n\n"

    return StreamingResponse(_generate(), media_type="text/event-stream")


@router.delete("/jobs/{job_id}", status_code=204)
async def revoke_job(
    job_id: str,
    tenant_id: str = Query(...),
    actor_email: str = Query(...),
) -> None:
    """Cancel a queued or running job."""
    admin_service.revoke_job(job_id, tenant_id=tenant_id, actor_email=actor_email)


@router.get("/workers", response_model=ApiResponse[list[WorkerInfo]])
async def list_workers() -> ApiResponse[list[WorkerInfo]]:
    """Return info about active Celery workers."""
    return ApiResponse(data=admin_service.get_workers())


@router.get("/queue-depth", response_model=ApiResponse[list[QueueDepth]])
async def get_queue_depth() -> ApiResponse[list[QueueDepth]]:
    """Return the number of pending messages in each Celery queue."""
    return ApiResponse(data=admin_service.get_queue_depths())
