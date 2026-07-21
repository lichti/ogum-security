"""Scan management API — trigger CSPM scans and query job status."""

from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.finding import ScanJob
from app.services.provider_service import get_provider, get_provider_credentials
from app.services.scan_service import get_scan_job, get_scan_job_logs, list_scan_jobs
from app.workers.tasks.cspm_scan import run_cspm_scan

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


class ScanRequest(BaseModel):
    provider_id: str
    frameworks: list[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    job_id: str
    status: str


class PagedScanJobs(BaseModel):
    items: list[ScanJob]
    next_cursor: str | None = None


class ScanJobLogs(BaseModel):
    job_id: str
    logs: list[str]


@router.post("", response_model=ApiResponse[ScanResponse], status_code=202)
async def trigger_scan(
    body: ScanRequest,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ScanResponse]:
    """Trigger a CSPM scan for a provider. Returns a job_id for status polling."""
    provider = get_provider(db, body.provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Provider not found")

    credentials = get_provider_credentials(db, body.provider_id)
    if not credentials:
        raise HTTPException(status_code=400, detail="Provider credentials not available")

    account_id = provider.account_id or provider.subscription_id or provider.project_id or ""

    # No caller-supplied frameworks -> None, which runs Prowler's full check
    # catalog instead of a curated subset (see run_cspm_scan's docstring).
    frameworks = body.frameworks or None

    # Build complete credentials including non-secret role fields stored on the provider
    full_credentials = {
        **credentials,
        "role_arn": provider.role_arn,
        "external_id": getattr(provider, "external_id", None),
        "azure_tenant_id": getattr(provider, "azure_tenant_id", None),
        "azure_client_id": getattr(provider, "azure_client_id", None),
        "cluster_name": getattr(provider, "cluster_name", None),
    }

    task = run_cspm_scan.delay(
        tenant_id=x_tenant_id,
        provider_id=body.provider_id,
        provider=provider.provider,
        frameworks=frameworks,
        credentials=full_credentials,
        account_id=account_id,
        regions=provider.regions or None,
    )

    return ApiResponse(data=ScanResponse(job_id=task.id, status="queued"))


@router.get("/{job_id}", response_model=ApiResponse[ScanJob])
async def get_scan_status(
    job_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ScanJob]:
    """Get status and progress of a CSPM scan job."""
    job = get_scan_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.tenant_id != x_tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return ApiResponse(data=job)


@router.get("", response_model=ApiResponse[PagedScanJobs])
async def list_scans(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
    status: list[str] | None = Query(default=None),
    provider_id: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    cursor: str | None = Query(default=None),
) -> ApiResponse[PagedScanJobs]:
    """List scan jobs for a tenant — the Scans page registry (US-14.23)."""
    jobs, next_cursor = list_scan_jobs(
        db, x_tenant_id, status=status, provider_id=provider_id, limit=limit, cursor=cursor
    )
    return ApiResponse(data=PagedScanJobs(items=jobs, next_cursor=next_cursor))


@router.get("/{job_id}/logs", response_model=ApiResponse[ScanJobLogs])
async def get_scan_logs(
    job_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ScanJobLogs]:
    """Execution log lines captured during the scan (US-14.23)."""
    job = get_scan_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.tenant_id != x_tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    logs = get_scan_job_logs(db, job_id) or []
    return ApiResponse(data=ScanJobLogs(job_id=job_id, logs=logs))
