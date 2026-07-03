"""Scan management API — trigger CSPM scans and query job status."""

from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.finding import ScanJob
from app.services.provider_service import get_provider, get_provider_credentials
from app.services.scan_service import get_scan_job, list_scan_jobs
from app.workers.tasks.cspm_scan import run_cspm_scan

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

_DEFAULT_FRAMEWORKS = ["CIS-AWS-2.0", "PCI_DSS_v4", "SOC2"]


class ScanRequest(BaseModel):
    provider_id: str
    frameworks: list[str] = Field(default_factory=lambda: list(_DEFAULT_FRAMEWORKS))


class ScanResponse(BaseModel):
    job_id: str
    status: str


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

    # Build complete credentials including non-secret role fields stored on the provider
    full_credentials = {
        **credentials,
        "role_arn": provider.role_arn,
        "external_id": provider.external_id,
    }

    task = run_cspm_scan.delay(
        tenant_id=x_tenant_id,
        provider_id=body.provider_id,
        provider=provider.provider,
        frameworks=body.frameworks,
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


@router.get("", response_model=ApiResponse[list[ScanJob]])
async def list_scans(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[ScanJob]]:
    """List recent scan jobs for a tenant."""
    jobs = list_scan_jobs(db, x_tenant_id)
    return ApiResponse(data=jobs)
