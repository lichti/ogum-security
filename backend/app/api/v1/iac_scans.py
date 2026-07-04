"""IaC scan API — trigger Checkov scans on git repositories."""

from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.finding import ScanJob
from app.services.scan_service import get_scan_job
from app.workers.tasks.iac_scan import run_iac_scan

router = APIRouter(prefix="/api/v1/scans/iac", tags=["iac-scans"])


class IacScanRequest(BaseModel):
    repo_url: str = Field(..., description="Git HTTPS or SSH URL to the repository")
    branch: str = Field("main", description="Branch to scan")
    path: str = Field(".", description="Sub-directory within the repository to scan")
    account_id: str = Field("iac", description="Logical account label for findings")
    repo_token: str | None = Field(None, description="GitHub/GitLab token (not stored)")


class IacScanResponse(BaseModel):
    job_id: str
    status: str


@router.post("", response_model=ApiResponse[IacScanResponse], status_code=202)
def trigger_iac_scan(
    body: IacScanRequest,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[IacScanResponse]:
    """Trigger a Checkov IaC scan on a git repository. Returns a job_id for status polling."""
    if not body.repo_url.startswith(("https://", "ssh://", "git@")):
        raise HTTPException(status_code=422, detail="repo_url must be a valid git URL")

    task = run_iac_scan.delay(
        tenant_id=x_tenant_id,
        repo_url=body.repo_url,
        branch=body.branch,
        path=body.path,
        account_id=body.account_id,
        repo_token=body.repo_token,
    )
    return ApiResponse(data=IacScanResponse(job_id=task.id, status="queued"))


@router.get("/{job_id}", response_model=ApiResponse[ScanJob])
def get_iac_scan_status(
    job_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ScanJob]:
    """Get status of an IaC scan job."""
    job = get_scan_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.tenant_id != x_tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return ApiResponse(data=job)
