"""Findings API — list, detail, and status mutation endpoints."""

from __future__ import annotations

from typing import Any

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, model_validator

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.finding import FindingStatus
from app.services.cli_command import build_cli_command
from app.services.findings_service import get_finding, list_findings, update_finding_status

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_VALID_PROVIDERS = {"aws", "azure", "gcp", "k8s"}
_VALID_SORT_BY = {"severity", "detected_at", "resource_type"}
_VALID_SORT_ORDER = {"ASC", "DESC"}


class PagedFindings(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None
    count: int


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    reason: str | None = None

    @model_validator(mode="after")
    def require_reason_for_muted(self) -> FindingStatusUpdate:
        if self.status == FindingStatus.MUTED and not self.reason:
            raise ValueError("reason is required when status is 'muted'")
        if self.status not in (FindingStatus.MUTED, FindingStatus.ACCEPTED):
            raise ValueError("status must be 'muted' or 'accepted'")
        return self


@router.get("", response_model=ApiResponse[PagedFindings])
async def list_findings_endpoint(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
    provider: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    framework: str | None = Query(default=None),
    region: str | None = Query(default=None),
    account_id: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    q: str | None = Query(default=None, description="Full-text search in title, check_id, resource_arn"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> ApiResponse[PagedFindings]:
    if provider and provider not in _VALID_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"provider must be one of {sorted(_VALID_PROVIDERS)}")

    items, next_cursor = list_findings(
        db,
        x_tenant_id,
        provider=provider,
        severity=severity,
        status=status,
        framework=framework,
        region=region,
        account_id=account_id,
        resource_type=resource_type,
        source=source,
        q=q,
        limit=limit,
        cursor=cursor,
    )

    return ApiResponse(data=PagedFindings(items=items, next_cursor=next_cursor, count=len(items)))


@router.get("/{finding_key}", response_model=ApiResponse[dict[str, Any]])
async def get_finding_endpoint(
    finding_key: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict[str, Any]]:
    doc = get_finding(db, finding_key, x_tenant_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Attach best available CLI command
    doc["cli_command"] = build_cli_command(
        provider=doc.get("provider", ""),
        resource_type=doc.get("resource_type", ""),
        resource_id=doc.get("resource_id", ""),
        remediation_code=doc.get("remediation_code"),
    )

    return ApiResponse(data=doc)


@router.patch("/{finding_key}", response_model=ApiResponse[dict[str, Any]])
async def update_finding_status_endpoint(
    finding_key: str,
    body: FindingStatusUpdate,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict[str, Any]]:
    updated = update_finding_status(
        db,
        finding_key,
        x_tenant_id,
        new_status=body.status,
        reason=body.reason,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return ApiResponse(data=updated)
