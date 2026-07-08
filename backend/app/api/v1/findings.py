"""Findings API — list, detail, status mutation, and export endpoints."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any, Literal

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
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
    mitre_ttp: str | None = Query(default=None, description="Filter by MITRE ATT&CK technique ID (e.g. T1078)"),
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
        mitre_ttp=mitre_ttp,
        limit=limit,
        cursor=cursor,
    )

    return ApiResponse(data=PagedFindings(items=items, next_cursor=next_cursor, count=len(items)))


class FindingsStats(BaseModel):
    by_severity: dict[str, int]
    by_status: dict[str, int]
    total: int


@router.get("/stats", response_model=ApiResponse[FindingsStats])
async def findings_stats_endpoint(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[FindingsStats]:
    """Aggregate counts by severity and status — used by the dashboard."""
    aql = """
    FOR f IN findings
      FILTER f.tenant_id == @tid
      COLLECT severity = f.severity, status = f.status WITH COUNT INTO c
      RETURN { severity, status, c }
    """
    rows = list(db.aql.execute(aql, bind_vars={"tid": x_tenant_id}))

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    by_status: dict[str, int] = {"FAIL": 0, "PASS": 0, "MUTED": 0, "ACCEPTED": 0}
    total = 0

    for row in rows:
        sev = str(row.get("severity", "")).upper()
        sta = str(row.get("status", "")).upper()
        count = int(row.get("c", 0))
        if sev in by_severity:
            by_severity[sev] += count
        if sta in by_status:
            by_status[sta] += count
        total += count

    return ApiResponse(data=FindingsStats(by_severity=by_severity, by_status=by_status, total=total))


_EXPORT_FIELDS = [
    "check_id",
    "title",
    "severity",
    "status",
    "provider",
    "resource_type",
    "resource_id",
    "resource_arn",
    "account_id",
    "region",
    "source",
    "framework_mapping",
    "remediation",
    "detected_at",
    "updated_at",
]


def _findings_stream(
    db: StandardDatabase,
    tenant_id: str,
    filters: dict[str, Any],
    export_format: Literal["csv", "json"],
) -> Any:
    """Generator that streams findings rows in the requested format."""
    page_limit = 500
    cursor: str | None = None

    if export_format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_EXPORT_FIELDS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()

        while True:
            rows, next_cursor = list_findings(db, tenant_id, **filters, limit=page_limit, cursor=cursor)
            for row in rows:
                if isinstance(row.get("framework_mapping"), list):
                    row = {**row, "framework_mapping": "|".join(row["framework_mapping"])}
                writer.writerow(row)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
            if not next_cursor:
                break
            cursor = next_cursor

    else:  # json
        first = True
        yield '{"data":['
        while True:
            rows, next_cursor = list_findings(db, tenant_id, **filters, limit=page_limit, cursor=cursor)
            for row in rows:
                if not first:
                    yield ","
                yield json.dumps(row, default=str)
                first = False
            if not next_cursor:
                break
            cursor = next_cursor
        yield "]}"


@router.get("/export")
def export_findings_endpoint(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
    format: Literal["csv", "json"] = Query(default="csv"),
    provider: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    framework: str | None = Query(default=None),
    region: str | None = Query(default=None),
    account_id: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    q: str | None = Query(default=None),
) -> StreamingResponse:
    """Stream findings as CSV or OCSF-aligned JSON with active filters applied."""
    date_str = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"findings_{date_str}.{format}"

    filters: dict[str, Any] = {
        "provider": provider,
        "severity": severity,
        "status": status,
        "framework": framework,
        "region": region,
        "account_id": account_id,
        "resource_type": resource_type,
        "source": source,
        "q": q,
    }

    media_type = "text/csv" if format == "csv" else "application/json"
    return StreamingResponse(
        _findings_stream(db, x_tenant_id, filters, format),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
