from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from arango import ArangoClient
from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.api_responses import (
    ApiResponse,
    DiscoverJobResponse,
    InventoryStats,
    Meta,
    ResourceDetail,
    ResourceSummary,
)
from app.models.inventory_detail import BlastRadiusResponse, ResourceComplianceResponse, ResourceNarrativeSummary
from app.models.software_inventory import SoftwareInventoryResponse
from app.services.inventory_detail_service import build_resource_summary, get_blast_radius, get_resource_compliance
from app.services.inventory_service import get_inventory_stats, get_resource, list_resources
from app.services.software_inventory_service import get_software_inventory
from app.workers.tasks.cspm_scan import run_cspm_scan

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


def get_tenant_db(x_tenant_id: str = Header(..., alias="X-Tenant-ID")) -> StandardDatabase:
    """DEV MODE: tenant_id from X-Tenant-ID header. Sprint 7 replaces this with JWT extraction."""
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    sys_db = client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
    db_name = f"ogum_{x_tenant_id}"
    if not sys_db.has_database(db_name):
        sys_db.create_database(db_name)
    db = client.db(db_name, username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
    init_tenant_schema(db)
    return db


@router.get("", response_model=ApiResponse[list[ResourceSummary]])
async def list_inventory(
    provider: list[str] | None = Query(None),
    resource_type: list[str] | None = Query(None),
    account_id: list[str] | None = Query(None),
    region: list[str] | None = Query(None),
    status: str | None = Query(None, pattern="^(active|deleted)$"),
    search: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("name", pattern="^(name|updated_at|last_scanned_at)$"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[list[ResourceSummary]]:
    items, total = list_resources(
        db,
        x_tenant_id,
        provider=provider,
        resource_type=resource_type,
        account_id=account_id,
        region=region,
        status=status,
        search=search,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return ApiResponse(
        data=items,
        meta=Meta(total=total, limit=limit, offset=offset),
    )


@router.get("/stats", response_model=ApiResponse[InventoryStats])
async def inventory_stats(
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[InventoryStats]:
    stats = get_inventory_stats(db, x_tenant_id)
    return ApiResponse(data=stats)


@router.get("/export")
async def export_inventory(
    format: str = Query("csv", pattern="^(csv|json)$"),
    status: str | None = Query(None, pattern="^(active|deleted)$"),
    provider: str | None = Query(None),
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> StreamingResponse:
    """Export full inventory as CSV or OCSF-inspired JSON (streamed, capped at 50k rows)."""
    items, total = list_resources(
        db,
        x_tenant_id,
        provider=[provider] if provider else None,
        status=status,
        limit=50_000,
        offset=0,
    )
    if format == "csv":
        return _export_csv(items, x_tenant_id)
    return _export_json(items, x_tenant_id, total)


def _export_csv(items: list[ResourceSummary], tenant_id: str) -> StreamingResponse:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "key",
            "provider",
            "resource_type",
            "resource_id",
            "name",
            "region",
            "account_id",
            "status",
            "is_public",
            "tags",
            "last_scanned_at",
        ],
    )
    writer.writeheader()
    for item in items:
        writer.writerow(
            {
                "key": item.key,
                "provider": item.provider,
                "resource_type": item.resource_type,
                "resource_id": item.resource_id,
                "name": item.name,
                "region": item.region or "",
                "account_id": item.account_id or "",
                "status": item.status,
                "is_public": item.is_public,
                "tags": json.dumps(item.tags),
                "last_scanned_at": item.last_scanned_at or "",
            }
        )
    buf.seek(0)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"ogum_inventory_{tenant_id}_{ts}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _export_json(items: list[ResourceSummary], tenant_id: str, total: int) -> StreamingResponse:
    """OCSF-inspired JSON export (simplified Cloud Resources category)."""
    doc = {
        "ocsf_version": "1.0.0",
        "category_name": "Discovery",
        "class_name": "Resource Inventory",
        "metadata": {
            "tenant_id": tenant_id,
            "exported_at": datetime.now(UTC).isoformat(),
            "total_resources": total,
            "product": {"name": "Ogum Security", "version": "0.1.0"},
        },
        "resources": [
            {
                "uid": item.key,
                "type": item.resource_type,
                "name": item.name,
                "cloud": {
                    "provider": item.provider,
                    "account_uid": item.account_id,
                    "region": item.region,
                },
                "is_public": item.is_public,
                "status": item.status,
                "labels": item.tags,
                "last_scanned_time": item.last_scanned_at,
            }
            for item in items
        ],
    }
    content = json.dumps(doc, indent=2, default=str)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"ogum_inventory_{tenant_id}_{ts}.json"
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{resource_key}", response_model=ApiResponse[ResourceDetail])
async def get_resource_detail(
    resource_key: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[ResourceDetail]:
    resource = get_resource(db, x_tenant_id, resource_key)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return ApiResponse(data=resource)


@router.get("/{resource_key}/summary", response_model=ApiResponse[ResourceNarrativeSummary])
async def get_resource_summary(
    resource_key: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[ResourceNarrativeSummary]:
    resource = get_resource(db, x_tenant_id, resource_key)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return ApiResponse(data=build_resource_summary(db, x_tenant_id, resource))


@router.get("/{resource_key}/blast-radius", response_model=ApiResponse[BlastRadiusResponse])
async def get_resource_blast_radius(
    resource_key: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[BlastRadiusResponse]:
    resource = get_resource(db, x_tenant_id, resource_key)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return ApiResponse(data=get_blast_radius(db, x_tenant_id, resource_key))


@router.get("/{resource_key}/software", response_model=ApiResponse[SoftwareInventoryResponse])
async def get_resource_software(
    resource_key: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[SoftwareInventoryResponse]:
    resource = get_resource(db, x_tenant_id, resource_key)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return ApiResponse(data=get_software_inventory(db, x_tenant_id, resource))


@router.get("/{resource_key}/compliance", response_model=ApiResponse[ResourceComplianceResponse])
async def get_resource_compliance_endpoint(
    resource_key: str,
    framework: str | None = Query(None),
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[ResourceComplianceResponse]:
    resource = get_resource(db, x_tenant_id, resource_key)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return ApiResponse(data=get_resource_compliance(db, x_tenant_id, resource, framework))


@router.post("/discover", response_model=ApiResponse[DiscoverJobResponse], status_code=202)
async def trigger_discovery(
    provider: str = Query(..., pattern="^(aws|azure|gcp|k8s)$"),
    regions: list[str] = Query(default=["us-east-1"]),
    account_id: str | None = Query(None),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[DiscoverJobResponse]:
    if provider == "aws":
        # frameworks=None -> Prowler's full check catalog. No stored credentials
        # here — falls back to ambient worker credentials, same as the old
        # discover_aws's ambient-credential path.
        task = run_cspm_scan.delay(
            tenant_id=x_tenant_id,
            provider_id=f"aws-{account_id or 'ambient'}",
            provider="aws",
            frameworks=None,
            credentials={},
            account_id=account_id or "",
            regions=regions,
        )
        return ApiResponse(
            data=DiscoverJobResponse(
                job_id=task.id,
                tenant_id=x_tenant_id,
                provider=provider,
                regions=regions,
            )
        )
    raise HTTPException(
        status_code=422,
        detail=f"Provider '{provider}' discovery not yet implemented",
    )
