from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from arango import ArangoClient
from arango.database import StandardDatabase

from app.core.config import settings
from app.models.api_responses import (
    ApiResponse,
    DiscoverJobResponse,
    InventoryStats,
    Meta,
    ResourceDetail,
    ResourceSummary,
)
from app.services.inventory_service import get_inventory_stats, get_resource, list_resources
from app.workers.tasks.discovery import discover_aws

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


def get_tenant_db(x_tenant_id: str = Header(..., alias="X-Tenant-ID")) -> StandardDatabase:
    """DEV MODE: tenant_id from X-Tenant-ID header. Sprint 7 replaces this with JWT extraction."""
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    return client.db(
        f"ogum_{x_tenant_id}",
        username=settings.ARANGO_USER,
        password=settings.ARANGO_PASSWORD,
    )


@router.get("", response_model=ApiResponse[list[ResourceSummary]])
async def list_inventory(
    provider: str | None = Query(None),
    resource_type: str | None = Query(None),
    account_id: str | None = Query(None),
    region: str | None = Query(None),
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
        provider=provider,
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
            "key", "provider", "resource_type", "resource_id", "name",
            "region", "account_id", "status", "is_public", "tags", "last_scanned_at",
        ],
    )
    writer.writeheader()
    for item in items:
        writer.writerow({
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
        })
    buf.seek(0)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
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
            "exported_at": datetime.now(timezone.utc).isoformat(),
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
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
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


@router.post("/discover", response_model=ApiResponse[DiscoverJobResponse], status_code=202)
async def trigger_discovery(
    provider: str = Query(..., pattern="^(aws|azure|gcp|k8s)$"),
    regions: list[str] = Query(default=["us-east-1"]),
    account_id: str | None = Query(None),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[DiscoverJobResponse]:
    if provider == "aws":
        task = discover_aws.delay(x_tenant_id, regions, account_id)
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
