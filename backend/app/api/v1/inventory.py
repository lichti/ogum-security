from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query
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
