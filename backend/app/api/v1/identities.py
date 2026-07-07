from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse, Meta
from app.services.ciem_service import get_identity_ciem_summary, list_identities_with_ciem

router = APIRouter(prefix="/api/v1/identities", tags=["identities"])


@router.get("", response_model=ApiResponse[list[dict]])
async def list_identities(
    provider: str | None = Query(None),
    only_dangerous: bool = Query(False, alias="only_dangerous"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[list[dict]]:
    items, total = list_identities_with_ciem(
        db,
        x_tenant_id,
        limit=limit,
        offset=offset,
        provider=provider,
        only_dangerous=only_dangerous,
    )
    return ApiResponse(
        data=items,
        meta=Meta(total=total, limit=limit, offset=offset),
    )


@router.get("/{identity_key}/permissions", response_model=ApiResponse[dict])
async def identity_permissions(
    identity_key: str,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[dict]:
    result = get_identity_ciem_summary(db, identity_key, x_tenant_id)
    if not result:
        raise HTTPException(status_code=404, detail="Identity not found")
    return ApiResponse(data=result)
