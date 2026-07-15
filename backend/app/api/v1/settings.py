from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.settings import SLASettings, SLASettingsUpdateRequest
from app.services.settings_service import get_sla_settings, update_sla_settings

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/sla", response_model=ApiResponse[SLASettings])
async def get_sla(
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[SLASettings]:
    return ApiResponse(data=get_sla_settings(db))


@router.put("/sla", response_model=ApiResponse[SLASettings])
async def update_sla(
    request: SLASettingsUpdateRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[SLASettings]:
    return ApiResponse(data=update_sla_settings(db, request))
