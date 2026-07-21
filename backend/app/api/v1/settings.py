from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.settings import (
    ComplianceFamilySettings,
    ComplianceFamilySettingsUpdateRequest,
    ComplianceFamilySettingsView,
    SLASettings,
    SLASettingsUpdateRequest,
)
from app.services.compliance_service import list_compliance_family_settings
from app.services.settings_service import get_sla_settings, update_compliance_family_settings, update_sla_settings

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


@router.get("/compliance", response_model=ApiResponse[list[ComplianceFamilySettingsView]])
async def list_compliance_settings(
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[list[ComplianceFamilySettingsView]]:
    rows = list_compliance_family_settings(db, x_tenant_id)
    return ApiResponse(data=[ComplianceFamilySettingsView(**row) for row in rows])


@router.put("/compliance/{family_key}", response_model=ApiResponse[ComplianceFamilySettings])
async def update_compliance_settings(
    family_key: str,
    request: ComplianceFamilySettingsUpdateRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[ComplianceFamilySettings]:
    return ApiResponse(data=update_compliance_family_settings(db, family_key, request))
