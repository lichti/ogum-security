from typing import Literal

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.compliance import ComplianceControlAsset, ComplianceFrameworkDetail, ComplianceScoreTrendPoint
from app.services import compliance_service

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/summary")
def compliance_summary(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
    framework: str | None = Query(
        default=None, description="Scope top_failing/top_assets to this framework version id"
    ),
    severity: list[str] | None = Query(
        default=None, description="Restrict top_failing to these severities (does not affect top_assets)"
    ),
) -> dict:
    try:
        return {
            "data": compliance_service.get_compliance_summary(db, x_tenant_id, framework=framework, severities=severity)
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/frameworks/{framework_id}", response_model=ApiResponse[ComplianceFrameworkDetail])
def get_framework_detail(
    framework_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ComplianceFrameworkDetail]:
    detail = compliance_service.get_framework_detail(db, x_tenant_id, framework_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Unknown compliance framework: {framework_id}")
    return ApiResponse(data=ComplianceFrameworkDetail(**detail))


@router.get("/frameworks/{framework_id}/trend", response_model=ApiResponse[list[ComplianceScoreTrendPoint]])
def get_framework_trend(
    framework_id: str,
    period: Literal["7d", "14d", "1m"] = Query(default="7d"),
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[ComplianceScoreTrendPoint]]:
    points = compliance_service.get_score_trend(db, x_tenant_id, framework_id, period)
    return ApiResponse(data=[ComplianceScoreTrendPoint(**p) for p in points])


@router.get("/frameworks/{framework_id}/control-assets", response_model=ApiResponse[list[ComplianceControlAsset]])
def get_control_assets(
    framework_id: str,
    control_id: str = Query(..., description="The control's control_id within this framework version"),
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[ComplianceControlAsset]]:
    assets = compliance_service.get_control_assets(db, x_tenant_id, framework_id, control_id)
    return ApiResponse(data=[ComplianceControlAsset(**a) for a in assets])
