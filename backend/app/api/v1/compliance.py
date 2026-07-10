from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.api.v1.inventory import get_tenant_db
from app.services import compliance_service

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/summary")
def compliance_summary(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
    framework: str | None = Query(default=None, description="Scope top_failing to this framework version id"),
) -> dict:
    try:
        return {"data": compliance_service.get_compliance_summary(db, x_tenant_id, framework=framework)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
