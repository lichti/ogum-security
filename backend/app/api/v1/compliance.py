from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import get_current_tenant
from app.core.db import get_db
from app.services import compliance_service

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/summary")
def compliance_summary(
    tenant_id: str = Depends(get_current_tenant),
    db=Depends(get_db),
) -> dict:
    try:
        return {"data": compliance_service.get_compliance_summary(db, tenant_id)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
