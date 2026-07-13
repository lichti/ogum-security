from __future__ import annotations

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.views import SavedView, SavedViewCreateRequest, SavedViewUpdateRequest, ViewScope
from app.services.view_service import create_view, delete_view, list_views, update_view

router = APIRouter(prefix="/api/v1/views", tags=["views"])


def get_current_user_id(x_user_id: str = Header(..., alias="X-User-Id")) -> str:
    """DEV MODE: user identity from X-User-Id header — Epic 06 replaces this with JWT extraction.

    Views are scoped per-user in this phase; shared/team views depend on RBAC (Epic 06).
    """
    return x_user_id


@router.get("", response_model=ApiResponse[list[SavedView]])
async def list_views_endpoint(
    scope: ViewScope | None = Query(None),
    db: StandardDatabase = Depends(get_tenant_db),
    user_id: str = Depends(get_current_user_id),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[list[SavedView]]:
    return ApiResponse(data=list_views(db, user_id, scope=scope))


@router.post("", response_model=ApiResponse[SavedView], status_code=201)
async def create_view_endpoint(
    request: SavedViewCreateRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    user_id: str = Depends(get_current_user_id),
) -> ApiResponse[SavedView]:
    return ApiResponse(data=create_view(db, user_id, request))


@router.patch("/{view_id}", response_model=ApiResponse[SavedView])
async def update_view_endpoint(
    view_id: str,
    request: SavedViewUpdateRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    user_id: str = Depends(get_current_user_id),
) -> ApiResponse[SavedView]:
    view = update_view(db, user_id, view_id, request)
    if not view:
        raise HTTPException(
            status_code=404, detail="View not found, not owned by this user, or read-only (system view)"
        )
    return ApiResponse(data=view)


@router.delete("/{view_id}", response_model=ApiResponse[dict[str, bool]])
async def delete_view_endpoint(
    view_id: str,
    db: StandardDatabase = Depends(get_tenant_db),
    user_id: str = Depends(get_current_user_id),
) -> ApiResponse[dict[str, bool]]:
    deleted = delete_view(db, user_id, view_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail="View not found, not owned by this user, or read-only (system view)"
        )
    return ApiResponse(data={"deleted": True})
