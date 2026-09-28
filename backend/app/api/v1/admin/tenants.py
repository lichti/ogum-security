"""Admin Tenants API — registro de tenants e emissão/rotação do token API
interim (US-06.09). Rotas PlatformAdmin (gate inertre em dev, via
`require_platform_admin`)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.deps import require_platform_admin
from app.models.api_responses import ApiResponse
from app.services import tenant_registry

router = APIRouter(
    prefix="/api/v1/admin/tenants",
    tags=["admin-tenants"],
    dependencies=[Depends(require_platform_admin)],
)


@router.get("", response_model=ApiResponse[list[dict]])
async def list_registered_tenants() -> ApiResponse[list[dict]]:
    """Lista os tenants registrados (sem expor hashes de token)."""
    return ApiResponse(data=tenant_registry.list_tenants())


@router.put("/{tenant_id}/api-token", response_model=ApiResponse[dict])
async def issue_api_token(tenant_id: str, platform_admin: bool = False) -> ApiResponse[dict]:
    """Registra o tenant (se necessário) e emite/rotaciona o token API.

    O valor do token é retornado **uma única vez** nesta resposta; o registro
    persiste apenas o hash. Emitir novamente revoga o token anterior.
    """
    issued = tenant_registry.mint_api_token(tenant_id, platform_admin=platform_admin)
    return ApiResponse(data=issued.model_dump(mode="json"))
