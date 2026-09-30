"""Dependências FastAPI de autenticação (Epic 06 Sprint 1).

`get_current_user` resolve a identidade a partir do Bearer JWT e seleciona o
database ArangoDB do tenant por request — o `tenant_id` nunca vem de header
ou parâmetro do cliente (a substituição definitiva dos headers dev-mode
`X-Tenant-ID`/`X-User-Id` acontece no wiring da US-06.09).

Nenhum router usa esta dependência ainda: o enforcement é ligado na US-06.09,
junto com o provisionamento do primeiro emissor de tokens.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.core.config import settings
from app.core.rbac import Role, has_permission
from app.core.security import decode_access_token
from app.db.client import get_arango_client
from app.services import tenant_registry

# HTTPBearer (e não OAuth2PasswordBearer) porque o fluxo não tem formulário de
# login próprio — o token chega exclusivamente no header Authorization.
_bearer_scheme = HTTPBearer(auto_error=False)

_401_HEADERS = {"WWW-Authenticate": "Bearer"}


class CurrentUser(BaseModel):
    sub: str
    tenant_id: str
    role: Role
    email: str | None = None
    # Handle do database ArangoDB `ogum_{tenant_id}`, resolvido por request.
    # `Any` porque o driver python-arango não é tipado (US-00.11 centraliza).
    db: Any = None


def _tenant_database(tenant_id: str) -> Any:
    client = get_arango_client()
    # Somente resolve um database existente — jamais cria (US-06.10 torna o
    # registro em `_system.tenants` a allowlist única; criação é do provisioning).
    return client.db(f"ogum_{tenant_id}", settings.ARANGO_USER, settings.ARANGO_PASSWORD)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers=_401_HEADERS,
        )
    return _resolve_user(credentials.credentials)


def _resolve_user(raw_token: str) -> CurrentUser:
    try:
        token = decode_access_token(raw_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid credentials: {exc}",
            headers=_401_HEADERS,
        ) from exc
    # Token API interim (US-06.09): além da assinatura/exp, o hash precisa
    # bater com o registro — regenerar o token revoga o anterior na hora.
    if token.typ == "api" and not tenant_registry.verify_api_token(token.tenant_id, raw_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials: token revoked or unknown",
            headers=_401_HEADERS,
        )
    return CurrentUser(
        sub=token.sub,
        tenant_id=token.tenant_id,
        role=token.role,
        email=token.email,
        db=_tenant_database(token.tenant_id),
    )


def require_platform_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> None:
    """Gate das rotas /api/v1/admin/* (US-06.09: role PlatformAdmin).

    Com AUTH_ENABLED=false o gate é inerte (dev, comportamento atual — o
    TODO(epic-06) original dos routers admin). Com true, exige Bearer válido
    de token com flag platform_admin; qualquer outra role → 403.
    """
    if not settings.AUTH_ENABLED:
        return
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers=_401_HEADERS,
        )
    user = _resolve_user(credentials.credentials)
    if user.role is not Role.PlatformAdmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PlatformAdmin role required",
        )


def require_permission(permission: str):
    """Reexporta o gate do rbac no módulo de deps para uso idiomático:

    `user = Depends(require_permission("scans:trigger"))`.
    """
    from app.core.rbac import require_permission as _require_permission

    return _require_permission(permission)


__all__ = [
    "CurrentUser",
    "get_current_user",
    "has_permission",
    "require_permission",
    "require_platform_admin",
]
