"""Modelos de request/response de autenticação (US-06.01)."""

from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl

from app.core.rbac import Role


class RoleMappingIn(BaseModel):
    group: str = Field(..., min_length=1, max_length=200)
    role: Role


class OidcConfigIn(BaseModel):
    """Configuração do IdP do tenant — PlatformAdmin via POST /auth/oidc/config.

    O Client Secret transita apenas aqui (TLS) e é gravado no Vault; nunca
    é retornado por nenhuma rota.
    """

    tenant_id: str = Field(..., min_length=1, max_length=64)
    idp_name: str = Field("OIDC", max_length=60)
    discovery_url: HttpUrl
    client_id: str = Field(..., min_length=1, max_length=256)
    client_secret: str = Field(..., min_length=1, max_length=2048)
    scopes: str = Field("openid email profile groups", max_length=200)
    group_claim_key: str = Field("groups", max_length=60)
    default_role: Role = Role.SecOps
    role_mappings: list[RoleMappingIn] = Field(default_factory=list)


class RefreshIn(BaseModel):
    """Fallback do cookie para clientes não-browser (workers, CLIs)."""

    refresh_token: str | None = Field(None, max_length=4096)
