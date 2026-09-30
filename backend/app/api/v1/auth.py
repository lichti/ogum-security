"""Rotas de autenticação (US-06.01 — Epic 06 Sprint 2).

Fluxo OIDC authorization-code por tenant: login redireciona ao IdP com
`state`+`nonce` anti-CSRF no Redis (TTL 10 min, consumo único), o callback
troca o código no token endpoint (Client Secret direto do Vault), valida o
`id_token` por JWKS e emite o JWT interno do Ogum (access 15 min + refresh
7 d com rotação, `auth:refresh:{jti}` no Redis). Os tokens vão para o
browser em cookies HttpOnly — o `TenantIdentityMiddleware` aceita o cookie
`ogum_access` como fallback do header Bearer.

Rotas públicas (isentas no middleware): login, callback e refresh. A
configuração do IdP é PlatformAdmin.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from redis import Redis

from app.core.config import settings
from app.core.deps import require_platform_admin
from app.core.rbac import Role
from app.core.security import create_access_token, decode_access_token
from app.db.client import get_arango_client
from app.models.api_responses import ApiResponse
from app.models.auth import OidcConfigIn, RefreshIn
from app.services import oidc_service, tenant_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

STATE_KEY_PREFIX = "auth:oidc:state:"
REFRESH_KEY_PREFIX = "auth:refresh:"


def _redis() -> Redis:
    # mesmo pool do security.py (mesmo Redis, mesma política de timeout)
    from functools import lru_cache

    @lru_cache(maxsize=1)
    def _client() -> Redis:
        return Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1)

    return _client()


def _secure_cookies() -> bool:
    return settings.APP_ENV == "production"


def _redirect_uri() -> str:
    return f"{settings.PUBLIC_BASE_URL.rstrip('/')}/api/v1/auth/oidc/callback"


def _refresh_ttl_seconds() -> int:
    return int(timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())


def _tenant_db_or_none(tenant_id: str) -> StandardDatabase | None:
    """Abre `ogum_{tenant_id}` sem provisionar nada (fluxo pré-auth)."""
    client = get_arango_client()
    db_name = f"ogum_{tenant_id}"
    try:
        sys_db = client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
        if not sys_db.has_database(db_name):
            return None
        return client.db(db_name, username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
    except Exception:
        logger.warning("failed to open tenant database for %s", tenant_id, exc_info=True)
        return None


def _set_token_cookies(response: Response, access: str, refresh: str) -> None:
    response.set_cookie(
        settings.ACCESS_COOKIE_NAME,
        access,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=_secure_cookies(),
        samesite="lax",
    )
    response.set_cookie(
        settings.REFRESH_COOKIE_NAME,
        refresh,
        max_age=_refresh_ttl_seconds(),
        httponly=True,
        secure=_secure_cookies(),
        samesite="lax",
        path="/api/v1/auth",
    )


def _issue_session(tenant_id: str, subject: str, role: Role, email: str | None) -> tuple[str, str]:
    """JWT interno access + refresh; o jti do refresh fica no Redis (rotação)."""
    access = create_access_token(subject=subject, tenant_id=tenant_id, role=role, email=email, token_type="access")
    refresh = create_access_token(subject=subject, tenant_id=tenant_id, role=role, email=email, token_type="refresh")
    refresh_jti = decode_access_token(refresh).jti
    _redis().setex(f"{REFRESH_KEY_PREFIX}{refresh_jti}", _refresh_ttl_seconds(), tenant_id)
    return access, refresh


# ── Status do IdP (para a página de login) ───────────────────────────────────


@router.get("/oidc/status", response_model=ApiResponse[dict[str, Any]])
async def oidc_status(tenant_id: str = Query(..., max_length=64)) -> ApiResponse[dict[str, Any]]:
    """Login page consulta antes de renderizar o botão SSO (nome do IdP)."""
    try:
        tenant_registry.validate_tenant_id(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db = _tenant_db_or_none(tenant_id)
    config = oidc_service.load_config(db) if db is not None else None
    if config is None:
        raise HTTPException(status_code=404, detail="No OIDC identity provider configured for tenant")
    return ApiResponse(data={"enabled": True, "idp_name": config.idp_name})


# ── Login: redireciona ao IdP ────────────────────────────────────────────────


def _safe_next_path(next_url: str | None) -> str:
    """Só caminhos relativos internos — bloqueia open redirect pós-login."""
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/dashboard"


@router.get("/oidc/login")
async def oidc_login(
    tenant_id: str = Query(..., max_length=64),
    next: str | None = Query(None, max_length=256),
) -> RedirectResponse:
    try:
        tenant_registry.validate_tenant_id(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not tenant_registry.is_registered(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant not registered")
    db = _tenant_db_or_none(tenant_id)
    config = oidc_service.load_config(db) if db is not None else None
    if config is None:
        raise HTTPException(status_code=404, detail="No OIDC identity provider configured for tenant")

    discovery = oidc_service.fetch_discovery(config.discovery_url)
    state = uuid4().hex
    nonce = uuid4().hex
    _redis().setex(
        f"{STATE_KEY_PREFIX}{state}",
        oidc_service.STATE_TTL_SECONDS,
        json.dumps({"tenant_id": tenant_id, "nonce": nonce, "next": _safe_next_path(next)}),
    )
    params = urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": _redirect_uri(),
            "scope": config.scopes,
            "state": state,
            "nonce": nonce,
        }
    )
    return RedirectResponse(f"{discovery['authorization_endpoint']}?{params}", status_code=307)


# ── Callback: troca o code, valida id_token, emite JWT interno ───────────────


@router.get("/oidc/callback")
async def oidc_callback(code: str | None = Query(None), state: str | None = Query(None)) -> Response:
    if not code or not state:
        raise HTTPException(status_code=400, detail="code and state are required")
    raw = _redis().getdel(f"{STATE_KEY_PREFIX}{state}")
    if not raw:
        # state inexistente, expirado (10 min) ou reutilizado — anti-CSRF falhou
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    session = json.loads(raw)
    tenant_id: str = session["tenant_id"]
    nonce: str = session["nonce"]

    db = _tenant_db_or_none(tenant_id)
    config = oidc_service.load_config(db) if db is not None else None
    if config is None:
        raise HTTPException(status_code=400, detail="OIDC configuration disappeared")

    try:
        discovery = oidc_service.fetch_discovery(config.discovery_url)
        client_secret = oidc_service.load_client_secret(tenant_id)
        tokens = oidc_service.exchange_code(discovery, config, code, client_secret, _redirect_uri())
        id_token = tokens.get("id_token")
        if not id_token:
            raise ValueError("token endpoint did not return id_token")
        claims = oidc_service.validate_id_token(id_token, discovery, config, nonce)
    except ValueError as exc:
        logger.warning("OIDC callback failed for tenant %s: %s", tenant_id, exc)
        raise HTTPException(status_code=400, detail=f"OIDC login failed: {exc}") from exc

    role = oidc_service.map_role(claims, config)
    subject = f"user:{claims.get('sub', '')}"
    email = claims.get("email") or str(claims.get("sub", ""))
    access, refresh = _issue_session(tenant_id, subject, role, email)

    next_path = _safe_next_path(session.get("next"))
    response = RedirectResponse(f"{settings.FRONTEND_URL.rstrip('/')}{next_path}", status_code=307)
    _set_token_cookies(response, access, refresh)
    logger.info("OIDC login ok tenant=%s role=%s", tenant_id, role.value)
    return response


# ── Refresh com rotação ──────────────────────────────────────────────────────


@router.post("/refresh")
async def refresh(request: Request, body: RefreshIn | None = None) -> Response:
    token = request.cookies.get(settings.REFRESH_COOKIE_NAME) or (body.refresh_token if body else None)
    if not token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    try:
        data = decode_access_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None
    if data.typ != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")
    # rotação: o jti anterior é consumido — replay do mesmo refresh falha
    if not _redis().getdel(f"{REFRESH_KEY_PREFIX}{data.jti}"):
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    access, new_refresh = _issue_session(data.tenant_id, data.sub, Role(data.role), data.email)
    payload = ApiResponse[dict[str, int]](data={"expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60})
    response = JSONResponse(content=payload.model_dump(mode="json"))
    _set_token_cookies(response, access, new_refresh)
    return response


# ── Configuração do IdP (PlatformAdmin) ──────────────────────────────────────


@router.post(
    "/oidc/config",
    dependencies=[Depends(require_platform_admin)],
    response_model=ApiResponse[dict[str, Any]],
)
async def save_oidc_config(request: OidcConfigIn) -> ApiResponse[dict[str, Any]]:
    from app.api.v1.inventory import get_tenant_db  # resolver estrito + allowlist

    db = get_tenant_db(x_tenant_id=request.tenant_id)
    config = oidc_service.save_config(
        db,
        request.tenant_id,
        oidc_service.OidcConfig(
            idp_name=request.idp_name,
            discovery_url=str(request.discovery_url),
            client_id=request.client_id,
            scopes=request.scopes,
            group_claim_key=request.group_claim_key,
            default_role=request.default_role,
            role_mappings=[oidc_service.RoleMapping(group=m.group, role=m.role) for m in request.role_mappings],
        ),
        request.client_secret,
    )
    try:
        # gate do AC: o discovery tem que responder antes de "salvar" — o fetch
        # roda sobre o valor RELIDO do ArangoDB (o que ficou persistido é o que
        # é validado), não sobre o payload da request.
        saved = oidc_service.load_config(db)
        assert saved is not None  # acabou de ser gravado
        oidc_service.validate_discovery(saved.discovery_url)
    except oidc_service.DiscoveryError as exc:
        # rollback compensatório: um IdP que não responde não fica registrado
        # (o secret órfão no Vault é inerte sem o doc — destruído por higiene)
        db.collection("oidc_config").delete("idp")
        try:
            oidc_service.vault_client.destroy_credentials(
                oidc_service.vault_client.tenant_secret_path(request.tenant_id, "oidc")
            )
        except Exception:
            logger.warning("Vault cleanup after invalid discovery failed for %s", request.tenant_id, exc_info=True)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ApiResponse(
        data={
            "tenant_id": request.tenant_id,
            "idp_name": config.idp_name,
            "client_id": config.client_id,
            "role_mappings": [m.model_dump(mode="json") for m in config.role_mappings],
        }
    )
