"""Middleware de identidade do gate interim (US-06.09).

Com `AUTH_ENABLED=false` (dev): pass-through puro — comportamento atual,
headers `X-Tenant-ID`/`X-User-Id` seguem funcionando.

Com `AUTH_ENABLED=true`: exige `Authorization: Bearer` em toda rota exceto
as isentas (`/health`, docs/OpenAPI e os webhooks de scanner, que têm
autenticação própria via `x-ogum-token`), resolve a identidade do JWT
(token API interim valida também o hash no registro) e **reescreve os
headers `X-Tenant-ID`/`X-User-Id` no scope** com os claims verificados —
assim os handlers que hoje leem esses headers passam a consumir a
identidade autenticada sem reescrita de assinatura. Um `X-Tenant-ID`
divergente do token é sobrescrito e logado como aviso de deprecação
(US-06.10 remove a leitura de headers por completo).

Pure ASGI (não BaseHTTPMiddleware) para poder mutar `scope["headers"]`.
"""

from __future__ import annotations

import logging

from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.security import decode_access_token
from app.services import tenant_registry

logger = logging.getLogger(__name__)

EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}
WEBHOOK_PREFIXES = ("/api/v1/side-scans/webhooks/",)
_401_HEADERS = {b"www-authenticate": b"Bearer"}


def _unauthorized(detail: str):
    return JSONResponse(
        status_code=401,
        content={"detail": detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _header_value(scope, name: bytes) -> str | None:
    for key, value in scope["headers"]:
        if key == name:
            return bytes(value).decode("latin-1")
    return None


def _set_header(scope, name: bytes, value: str) -> None:
    headers = [h for h in scope["headers"] if h[0] != name]
    headers.append((name, value.encode("latin-1")))
    scope["headers"] = headers


class TenantIdentityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] == "http"
            and settings.AUTH_ENABLED
            and scope["method"] != "OPTIONS"
            and scope["path"] not in EXEMPT_PATHS
            and not scope["path"].startswith(WEBHOOK_PREFIXES)
        ):
            raw_auth = _header_value(scope, b"authorization")
            if not raw_auth or not raw_auth.lower().startswith("bearer "):
                resp = _unauthorized("Not authenticated")
                await resp(scope, receive, send)
                return
            raw_token = raw_auth.split(" ", 1)[1].strip()
            try:
                token = decode_access_token(raw_token)
                if token.typ == "api" and not tenant_registry.verify_api_token(token.tenant_id, raw_token):
                    raise ValueError("token revoked or unknown")
            except ValueError as exc:
                logger.info("auth rejected %s %s: %s", scope["method"], scope["path"], exc)
                resp = _unauthorized(f"Invalid credentials: {exc}")
                await resp(scope, receive, send)
                return

            spoofed = _header_value(scope, b"x-tenant-id")
            if spoofed and spoofed != token.tenant_id:
                logger.warning(
                    "DEPRECATED header X-Tenant-ID=%r ignored — identity resolved from "
                    "the bearer token (tenant %s). Remove the header; US-06.10 drops "
                    "header resolution entirely.",
                    spoofed,
                    token.tenant_id,
                )
            _set_header(scope, b"x-tenant-id", token.tenant_id)
            _set_header(scope, b"x-user-id", token.sub)
        await self.app(scope, receive, send)


__all__ = ["TenantIdentityMiddleware"]
