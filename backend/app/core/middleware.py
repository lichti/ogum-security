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
import time
from functools import lru_cache

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


__all__ = ["TenantIdentityMiddleware", "TenantRateLimitMiddleware"]


# ── Rate limiting por tenant (US-06.13) ──────────────────────────────────────


class TenantRateLimitMiddleware:
    """Fixed-window por tenant no Redis (`ogum:rl:{tenant}:{epoch_sec}`).

    Lê o `X-Tenant-ID` **já reescrito** pelo TenantIdentityMiddleware (por isso
    deve ser adicionado ANTES dele — identity é o middleware mais externo).
    Limite: `rate_limit_per_second` do registro do tenant (cache em processo,
    60s) ou `RATE_LIMIT_PER_SECOND` default. Estourou → 429 com `Retry-After`
    e headers `X-RateLimit-*`. Redis indisponível → fail-open com warning
    (rate limit é defesa em profundidade; disponibilidade primeiro).
    Isento: `/health`, docs/OpenAPI, webhooks de scanner, OPTIONS.
    """

    _REGISTRY_CACHE_TTL = 60.0

    def __init__(self, app):
        self.app = app
        self._overrides: dict[str, tuple[float, int]] = {}

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or not settings.RATE_LIMIT_ENABLED
            or scope["method"] == "OPTIONS"
            or scope["path"] in EXEMPT_PATHS
            or scope["path"].startswith(WEBHOOK_PREFIXES)
        ):
            await self.app(scope, receive, send)
            return
        tenant = _header_value(scope, b"x-tenant-id")
        if not tenant:
            await self.app(scope, receive, send)
            return

        limit = self._limit_for(tenant)
        window_secs = max(1, settings.RATE_LIMIT_WINDOW_SECONDS)
        window = int(time.time() // window_secs)
        key = f"ogum:rl:{tenant}:{window}"
        try:
            redis = _rl_redis()
            count = redis.incr(key)
            if count == 1:
                redis.expire(key, window_secs + 1)
        except Exception:
            logger.warning("rate-limit Redis unavailable — failing open", exc_info=True)
            await self.app(scope, receive, send)
            return

        remaining = max(0, limit - count)
        reset_in = max(0, (window + 1) * window_secs - time.time())

        if count > limit:
            resp = JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={
                    "Retry-After": str(max(1, int(reset_in) or 1)),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(window + 1),
                },
            )
            await resp(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers += [
                    (b"x-ratelimit-limit", str(limit).encode()),
                    (b"x-ratelimit-remaining", str(remaining).encode()),
                    (b"x-ratelimit-reset", str(window + 1).encode()),
                ]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)

    def _limit_for(self, tenant: str) -> int:
        now = time.monotonic()
        cached = self._overrides.get(tenant)
        if cached and now - cached[0] < self._REGISTRY_CACHE_TTL:
            return cached[1]
        limit = settings.RATE_LIMIT_PER_SECOND
        try:
            from app.services import tenant_registry

            doc = tenant_registry._registry_collection().get(tenant)
            if doc and doc.get("rate_limit_per_second"):
                limit = int(doc["rate_limit_per_second"])
        except Exception:
            logger.debug("rate-limit override lookup failed for %s", tenant, exc_info=True)
        self._overrides[tenant] = (now, limit)
        return limit


@lru_cache(maxsize=1)
def _rl_redis():
    from redis import Redis

    return Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
