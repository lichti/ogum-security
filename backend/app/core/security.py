"""JWT — emissão e verificação de tokens (Epic 06 Sprint 1).

Fundação apenas: nenhum router exige autenticação ainda. O wiring nas rotas
entra junto com o fluxo interim de token por tenant (US-06.09), que fornece
o emissor enquanto o OIDC (US-06.01) não existe. Enquanto isso, o enforcement
fica atrás de `settings.AUTH_ENABLED`.

O algoritmo default é HS256 assinado com `JWT_SECRET_KEY` (fallback:
`APP_SECRET_KEY`). RS256 — verificação de tokens emitidos por IdP — chega com
a US-06.01; `create_access_token` recusa explicitamente esse modo enquanto não
houver par de chaves configurado.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from uuid import uuid4

from jose import JWTError, jwt
from pydantic import BaseModel
from redis import Redis

from app.core.config import settings
from app.core.rbac import Role

logger = logging.getLogger(__name__)

BLOCKLIST_KEY_PREFIX = "auth:blocklist:"


class TokenData(BaseModel):
    sub: str
    tenant_id: str
    role: Role
    email: str | None = None
    exp: int
    iat: int
    jti: str


def _signing_key() -> str:
    if settings.JWT_ALGORITHM.startswith("RS"):
        raise RuntimeError("RS256 requires the OIDC key pair (US-06.01); interim tokens use HS256")
    return settings.JWT_SECRET_KEY or settings.APP_SECRET_KEY


@lru_cache(maxsize=1)
def _redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1)


def is_jti_blocklisted(jti: str) -> bool:
    """True se o `jti` foi revogado (US-06.06: TTL = vida máxima do JWT).

    Redis indisponível → fail-open com warning: revogação fica inativa, mas
    autenticação básica (assinatura + exp) continua válida. Revisitado na
    US-06.07, onde a decisão de autorização inteira vira fail-safe deny.
    """
    try:
        return bool(_redis_client().exists(f"{BLOCKLIST_KEY_PREFIX}{jti}"))
    except Exception:
        logger.warning("JWT blocklist (Redis) unreachable — failing open", exc_info=True)
        return False


def create_access_token(
    subject: str,
    tenant_id: str,
    role: Role | str,
    expires_delta: timedelta | None = None,
    email: str | None = None,
) -> str:
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": subject,
        "tenant_id": tenant_id,
        "role": role.value if isinstance(role, Role) else str(role),
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": uuid4().hex,
    }
    return str(jwt.encode(payload, _signing_key(), algorithm=settings.JWT_ALGORITHM))


def decode_access_token(token: str) -> TokenData:
    """Valida assinatura, exp e blocklist; levanta ValueError se inválido."""
    try:
        payload = jwt.decode(token, _signing_key(), algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise ValueError(f"invalid token: {exc}") from exc
    if is_jti_blocklisted(str(payload.get("jti", ""))):
        raise ValueError("token revoked")
    return TokenData.model_validate(payload)
