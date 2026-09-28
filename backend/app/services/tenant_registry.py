"""Registro de tenants e ciclo de vida do token API interim (US-06.09).

O registro vive no database `_system` do ArangoDB (coleção `tenants`), como
prescrito pela US-06.04 — esta US antecipa apenas a allowlist mínima e o
emissor de tokens que o gate interim exige enquanto o OIDC (US-06.01) não
existe. O valor do token sai desta função **uma única vez**; no banco fica
apenas o hash SHA-256, comparado em tempo constante. Regenerar o token
substitui o hash — o anterior deixa de autenticar imediatamente.

O `api_token` é um JWT (`typ: "api"`) de longa vida (`INTERIM_TOKEN_EXPIRE_DAYS`,
30 dias por default): valida assinatura/exp/blocklist pelo caminho normal do
Sprint 1 e, por ser hasheado no registro, é revogável sem Redis.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from arango import ArangoClient
from pydantic import BaseModel

from app.core.config import settings
from app.core.rbac import Role
from app.core.security import create_access_token

logger = logging.getLogger(__name__)

SYSTEM_DB_NAME = "_system"
TENANTS_COLLECTION = "tenants"


class ApiTokenIssued(BaseModel):
    tenant_id: str
    platform_admin: bool
    api_token: str
    expires_at: str


def _registry_collection() -> Any:
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    db = client.db(SYSTEM_DB_NAME, settings.ARANGO_USER, settings.ARANGO_PASSWORD)
    if not db.has_collection(TENANTS_COLLECTION):
        db.create_collection(TENANTS_COLLECTION)
    return db.collection(TENANTS_COLLECTION)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register_tenant(tenant_id: str, platform_admin: bool = False) -> dict:
    """Idempotente: cria o registro do tenant se não existir (US-06.09; a
    criação do database segue sendo do provisioning da US-06.04)."""
    col = _registry_collection()
    doc: dict | None = col.get(tenant_id)
    if doc is None:
        col.insert(
            {
                "_key": tenant_id,
                "tenant_id": tenant_id,
                "platform_admin": platform_admin,
                "token_hash": None,
                "token_issued_at": None,
                "token_jti": None,
                "token_expires_at": None,
            }
        )
        doc = dict(col.get(tenant_id))
    elif platform_admin and not doc.get("platform_admin"):
        col.update({"_key": tenant_id, "platform_admin": True})
        doc = dict(col.get(tenant_id))
    return doc


def mint_api_token(tenant_id: str, platform_admin: bool = False) -> ApiTokenIssued:
    """Gera (ou rotaciona) o token do tenant. O valor plaintext só existe no
    retorno — o registro guarda apenas o hash."""
    register_tenant(tenant_id, platform_admin)
    expires = datetime.now(UTC) + timedelta(days=settings.INTERIM_TOKEN_EXPIRE_DAYS)
    token = create_access_token(
        subject=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        role=Role.PlatformAdmin if platform_admin else Role.SecOps,
        expires_delta=timedelta(days=settings.INTERIM_TOKEN_EXPIRE_DAYS),
        token_type="api",
    )
    _registry_collection().update(
        {
            "_key": tenant_id,
            "token_hash": _hash_token(token),
            "token_issued_at": datetime.now(UTC).isoformat(),
            "token_expires_at": expires.isoformat(),
        }
    )
    logger.info("API token minted for tenant %s (platform_admin=%s)", tenant_id, platform_admin)
    return ApiTokenIssued(
        tenant_id=tenant_id,
        platform_admin=platform_admin,
        api_token=token,
        expires_at=expires.isoformat(),
    )


def verify_api_token(tenant_id: str, token: str) -> bool:
    """True se o hash do token apresentado bate com o registro do tenant
    (comparação em tempo constante sobre o hash)."""
    try:
        doc = _registry_collection().get(tenant_id)
    except Exception:
        logger.warning("tenant registry unavailable — token rejected", exc_info=True)
        return False
    stored = (doc or {}).get("token_hash")
    if not stored:
        return False
    return hmac.compare_digest(stored, _hash_token(token))


def list_tenants() -> list[dict]:
    """Registros sem os hashes — para a UI de admin."""
    cursor = _registry_collection().all()
    out = []
    for doc in cursor:
        out.append(
            {
                "tenant_id": doc.get("tenant_id") or doc["_key"],
                "platform_admin": bool(doc.get("platform_admin")),
                "has_token": bool(doc.get("token_hash")),
                "token_issued_at": doc.get("token_issued_at"),
                "token_expires_at": doc.get("token_expires_at"),
            }
        )
    return out
