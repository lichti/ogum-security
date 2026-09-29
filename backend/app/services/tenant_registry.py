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
import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from arango import ArangoClient
from pydantic import BaseModel

from app.core.config import settings
from app.core.rbac import Role
from app.core.security import create_access_token

logger = logging.getLogger(__name__)

SYSTEM_DB_NAME = "_system"
TENANTS_COLLECTION = "tenants"

# ArangoDB-safe tenant id: charset restrito e tamanho limitado — bloqueia
# path/injection no nome do database (`ogum_{tenant_id}`). UUID v4 estrito é
# exigência do provisioning completo (US-06.04); ambientes existentes usam
# nomes ("dev"), então a validação interim é de formato seguro.
_TENANT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")


class InvalidTenantIdError(ValueError):
    pass


def validate_tenant_id(tenant_id: str) -> str:
    if not _TENANT_ID_RE.fullmatch(tenant_id or ""):
        raise InvalidTenantIdError("tenant_id must match ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    return tenant_id


class ApiTokenIssued(BaseModel):
    tenant_id: str
    platform_admin: bool
    api_token: str
    expires_at: str


@lru_cache(maxsize=1)
def _client() -> ArangoClient:
    return ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")


def _registry_collection() -> Any:
    db = _client().db(SYSTEM_DB_NAME, settings.ARANGO_USER, settings.ARANGO_PASSWORD)
    if not db.has_collection(TENANTS_COLLECTION):
        db.create_collection(TENANTS_COLLECTION)
    return db.collection(TENANTS_COLLECTION)


def is_registered(tenant_id: str) -> bool:
    """Allowlist check do resolver estrito (US-06.10)."""
    try:
        return _registry_collection().has(tenant_id)
    except Exception:
        # Registro indisponível → não é allowlist: falha fechada (o tenant
        # deixa de resolver) com o erro logado.
        logger.warning("tenant registry unavailable — treating as unregistered", exc_info=True)
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register_tenant(tenant_id: str, platform_admin: bool = False) -> dict:
    """Interim provisioning (US-06.04 é o estado completo): valida o formato,
    garante o registro em `_system.tenants`, cria o database `ogum_{tenant_id}`
    se faltar e aplica o schema (idempotente). Idempotente por construction."""
    validate_tenant_id(tenant_id)
    col = _registry_collection()
    doc = col.get(tenant_id)
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

    # Provisioning mínimo do database (US-06.10: a resolução por request não
    # cria nada — a criação é toda daqui).
    client = _client()
    db_name = f"ogum_{tenant_id}"
    if not client.db(SYSTEM_DB_NAME, settings.ARANGO_USER, settings.ARANGO_PASSWORD).has_database(db_name):
        client.db(SYSTEM_DB_NAME, settings.ARANGO_USER, settings.ARANGO_PASSWORD).create_database(db_name)
        from app.db.init import init_tenant_schema

        init_tenant_schema(client.db(db_name, settings.ARANGO_USER, settings.ARANGO_PASSWORD))
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
