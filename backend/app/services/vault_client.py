"""Cliente Vault para credenciais de provider (US-06.11 — ADR-015: Vault
direto, sem camada intermediária de criptografia).

Paths (KV v2, mount `secret`): `tenants/{tenant_id}/{provider_key}` —
desvio consciente do `{aws,azure,gcp,k8s}` do credential-model §5: o mesmo
tenant pode ter vários providers do mesmo tipo, e o provider_key é único.
AppRole por tenant (`auth/approle/role/tenant-{tenant_id}`, policy de leitura
escopada ao path do tenant) é criado de forma idempotente no primeiro store —
a distribuição do secret_id às cargas é parte do provisioning completo
(US-06.04); até lá os workers usam o token do próprio serviço.

Sem fallback: Vault indisponível ou segredo ausente levanta exceção — nunca
se lê credencial do ArangoDB (AC da US-06.11).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

MOUNT_POINT = "secret"


class VaultError(Exception):
    """Base de erros do credential store."""


class VaultUnavailableError(VaultError):
    """Vault inacessível ou não configurado — a operação NÃO deve ter fallback."""


class CredentialNotFoundError(VaultError):
    """Segredo do provider ausente no Vault."""


def tenant_secret_path(tenant_id: str, provider_key: str) -> str:
    return f"tenants/{tenant_id}/{provider_key}"


def is_configured() -> bool:
    return bool(settings.VAULT_ENABLED and settings.VAULT_ADDR and settings.VAULT_TOKEN)


@lru_cache(maxsize=1)
def _client() -> Any:
    import hvac

    client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
    return client


def _ensure_ready() -> Any:
    if not is_configured():
        raise VaultUnavailableError("Vault is not configured (VAULT_ENABLED/VAULT_ADDR/VAULT_TOKEN)")
    client = _client()
    if not client.is_authenticated():
        raise VaultUnavailableError("Vault authentication failed — check VAULT_TOKEN")
    return client


def ensure_tenant_approle(tenant_id: str) -> None:
    """Cria (idempotente) a policy e o AppRole do tenant. Best-effort: falhas
    são logadas e não interrompem o store — o enforcement do AppRole passa a
    valer com a distribuição de secret_id da US-06.04."""
    try:
        client = _ensure_ready()
        policy = (
            f'path "{MOUNT_POINT}/data/tenants/{tenant_id}/*" {{\n'
            '  capabilities = ["read"]\n}\n'
            f'path "{MOUNT_POINT}/metadata/tenants/{tenant_id}/*" {{\n'
            '  capabilities = ["list", "read"]\n}\n'
        )
        client.sys.create_or_update_policy(name=f"tenant-{tenant_id}", policy=policy)
        client.auth.approle.create_or_update_approle(
            role_name=f"tenant-{tenant_id}",
            token_policies=[f"tenant-{tenant_id}"],
            token_ttl="1h",
            token_max_ttl="4h",
        )
    except VaultError:
        raise
    except Exception:
        logger.warning("AppRole provisioning for tenant %s failed", tenant_id, exc_info=True)


def store_credentials(tenant_id: str, provider_key: str, secrets: dict[str, Any]) -> dict[str, Any]:
    """Grava o lote de segredos do provider e retorna `{path, version}`."""
    if not secrets:
        raise ValueError("refusing to store an empty credential set")
    client = _ensure_ready()
    path = tenant_secret_path(tenant_id, provider_key)
    try:
        result = client.secrets.kv.v2.create_or_update_secret(path=path, secret=dict(secrets), mount_point=MOUNT_POINT)
    except Exception as exc:
        raise VaultUnavailableError(f"Vault write failed for {path}: {exc}") from exc
    ensure_tenant_approle(tenant_id)
    version = (result or {}).get("data", {}).get("version")
    logger.info("Credentials stored in Vault at %s (version=%s)", path, version)
    return {"path": path, "version": version}


def load_credentials(path: str) -> dict[str, Any]:
    """Lê o lote de segredos do provider. Erros são explícitos — sem fallback:
    path inexistente → CredentialNotFoundError; Vault fora → VaultUnavailableError."""
    from hvac.exceptions import InvalidPath

    client = _ensure_ready()
    try:
        result = client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=MOUNT_POINT, raise_on_deleted_version=True
        )
    except InvalidPath as exc:
        raise CredentialNotFoundError(f"No credentials stored at {path}") from exc
    except Exception as exc:
        raise VaultUnavailableError(f"Vault read failed for {path}: {exc}") from exc
    data = ((result or {}).get("data") or {}).get("data") or {}
    if not data:
        raise CredentialNotFoundError(f"No credentials stored at {path}")
    return dict(data)


def destroy_credentials(path: str) -> None:
    """Remove as versões do segredo (metadata delete). Best-effort no delete
    do provider — falha é logada, não bloqueia a exclusão."""
    client = _ensure_ready()
    try:
        client.secrets.kv.v2.delete_metadata_and_all_versions(path=path, mount_point=MOUNT_POINT)
    except Exception:
        logger.warning("Vault metadata delete failed for %s", path, exc_info=True)
