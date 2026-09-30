from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from arango.database import StandardDatabase

from app.models.provider import ProviderConfig, ProviderRegisterRequest, ProviderUpdateRequest
from app.services import vault_client
from app.services.vault_client import CredentialNotFoundError

logger = logging.getLogger(__name__)


def secrets_module_token() -> str:
    return secrets.token_urlsafe(32)


def hash_scanner_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _make_key(provider: str, identifier: str) -> str:
    safe = identifier.replace("/", "_").replace(":", "_")
    return f"{provider}-{safe}"[:220]


def _ensure_collection(db: StandardDatabase) -> None:
    if not db.has_collection("tenant_config"):
        db.create_collection("tenant_config")


_SECRET_FIELDS = frozenset(
    {
        "aws_access_key_id",
        "aws_secret_access_key",
        "azure_client_secret",
        "gcp_service_account_json",
        "kubeconfig",
    }
)


def _request_secrets(request: ProviderRegisterRequest) -> dict[str, Any]:
    """Campos de segredo presentes no pedido de registro (a fonte única de
    segredos é o Vault — o documento no ArangoDB nunca os recebe)."""
    secrets: dict[str, Any] = {}
    for field in _SECRET_FIELDS:
        value = getattr(request, field, None)
        if value:
            secrets[field] = value
    return secrets


def _doc_to_config(doc: dict[str, Any]) -> ProviderConfig:
    """Map ArangoDB document to ProviderConfig, stripping credential secrets."""
    return ProviderConfig(
        key=doc["_key"],
        **{k: v for k, v in doc.items() if k not in ("_key", "_id", "_rev") and k not in _SECRET_FIELDS},
    )


def _infer_credential_type(provider: str, request: ProviderRegisterRequest) -> str:
    if provider == "aws":
        if request.role_arn:
            return "role"
        if request.aws_access_key_id and request.aws_secret_access_key:
            return "static"
        return "ambient"
    if provider == "azure":
        if request.azure_client_id and request.azure_client_secret and request.azure_tenant_id:
            return "service_principal"
        return "managed_identity"
    if provider == "gcp":
        if request.gcp_service_account_json:
            return "service_account"
        return "adc"
    if provider == "k8s":
        if request.kubeconfig:
            return "kubeconfig"
        return "incluster"
    return "ambient"


def register_provider(
    db: StandardDatabase,
    tenant_id: str,
    request: ProviderRegisterRequest,
) -> ProviderConfig:
    """Persist provider config in tenant_config.

    Segredos vão exclusivamente para o Vault (US-06.11/ADR-015): o documento
    guarda apenas `credentials_vault_path`/`credentials_vault_version` — nunca
    campos de credencial (verdade desde agora; as docstrings anteriores
    afirmavam isso enquanto gravavam plaintext)."""
    identifier = (
        request.account_id or request.subscription_id or request.project_id or request.cluster_name or "default"
    )
    key = _make_key(request.provider, identifier)

    # Check if an external_id already exists (idempotent re-registration must preserve it)
    existing_external_id: str | None = None
    _ensure_collection(db)
    existing = db.collection("tenant_config").get(key)
    if existing:
        existing_external_id = existing.get("external_id")

    credential_type = _infer_credential_type(request.provider, request)

    # Secrets → Vault (fora do ArangoDB por construção). Se o Vault estiver
    # indisponível, VaultUnavailableError propaga — registro falha com erro
    # claro, sem degradar para armazenamento local.
    secrets = _request_secrets(request)
    vault_ref: dict[str, Any] = {}
    if secrets:
        vault_ref = vault_client.store_credentials(tenant_id, key, secrets)

    # scanner_token (US-03.17): gerado no registro de providers consumidos por
    # webhook (K8s DaemonSet / ECR); o documento guarda só o hash.
    scanner_token: str | None = None
    if request.provider in ("k8s", "kubernetes"):
        scanner_token = secrets_module_token()
        doc_scanner_hash: str | None = hash_scanner_token(scanner_token)
    else:
        doc_scanner_hash = None

    doc = {
        "_key": key,
        "provider": request.provider,
        "display_name": request.display_name,
        "account_id": request.account_id,
        "subscription_id": request.subscription_id,
        "project_id": request.project_id,
        "cluster_name": request.cluster_name,
        "regions": request.regions,
        "enabled": True,
        "status": "pending",
        "credential_type": credential_type,
        "role_arn": request.role_arn,
        "external_id": existing_external_id or str(uuid.uuid4()),
        "azure_tenant_id": request.azure_tenant_id,
        "azure_client_id": request.azure_client_id,
        # Segredos: apenas a referência ao Vault — campos de credencial sempre None
        "credentials_vault_path": vault_ref.get("path"),
        "credentials_vault_version": vault_ref.get("version"),
        "scanner_token_hash": doc_scanner_hash,
        "aws_access_key_id": None,
        "aws_secret_access_key": None,
        "azure_client_secret": None,
        "gcp_service_account_json": None,
        "kubeconfig": None,
        "last_discovery_at": None,
        "last_discovery_job_id": None,
        "created_at": datetime.now(UTC).isoformat(),
    }

    _ensure_collection(db)
    db.collection("tenant_config").insert(doc, overwrite=True)
    config = ProviderConfig(
        key=key,
        **{k: v for k, v in doc.items() if k not in ("_key",) and k not in _SECRET_FIELDS},  # type: ignore[arg-type]
    )
    # Valor do token anexado uma única vez ao retorno (nunca persistido)
    config.scanner_token_once = scanner_token
    return config


def rotate_scanner_token(db: StandardDatabase, provider_id: str) -> str:
    """Gera novo scanner_token e revoga o anterior (hash substituído — US-03.17).

    O valor novo é retornado uma única vez; persiste-se apenas o hash."""
    _ensure_collection(db)
    doc = db.collection("tenant_config").get(provider_id)
    if not doc:
        raise KeyError(f"Provider {provider_id} not found")
    token = secrets_module_token()
    db.collection("tenant_config").update({"_key": provider_id, "scanner_token_hash": hash_scanner_token(token)})
    logger.info("scanner_token rotated for provider=%s", provider_id)
    return token


def resolve_provider_credentials(db: StandardDatabase, provider_id: str) -> dict[str, Any]:
    """Credenciais completas para execução de scan/discovery, resolvidas no
    momento do uso dentro do worker (US-06.11/US-06.12).

    Segredos vêm do Vault — indisponibilidade ou ausência levanta
    CredentialNotFoundError/VaultUnavailableError com mensagem clara (a task
    falha visivelmente; **nunca** há fallback para credencial em banco). Os
    campos não-secretos (role_arn, external_id, ids Azure, cluster) vêm do
    documento do provider.
    """
    _ensure_collection(db)
    doc = db.collection("tenant_config").get(provider_id)
    if not doc:
        raise CredentialNotFoundError(f"Provider {provider_id} not found")

    path = doc.get("credentials_vault_path")
    if path:
        try:
            secrets = vault_client.load_credentials(path)
        except vault_client.CredentialNotFoundError:
            # Sem fallback para banco: scan segue sem segredos (modo ambient da
            # worker) e falha na camada cloud com erro claro. O log fica em
            # mensagem estática + provider_id — nem path nem traceback (CodeQL
            # py/clear-text-logging-sensitive-data: campos de credencial e
            # tracebacks de leitura de segredo carregam taint).
            logger.warning("Credential load failed for %s (no secret stored)", provider_id)
            secrets = {}
        except vault_client.VaultError:
            logger.warning("Credential load failed for %s (Vault unavailable)", provider_id)
            secrets = {}
    else:
        # Documento legado pré-migração (plaintext) ou provider ambient/role
        # (nada a resolver — a worker usa as próprias credenciais). A janela
        # legado é fechada pelo script scripts/migrate_credentials_to_vault.py;
        # não é fallback de Vault indisponível (o load acima já teria logado).
        secrets = {f: doc[f] for f in _SECRET_FIELDS if doc.get(f)}

    return {
        **secrets,
        "role_arn": doc.get("role_arn"),
        "external_id": doc.get("external_id"),
        "azure_tenant_id": doc.get("azure_tenant_id"),
        "azure_client_id": doc.get("azure_client_id"),
        "cluster_name": doc.get("cluster_name"),
    }


def get_provider_credentials(db: StandardDatabase, provider_id: str) -> dict[str, Any]:
    """Return stored credential secrets for a provider (server-side probes:
    test-connection, provider health — not for task dispatch; workers use
    `resolve_provider_credentials`).

    Indisponibilidade do Vault/segredo ausente → `{}` (os chamadores tratam
    como "credentials not available"); a causa fica logada.
    """
    _ensure_collection(db)
    try:
        doc = db.collection("tenant_config").get(provider_id)
        if not doc:
            return {}
        path = doc.get("credentials_vault_path")
        if path:
            try:
                return vault_client.load_credentials(path)
            except vault_client.CredentialNotFoundError:
                logger.warning("Credential load failed for %s (no secret stored)", provider_id)
                return {}
            except vault_client.VaultError:
                logger.warning("Credential load failed for %s (Vault unavailable)", provider_id)
                return {}
        # Legado pré-migração
        return {
            "aws_access_key_id": doc.get("aws_access_key_id"),
            "aws_secret_access_key": doc.get("aws_secret_access_key"),
            "azure_client_secret": doc.get("azure_client_secret"),
            "gcp_service_account_json": doc.get("gcp_service_account_json"),
            "kubeconfig": doc.get("kubeconfig"),
        }
    except Exception:
        return {}


def get_provider(db: StandardDatabase, provider_id: str) -> ProviderConfig | None:
    _ensure_collection(db)
    try:
        doc = db.collection("tenant_config").get(provider_id)
        return _doc_to_config(doc) if doc else None
    except Exception:
        return None


def list_providers(db: StandardDatabase) -> list[ProviderConfig]:
    if not db.has_collection("tenant_config"):
        return []
    cursor = db.aql.execute("FOR c IN tenant_config RETURN c")
    return [_doc_to_config(doc) for doc in cursor]


def update_provider(
    db: StandardDatabase,
    provider_id: str,
    update: ProviderUpdateRequest,
    tenant_id: str | None = None,
) -> ProviderConfig | None:
    _ensure_collection(db)
    patch: dict[str, Any] = {"_key": provider_id}
    if update.display_name is not None:
        patch["display_name"] = update.display_name
    if update.regions is not None:
        patch["regions"] = update.regions
    if update.enabled is not None:
        patch["enabled"] = update.enabled
        patch["status"] = "disabled" if not update.enabled else "active"
    # Non-secret credential metadata — empty string clears the field (stores None)
    if update.role_arn is not None:
        patch["role_arn"] = update.role_arn or None
    if update.azure_tenant_id is not None:
        patch["azure_tenant_id"] = update.azure_tenant_id or None
    if update.azure_client_id is not None:
        patch["azure_client_id"] = update.azure_client_id or None

    # Secrets — empty string clears; None means "don't change". Novo lote vai
    # para o Vault (nova versão); campos no documento permanecem None.
    update_secrets: dict[str, Any] = {}
    for field in (
        "aws_access_key_id",
        "aws_secret_access_key",
        "azure_client_secret",
        "gcp_service_account_json",
        "kubeconfig",
    ):
        value = getattr(update, field)
        if value is not None:
            update_secrets[field] = value or None
    if any(v for v in update_secrets.values()):
        doc = db.collection("tenant_config").get(provider_id) or {}
        path = doc.get("credentials_vault_path")
        if not path:
            tenant = tenant_id or db.name.removeprefix("ogum_")
            path = vault_client.tenant_secret_path(tenant, provider_id)
        current: dict[str, Any] = {}
        try:
            current = vault_client.load_credentials(path)
        except CredentialNotFoundError:
            current = {}
        merged = {**current, **{k: v for k, v in update_secrets.items() if v}}
        # Campo limpo (string vazia) é removido do lote no Vault
        for k, v in update_secrets.items():
            if v is None and k in merged:
                del merged[k]
        vault_ref = vault_client.store_credentials(tenant_id or db.name.removeprefix("ogum_"), provider_id, merged)
        patch["credentials_vault_path"] = vault_ref["path"]
        patch["credentials_vault_version"] = vault_ref["version"]

    try:
        db.collection("tenant_config").update(patch)
        return get_provider(db, provider_id)
    except Exception:
        return None


_VERTEX_COLLECTIONS = ["resources", "identities", "data_assets", "network_endpoints"]
_EDGE_COLLECTIONS = [
    "EXPOSED_TO",
    "ASSUMES_ROLE",
    "CONTAINS_BUG",
    "STORES_SENSITIVE_DATA",
    "ROUTES_TRAFFIC",
    "BELONGS_TO",
    "ATTACHED_TO",
    "MEMBER_OF",
    "STS_ASSUMEROLE_ALLOW",
    "ATTACHED_POLICY",
    "HAS_FINDING",
]


def _purge_provider_resources(db: StandardDatabase, config: ProviderConfig) -> dict[str, int]:
    """Hard-delete all graph data owned by a provider.

    Order: findings → scan_jobs → graph vertices → orphaned edges → attack_paths.
    Scan jobs are keyed by provider_id (direct FK). Findings have no provider_id
    field at all (`Finding` never gained one) — scoped by (provider, account_id/
    cluster_name) instead, the same key vertices use, since that's the only FK a
    finding document actually carries back to a provider.
    Orphaned edges are swept after vertices (and findings) are removed.
    Attack paths are swept last: any path whose entry_point or target no longer
    exists as a graph document is considered stale and removed.

    Returns a dict of {collection_name: deleted_count}.
    """
    counts: dict[str, int] = {}
    provider_id = config.key

    # Scope used by both findings and graph vertices below.
    if config.provider == "k8s":
        scope_filter = "FILTER doc.provider == @provider AND doc.cluster_name == @identifier"
        identifier = config.cluster_name or ""
    else:
        scope_filter = "FILTER doc.provider == @provider AND doc.account_id == @identifier"
        identifier = config.account_id or config.subscription_id or config.project_id or ""

    # 1. Findings — no provider_id field; scoped by (provider, account_id/cluster_name).
    for coll in ("findings",):
        if not db.has_collection(coll):
            counts[coll] = 0
            continue
        cursor = db.aql.execute(
            f"""
            FOR doc IN @@coll
              {scope_filter}
              REMOVE doc IN @@coll
              COLLECT WITH COUNT INTO n
              RETURN n
            """,
            bind_vars={"@coll": coll, "provider": config.provider, "identifier": identifier},
        )
        result = list(cursor)
        counts[coll] = result[0] if result else 0

    # 2. Scan jobs — keyed by provider_id
    for coll in ("scan_jobs",):
        if not db.has_collection(coll):
            counts[coll] = 0
            continue
        cursor = db.aql.execute(
            """
            FOR doc IN @@coll
              FILTER doc.provider_id == @provider_id
              REMOVE doc IN @@coll
              COLLECT WITH COUNT INTO n
              RETURN n
            """,
            bind_vars={"@coll": coll, "provider_id": provider_id},
        )
        result = list(cursor)
        counts[coll] = result[0] if result else 0

    # 3. Graph vertices — scoped by (provider, account_id/cluster_name)
    for coll in _VERTEX_COLLECTIONS:
        if not db.has_collection(coll):
            counts[coll] = 0
            continue
        cursor = db.aql.execute(
            f"""
            FOR doc IN @@coll
              {scope_filter}
              REMOVE doc IN @@coll
              COLLECT WITH COUNT INTO n
              RETURN n
            """,
            bind_vars={"@coll": coll, "provider": config.provider, "identifier": identifier},
        )
        result = list(cursor)
        counts[coll] = result[0] if result else 0

    # 4. Orphaned edges — sweep after vertices are gone
    for edge_coll in _EDGE_COLLECTIONS:
        if not db.has_collection(edge_coll):
            counts[edge_coll] = 0
            continue
        cursor = db.aql.execute(
            """
            FOR e IN @@coll
              FILTER DOCUMENT(e._from) == null OR DOCUMENT(e._to) == null
              REMOVE e IN @@coll
              COLLECT WITH COUNT INTO n
              RETURN n
            """,
            bind_vars={"@coll": edge_coll},
        )
        result = list(cursor)
        counts[edge_coll] = result[0] if result else 0

    # 5. Attack paths — remove any path whose entry_point or target no longer exists
    if db.has_collection("attack_paths"):
        cursor = db.aql.execute(
            """
            FOR ap IN attack_paths
              FILTER DOCUMENT(ap.entry_point_id) == null
                  OR DOCUMENT(ap.target_id) == null
              REMOVE ap IN attack_paths
              COLLECT WITH COUNT INTO n
              RETURN n
            """
        )
        result = list(cursor)
        counts["attack_paths"] = result[0] if result else 0
    else:
        counts["attack_paths"] = 0

    return counts


def delete_provider(db: StandardDatabase, provider_id: str) -> tuple[bool, dict[str, int]]:
    """Delete a provider config and all its associated graph resources.

    Returns (success, purge_counts) where purge_counts maps collection → deleted count.
    """
    if not db.has_collection("tenant_config"):
        return False, {}
    config = get_provider(db, provider_id)
    if not config:
        return False, {}
    try:
        # Best-effort: destrói os segredos no Vault (todas as versões) antes
        # de remover o documento; falha não bloqueia a exclusão.
        doc = db.collection("tenant_config").get(provider_id) or {}
        path = doc.get("credentials_vault_path")
        if path:
            try:
                vault_client.destroy_credentials(path)
            except vault_client.VaultError:
                logger.warning("Vault destroy failed for %s", path, exc_info=True)
        purge_counts = _purge_provider_resources(db, config)
        db.collection("tenant_config").delete(provider_id)
        return True, purge_counts
    except Exception:
        return False, {}


def update_provider_last_discovery(db: StandardDatabase, provider_id: str, job_id: str) -> None:
    if not db.has_collection("tenant_config"):
        return
    db.collection("tenant_config").update(
        {
            "_key": provider_id,
            "last_discovery_at": datetime.now(UTC).isoformat(),
            "last_discovery_job_id": job_id,
            "status": "active",
        }
    )
