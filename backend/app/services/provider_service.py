from __future__ import annotations

import uuid
from datetime import datetime, timezone

from arango.database import StandardDatabase

from app.models.provider import ProviderConfig, ProviderRegisterRequest, ProviderUpdateRequest


def _make_key(provider: str, identifier: str) -> str:
    safe = identifier.replace("/", "_").replace(":", "_")
    return f"{provider}-{safe}"[:220]


def _ensure_collection(db: StandardDatabase) -> None:
    if not db.has_collection("tenant_config"):
        db.create_collection("tenant_config")


_SECRET_FIELDS = frozenset({
    "aws_access_key_id", "aws_secret_access_key",
    "azure_client_secret", "gcp_service_account_json", "kubeconfig",
})


def _doc_to_config(doc: dict) -> ProviderConfig:
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
    """Persist provider config in tenant_config. Credentials are never stored here."""
    identifier = (
        request.account_id
        or request.subscription_id
        or request.project_id
        or request.cluster_name
        or "default"
    )
    key = _make_key(request.provider, identifier)

    # Check if an external_id already exists (idempotent re-registration must preserve it)
    existing_external_id: str | None = None
    _ensure_collection(db)
    existing = db.collection("tenant_config").get(key)
    if existing:
        existing_external_id = existing.get("external_id")

    credential_type = _infer_credential_type(request.provider, request)

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
        # Credentials stored for scheduled jobs — NEVER returned in API responses
        "aws_access_key_id": request.aws_access_key_id,
        "aws_secret_access_key": request.aws_secret_access_key,
        "azure_client_secret": request.azure_client_secret,
        "gcp_service_account_json": request.gcp_service_account_json,
        "kubeconfig": request.kubeconfig,
        "last_discovery_at": None,
        "last_discovery_job_id": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    _ensure_collection(db)
    db.collection("tenant_config").insert(doc, overwrite=True)
    return ProviderConfig(
        key=key,
        **{k: v for k, v in doc.items() if k not in ("_key",) and k not in _SECRET_FIELDS},
    )


def get_provider_credentials(db: StandardDatabase, provider_id: str) -> dict:
    """Return stored credential secrets for a provider.

    These fields are intentionally excluded from ProviderConfig and never
    returned in API responses. Call this only inside task dispatch paths.
    """
    _ensure_collection(db)
    try:
        doc = db.collection("tenant_config").get(provider_id)
        if not doc:
            return {}
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
) -> ProviderConfig | None:
    _ensure_collection(db)
    patch: dict = {"_key": provider_id}
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
    # Secrets — empty string clears; None means "don't change"
    if update.aws_access_key_id is not None:
        patch["aws_access_key_id"] = update.aws_access_key_id or None
    if update.aws_secret_access_key is not None:
        patch["aws_secret_access_key"] = update.aws_secret_access_key or None
    if update.azure_client_secret is not None:
        patch["azure_client_secret"] = update.azure_client_secret or None
    if update.gcp_service_account_json is not None:
        patch["gcp_service_account_json"] = update.gcp_service_account_json or None
    if update.kubeconfig is not None:
        patch["kubeconfig"] = update.kubeconfig or None
    try:
        db.collection("tenant_config").update(patch)
        return get_provider(db, provider_id)
    except Exception:
        return None


def delete_provider(db: StandardDatabase, provider_id: str) -> bool:
    if not db.has_collection("tenant_config"):
        return False
    try:
        db.collection("tenant_config").delete(provider_id)
        return True
    except Exception:
        return False


def update_provider_last_discovery(db: StandardDatabase, provider_id: str, job_id: str) -> None:
    if not db.has_collection("tenant_config"):
        return
    db.collection("tenant_config").update({
        "_key": provider_id,
        "last_discovery_at": datetime.now(timezone.utc).isoformat(),
        "last_discovery_job_id": job_id,
        "status": "active",
    })
