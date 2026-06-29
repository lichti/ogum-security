from __future__ import annotations

from datetime import datetime, timezone

from arango.database import StandardDatabase

from app.models.provider import ProviderConfig, ProviderRegisterRequest, ProviderUpdateRequest


def _make_key(provider: str, identifier: str) -> str:
    safe = identifier.replace("/", "_").replace(":", "_")
    return f"{provider}-{safe}"[:220]


def _ensure_collection(db: StandardDatabase) -> None:
    if not db.has_collection("tenant_config"):
        db.create_collection("tenant_config")


def _doc_to_config(doc: dict) -> ProviderConfig:
    return ProviderConfig(
        key=doc["_key"],
        **{k: v for k, v in doc.items() if k not in ("_key", "_id", "_rev")},
    )


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
        "last_discovery_at": None,
        "last_discovery_job_id": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    _ensure_collection(db)
    db.collection("tenant_config").insert(doc, overwrite=True)
    return ProviderConfig(key=key, **{k: v for k, v in doc.items() if k != "_key"})


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
