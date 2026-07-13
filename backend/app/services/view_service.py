from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from arango.database import StandardDatabase

from app.models.views import SavedView, SavedViewCreateRequest, SavedViewUpdateRequest, ViewScope

SYSTEM_OWNER = "system"

# Curated system views, one per recurring risk category (specs/ui-design.md §2.17).
_SYSTEM_VIEWS: list[dict[str, Any]] = [
    {
        "_key": "system-internet-facing-critical",
        "scope": "inventory",
        "name": "Internet-Facing Critical Assets",
        "filters": {"exposure": ["internet_facing"], "crown_jewel": True},
    },
    {
        "_key": "system-unencrypted-data-storage",
        "scope": "inventory",
        "name": "Unencrypted Data Storage",
        "filters": {"resource_type": ["s3_bucket", "rds_instance", "ebs_volume"], "encrypted": False},
    },
    {
        "_key": "system-overly-permissive-iam",
        "scope": "inventory",
        "name": "Overly Permissive IAM Roles",
        "filters": {"resource_type": ["iam_role"], "dangerous_permissions": True},
    },
]


def _ensure_collection(db: StandardDatabase) -> None:
    if not db.has_collection("views"):
        db.create_collection("views")


def _seed_system_views(db: StandardDatabase) -> None:
    _ensure_collection(db)
    collection = db.collection("views")
    now = datetime.now(UTC).isoformat()
    for seed in _SYSTEM_VIEWS:
        if collection.has(seed["_key"]):
            continue
        collection.insert(
            {
                **seed,
                "columns": None,
                "owner": SYSTEM_OWNER,
                "is_system": True,
                "pinned": False,
                "created_at": now,
                "updated_at": now,
            }
        )


def _doc_to_view(doc: dict[str, Any]) -> SavedView:
    return SavedView(key=doc["_key"], **{k: v for k, v in doc.items() if k not in ("_key", "_id", "_rev")})


def list_views(db: StandardDatabase, owner: str, scope: ViewScope | None = None) -> list[SavedView]:
    _seed_system_views(db)
    cursor = db.aql.execute(
        "FOR v IN views FILTER v.owner == @owner OR v.owner == @system_owner "
        "FILTER @scope == null OR v.scope == @scope "
        "SORT v.pinned DESC, v.is_system DESC, v.name ASC RETURN v",
        bind_vars={"owner": owner, "system_owner": SYSTEM_OWNER, "scope": scope},
    )
    return [_doc_to_view(doc) for doc in cursor]


def create_view(db: StandardDatabase, owner: str, request: SavedViewCreateRequest) -> SavedView:
    _ensure_collection(db)
    now = datetime.now(UTC).isoformat()
    doc = {
        "_key": str(uuid.uuid4()),
        "scope": request.scope,
        "name": request.name,
        "filters": request.filters,
        "columns": request.columns,
        "owner": owner,
        "is_system": False,
        "pinned": False,
        "created_at": now,
        "updated_at": now,
    }
    db.collection("views").insert(doc)
    return _doc_to_view(doc)


def get_view(db: StandardDatabase, view_id: str) -> SavedView | None:
    _seed_system_views(db)
    doc = db.collection("views").get(view_id)
    return _doc_to_view(doc) if doc else None


def update_view(db: StandardDatabase, owner: str, view_id: str, update: SavedViewUpdateRequest) -> SavedView | None:
    """Returns None if the view doesn't exist, isn't owned by `owner`, or is a system view."""
    _ensure_collection(db)
    doc = db.collection("views").get(view_id)
    if not doc or doc["owner"] != owner or doc["is_system"]:
        return None

    changes = update.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        return _doc_to_view(doc)
    changes["updated_at"] = datetime.now(UTC).isoformat()
    db.collection("views").update({"_key": view_id, **changes})
    return _doc_to_view({**doc, **changes})


def delete_view(db: StandardDatabase, owner: str, view_id: str) -> bool:
    _ensure_collection(db)
    doc = db.collection("views").get(view_id)
    if not doc or doc["owner"] != owner or doc["is_system"]:
        return False
    db.collection("views").delete(view_id)
    return True
