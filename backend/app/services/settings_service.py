from __future__ import annotations

from datetime import UTC, datetime

from arango.database import StandardDatabase

from app.models.settings import SLASettings, SLASettingsUpdateRequest

_SLA_KEY = "sla"


def _ensure_collection(db: StandardDatabase) -> None:
    if not db.has_collection("settings"):
        db.create_collection("settings")


def get_sla_settings(db: StandardDatabase) -> SLASettings:
    _ensure_collection(db)
    collection = db.collection("settings")
    doc = collection.get(_SLA_KEY)
    if not doc:
        return SLASettings()
    return SLASettings(**{k: v for k, v in doc.items() if k not in ("_key", "_id", "_rev", "updated_at")})


def update_sla_settings(db: StandardDatabase, request: SLASettingsUpdateRequest) -> SLASettings:
    _ensure_collection(db)
    collection = db.collection("settings")
    current = get_sla_settings(db)
    changes = request.model_dump(exclude_unset=True, exclude_none=True)
    updated = current.model_copy(update=changes)

    doc = {"_key": _SLA_KEY, **updated.model_dump(), "updated_at": datetime.now(UTC).isoformat()}
    if collection.has(_SLA_KEY):
        collection.update(doc)
    else:
        collection.insert(doc)
    return updated
