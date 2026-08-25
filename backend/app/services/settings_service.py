from __future__ import annotations

from datetime import UTC, datetime

from arango.database import StandardDatabase

from app.models.settings import (
    ComplianceFamilySettings,
    ComplianceFamilySettingsUpdateRequest,
    SLASettings,
    SLASettingsUpdateRequest,
)

_SLA_KEY = "sla"
_COMPLIANCE_KEY = "compliance"


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


def get_all_compliance_family_settings(db: StandardDatabase) -> dict[str, ComplianceFamilySettings]:
    """Sparse family_key -> settings map — only families someone has explicitly
    configured (disabled, or given a target). A family absent from this dict is
    enabled with no targets, the same as `ComplianceFamilySettings()`'s defaults —
    callers must not treat absence as "unknown framework", just "untouched settings".
    """
    _ensure_collection(db)
    doc = db.collection("settings").get(_COMPLIANCE_KEY)
    if not doc:
        return {}
    return {key: ComplianceFamilySettings(**value) for key, value in doc.get("families", {}).items()}


def update_compliance_family_settings(
    db: StandardDatabase, family_key: str, request: ComplianceFamilySettingsUpdateRequest
) -> ComplianceFamilySettings:
    _ensure_collection(db)
    collection = db.collection("settings")
    families = get_all_compliance_family_settings(db)
    current = families.get(family_key, ComplianceFamilySettings())

    changes = request.model_dump(exclude={"clear_target_by_control"}, exclude_unset=True, exclude_none=True)
    updated = current.model_copy(update=changes)
    if request.clear_target_by_control:
        updated.target_by_control = None

    families[family_key] = updated
    doc = {
        "_key": _COMPLIANCE_KEY,
        "families": {key: value.model_dump() for key, value in families.items()},
        "updated_at": datetime.now(UTC).isoformat(),
    }
    if collection.has(_COMPLIANCE_KEY):
        collection.update(doc)
    else:
        collection.insert(doc)
    return updated
