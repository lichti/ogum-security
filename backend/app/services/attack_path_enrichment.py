"""
Read-time enrichment of attack path rows with target-derived fields (US-14.11).

`target_asset_category` and `target_crown_jewel_reason` are computed here,
not persisted on the attack_paths document — the target resource's crown-jewel
flag and type can change out-of-band (e.g. via the Crown Jewel toggle in
Inventory) between path detection runs, so persisting them would go stale
without a full re-detection. The list/stats/detail endpoints resolve the
target document fresh via AQL `DOCUMENT()` and pass it through here.
"""

from __future__ import annotations

from typing import Any

from app.services.resource_categories import category_of

_TARGET_SOURCE_FIELDS = (
    "target_resource_type",
    "target_is_public",
    "target_exposed_internet",
    "target_is_crown_jewel",
    "target_has_admin_policy",
    "target_contains_credentials",
    "target_contains_secrets",
)


def derive_crown_jewel_reason(row: dict[str, Any]) -> str | None:
    """Honest fallback chain — never fabricates a reason with no real signal."""
    if not row.get("target_is_crown_jewel"):
        return None
    if row.get("target_is_public") or row.get("target_exposed_internet"):
        return "internet_facing"
    if row.get("target_contains_credentials") or row.get("target_contains_secrets"):
        return "stores_sensitive_data"
    if row.get("target_has_admin_policy"):
        return "high_privilege_identity"
    return "manually_flagged"


def enrich_path_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add `target_asset_category`/`target_crown_jewel_reason`, strip intermediate fields."""
    enriched: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["target_asset_category"] = category_of(item.get("target_resource_type"))
        item["target_crown_jewel_reason"] = derive_crown_jewel_reason(item)
        for field in _TARGET_SOURCE_FIELDS:
            item.pop(field, None)
        enriched.append(item)
    return enriched
