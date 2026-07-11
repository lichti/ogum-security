"""
STORES_SENSITIVE_DATA edges — admin identities to all data assets.

Moved from workers/tasks/discovery.py (as part of retiring native discovery
in favor of Prowler as the single source of truth for inventory). Logic is
unchanged: both identity and data_asset keys are resolved from the DB rather
than reused from in-memory objects, since Prowler CSPM may create these
documents with different keys than the old discovery code did.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def _upsert_edge(
    db: Any,
    collection: str,
    from_id: str,
    to_id: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Idempotent edge upsert keyed on (_from, _to)."""
    now = datetime.now(UTC).isoformat()
    doc = {
        "_from": from_id,
        "_to": to_id,
        "created_at": now,
        "updated_at": now,
        **(extra or {}),
    }
    db.aql.execute(
        """
        UPSERT { _from: @from_id, _to: @to_id }
        INSERT @doc
        UPDATE { updated_at: @now }
        IN @@collection
        """,
        bind_vars={
            "@collection": collection,
            "from_id": from_id,
            "to_id": to_id,
            "doc": doc,
            "now": now,
        },
    )


def build_data_access_edges(db: Any, tenant_id: str) -> int:
    """
    Create STORES_SENSITIVE_DATA edges from admin identities to all data assets.

    Both identity and data_asset keys are resolved from the DB to handle the
    case where Prowler CSPM created the document with a hash key while some
    other path used a structured key — using a precomputed key would create
    dangling edge _from refs.
    """
    identity_aql = """
    FOR i IN identities
        FILTER i.tenant_id == @tenant_id
        FILTER i.has_admin_policy == true
        FILTER i.status != "deleted"
        RETURN i._key
    """
    cursor = db.aql.execute(identity_aql, bind_vars={"tenant_id": tenant_id})
    admin_keys = list(cursor)

    if not admin_keys:
        return 0

    data_aql = """
    FOR d IN data_assets
        FILTER d.tenant_id == @tenant_id
        FILTER d.status != "deleted"
        RETURN d._key
    """
    cursor = db.aql.execute(data_aql, bind_vars={"tenant_id": tenant_id})
    data_asset_keys = list(cursor)

    if not data_asset_keys:
        return 0

    extra = {"tenant_id": tenant_id}
    count = 0
    for identity_key in admin_keys:
        for asset_key in data_asset_keys:
            _upsert_edge(
                db,
                "STORES_SENSITIVE_DATA",
                f"identities/{identity_key}",
                f"data_assets/{asset_key}",
                extra,
            )
            count += 1

    return count
