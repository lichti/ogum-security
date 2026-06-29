from __future__ import annotations

from typing import Any

from arango.database import StandardDatabase

from app.models.api_responses import EdgeSummary, InventoryStats, ResourceDetail, ResourceSummary

_EDGE_COLLECTIONS = [
    "BELONGS_TO",
    "ATTACHED_TO",
    "ROUTES_TRAFFIC",
    "ASSUMES_ROLE",
    "MEMBER_OF",
    "EXPOSED_TO",
    "CONTAINS_BUG",
    "STORES_SENSITIVE_DATA",
]

_ALLOWED_SORT_FIELDS = {"name", "updated_at", "last_scanned_at"}


def _doc_to_summary(doc: dict[str, Any]) -> ResourceSummary:
    last_scanned = doc.get("last_scanned_at")
    updated = doc.get("updated_at")

    def _to_iso(v: Any) -> str | None:
        if v is None:
            return None
        if isinstance(v, str):
            return v
        return str(v)

    return ResourceSummary(
        key=doc["_key"],
        tenant_id=doc.get("tenant_id", ""),
        provider=doc.get("provider", ""),
        resource_type=doc.get("resource_type", ""),
        resource_id=doc.get("resource_id", ""),
        name=doc.get("name", ""),
        region=doc.get("region"),
        account_id=doc.get("account_id"),
        status=doc.get("status", "active"),
        is_public=doc.get("is_public", False),
        tags=doc.get("tags") or {},
        last_scanned_at=_to_iso(last_scanned),
        updated_at=_to_iso(updated),
    )


def list_resources(
    db: StandardDatabase,
    tenant_id: str,
    *,
    provider: str | None = None,
    resource_type: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str = "name",
    sort_dir: str = "asc",
) -> tuple[list[ResourceSummary], int]:
    filter_clauses: list[str] = [
        "FILTER r.tenant_id == @tenant_id",
    ]
    bind_vars: dict[str, Any] = {"tenant_id": tenant_id}

    if status:
        filter_clauses.append("FILTER r.status == @status")
        bind_vars["status"] = status
    else:
        filter_clauses.append("FILTER r.status != 'deleted'")

    if provider:
        filter_clauses.append("FILTER r.provider == @provider")
        bind_vars["provider"] = provider

    if resource_type:
        filter_clauses.append("FILTER r.resource_type == @resource_type")
        bind_vars["resource_type"] = resource_type

    if account_id:
        filter_clauses.append("FILTER r.account_id == @account_id")
        bind_vars["account_id"] = account_id

    if region:
        filter_clauses.append("FILTER r.region == @region")
        bind_vars["region"] = region

    if search:
        filter_clauses.append(
            "FILTER CONTAINS(LOWER(r.name), LOWER(@search))"
            " OR CONTAINS(LOWER(r.resource_id), LOWER(@search))"
            " OR (r.arn != null AND CONTAINS(LOWER(r.arn), LOWER(@search)))"
        )
        bind_vars["search"] = search

    sort_field = sort_by if sort_by in _ALLOWED_SORT_FIELDS else "name"
    sort_direction = "DESC" if sort_dir == "desc" else "ASC"
    filter_str = "\n    ".join(filter_clauses)

    aql = f"""
LET total = LENGTH(
  FOR r IN resources
    {filter_str}
    RETURN 1
)
LET items = (
  FOR r IN resources
    {filter_str}
    SORT r.{sort_field} {sort_direction}
    LIMIT @offset, @limit
    RETURN r
)
RETURN {{ total, items }}
"""
    bind_vars["offset"] = offset
    bind_vars["limit"] = limit

    cursor = db.aql.execute(aql, bind_vars=bind_vars)
    result = next(cursor, None)
    if result is None:
        return [], 0

    total: int = result.get("total", 0)
    items: list[ResourceSummary] = [_doc_to_summary(doc) for doc in result.get("items", [])]
    return items, total


def get_resource(
    db: StandardDatabase,
    tenant_id: str,
    resource_key: str,
) -> ResourceDetail | None:
    if not db.has_collection("resources"):
        return None

    col = db.collection("resources")
    try:
        doc = col.get(resource_key)
    except Exception:
        return None

    if doc is None:
        return None

    if doc.get("tenant_id") != tenant_id:
        return None

    edges: list[EdgeSummary] = []
    from_id = f"resources/{resource_key}"
    to_id = f"resources/{resource_key}"

    for coll in _EDGE_COLLECTIONS:
        if not db.has_collection(coll):
            continue

        outbound = db.aql.execute(
            "FOR e IN @@coll FILTER e._from == @from_id RETURN e",
            bind_vars={"@coll": coll, "from_id": from_id},
        )
        for e in outbound:
            raw_to = e.get("_to", "")
            parts = raw_to.split("/", 1)
            peer_collection = parts[0] if len(parts) == 2 else "resources"
            peer_key = parts[1] if len(parts) == 2 else raw_to
            edges.append(
                EdgeSummary(
                    edge_type=coll,
                    direction="outbound",
                    peer_key=peer_key,
                    peer_collection=peer_collection,
                    peer_type=None,
                )
            )

        inbound = db.aql.execute(
            "FOR e IN @@coll FILTER e._to == @to_id RETURN e",
            bind_vars={"@coll": coll, "to_id": to_id},
        )
        for e in inbound:
            raw_from = e.get("_from", "")
            parts = raw_from.split("/", 1)
            peer_collection = parts[0] if len(parts) == 2 else "resources"
            peer_key = parts[1] if len(parts) == 2 else raw_from
            edges.append(
                EdgeSummary(
                    edge_type=coll,
                    direction="inbound",
                    peer_key=peer_key,
                    peer_collection=peer_collection,
                    peer_type=None,
                )
            )

    def _to_iso(v: Any) -> str | None:
        if v is None:
            return None
        if isinstance(v, str):
            return v
        return str(v)

    return ResourceDetail(
        key=doc["_key"],
        tenant_id=doc.get("tenant_id", ""),
        provider=doc.get("provider", ""),
        resource_type=doc.get("resource_type", ""),
        resource_id=doc.get("resource_id", ""),
        name=doc.get("name", ""),
        region=doc.get("region"),
        account_id=doc.get("account_id"),
        status=doc.get("status", "active"),
        is_public=doc.get("is_public", False),
        tags=doc.get("tags") or {},
        last_scanned_at=_to_iso(doc.get("last_scanned_at")),
        updated_at=_to_iso(doc.get("updated_at")),
        arn=doc.get("arn"),
        raw_metadata=doc.get("raw_metadata") or {},
        edges=edges,
    )


def get_inventory_stats(
    db: StandardDatabase,
    tenant_id: str,
) -> InventoryStats:
    by_provider: dict[str, int] = {}
    by_resource_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    identity_count = 0
    data_asset_count = 0
    last_discovery_at: str | None = None

    if db.has_collection("resources"):
        provider_cursor = db.aql.execute(
            """
            FOR r IN resources
              FILTER r.tenant_id == @tenant_id
              COLLECT provider = r.provider WITH COUNT INTO cnt
              RETURN { provider, cnt }
            """,
            bind_vars={"tenant_id": tenant_id},
        )
        for row in provider_cursor:
            by_provider[row["provider"]] = row["cnt"]

        type_cursor = db.aql.execute(
            """
            FOR r IN resources
              FILTER r.tenant_id == @tenant_id
              FILTER r.status != 'deleted'
              COLLECT resource_type = r.resource_type WITH COUNT INTO cnt
              RETURN { resource_type, cnt }
            """,
            bind_vars={"tenant_id": tenant_id},
        )
        for row in type_cursor:
            by_resource_type[row["resource_type"]] = row["cnt"]

        status_cursor = db.aql.execute(
            """
            FOR r IN resources
              FILTER r.tenant_id == @tenant_id
              COLLECT status = r.status WITH COUNT INTO cnt
              RETURN { status, cnt }
            """,
            bind_vars={"tenant_id": tenant_id},
        )
        for row in status_cursor:
            by_status[row["status"]] = row["cnt"]

        freshness_cursor = db.aql.execute(
            """
            FOR r IN resources
              FILTER r.tenant_id == @tenant_id
              SORT r.updated_at DESC
              LIMIT 1
              RETURN r.updated_at
            """,
            bind_vars={"tenant_id": tenant_id},
        )
        val = next(freshness_cursor, None)
        if val is not None:
            last_discovery_at = str(val) if not isinstance(val, str) else val

    if db.has_collection("identities"):
        id_cursor = db.aql.execute(
            "FOR i IN identities FILTER i.tenant_id == @tenant_id COLLECT WITH COUNT INTO cnt RETURN cnt",
            bind_vars={"tenant_id": tenant_id},
        )
        identity_count = next(id_cursor, 0) or 0

    if db.has_collection("data_assets"):
        da_cursor = db.aql.execute(
            "FOR d IN data_assets FILTER d.tenant_id == @tenant_id COLLECT WITH COUNT INTO cnt RETURN cnt",
            bind_vars={"tenant_id": tenant_id},
        )
        data_asset_count = next(da_cursor, 0) or 0

    return InventoryStats(
        by_provider=by_provider,
        by_resource_type=by_resource_type,
        by_status=by_status,
        identity_count=identity_count,
        data_asset_count=data_asset_count,
        last_discovery_at=last_discovery_at,
    )
