"""Business logic for findings queries and status mutations."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from arango.database import StandardDatabase

from app.models.finding import FindingStatus


def _encode_cursor(detected_at: str, key: str) -> str:
    payload = json.dumps({"detected_at": detected_at, "_key": key})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _decode_cursor(cursor: str) -> dict[str, str] | None:
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        return None


def list_findings(
    db: StandardDatabase,
    tenant_id: str,
    *,
    provider: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    framework: str | None = None,
    region: str | None = None,
    account_id: str | None = None,
    resource_type: str | None = None,
    source: str | None = None,
    q: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Return (findings, next_cursor). Keyset pagination on (detected_at DESC, _key DESC)."""
    filters = ["f.tenant_id == @tenant_id"]
    bind: dict[str, Any] = {"tenant_id": tenant_id, "fetch_limit": limit + 1}

    if provider:
        filters.append("f.provider == @provider")
        bind["provider"] = provider
    if severity:
        filters.append("f.severity == @severity")
        bind["severity"] = severity
    if status:
        filters.append("f.status == @status")
        bind["status"] = status
    if framework:
        filters.append("@framework IN f.framework_mapping")
        bind["framework"] = framework
    if region:
        filters.append("f.region == @region")
        bind["region"] = region
    if account_id:
        filters.append("f.account_id == @account_id")
        bind["account_id"] = account_id
    if resource_type:
        filters.append("f.resource_type == @resource_type")
        bind["resource_type"] = resource_type
    if source:
        filters.append("f.source == @source")
        bind["source"] = source
    if q:
        filters.append(
            "(CONTAINS(LOWER(f.title), LOWER(@q)) OR "
            "CONTAINS(LOWER(f.check_id), LOWER(@q)) OR "
            "CONTAINS(f.resource_arn, @q))"
        )
        bind["q"] = q

    cursor_clause = ""
    if cursor:
        c = _decode_cursor(cursor)
        if c:
            cursor_clause = (
                "FILTER (f.detected_at < @cur_date) OR "
                "(f.detected_at == @cur_date AND f._key < @cur_key)"
            )
            bind["cur_date"] = c["detected_at"]
            bind["cur_key"] = c["_key"]

    filter_block = "\n            ".join(f"FILTER {f}" for f in filters)

    aql = f"""
        FOR f IN findings
            {filter_block}
            {cursor_clause}
            SORT f.detected_at DESC, f._key DESC
            LIMIT @fetch_limit
            RETURN UNSET(f, "_id", "_rev")
    """

    rows: list[dict[str, Any]] = list(db.aql.execute(aql, bind_vars=bind))  # type: ignore[arg-type]

    next_cursor: str | None = None
    if len(rows) == limit + 1:
        last = rows[limit]
        next_cursor = _encode_cursor(last["detected_at"], last["_key"])
        rows = rows[:limit]

    return rows, next_cursor


def get_finding(
    db: StandardDatabase,
    finding_key: str,
    tenant_id: str,
) -> dict[str, Any] | None:
    try:
        doc = db.collection("findings").get(finding_key)
    except Exception:
        return None
    if doc is None or doc.get("tenant_id") != tenant_id:
        return None

    # Strip ArangoDB internal fields
    for field in ("_id", "_rev"):
        doc.pop(field, None)

    # Enrich with linked resource info
    try:
        resources = list(
            db.aql.execute(
                "FOR r IN resources FILTER r.resource_id == @rid AND r.tenant_id == @tid LIMIT 1 "
                "RETURN {name: r.name, arn: r.arn, resource_type: r.resource_type, "
                "region: r.region, account_id: r.account_id}",
                bind_vars={"rid": doc.get("resource_id", ""), "tid": tenant_id},
            )
        )
        doc["resource"] = resources[0] if resources else None
    except Exception:
        doc["resource"] = None

    # Placeholder — attack paths implemented in Epic 02 (Ogum.Graph)
    doc["attack_paths"] = []

    return doc


def update_finding_status(
    db: StandardDatabase,
    finding_key: str,
    tenant_id: str,
    new_status: str,
    reason: str | None = None,
) -> dict[str, Any] | None:
    doc = db.collection("findings").get(finding_key)
    if doc is None or doc.get("tenant_id") != tenant_id:
        return None

    if new_status not in (FindingStatus.MUTED, FindingStatus.ACCEPTED):
        return None

    now = datetime.now(UTC).isoformat()
    update: dict[str, Any] = {"_key": finding_key, "status": new_status, "updated_at": now}
    if new_status == FindingStatus.MUTED:
        update["mute_reason"] = reason

    db.collection("findings").update(update)

    try:
        if db.has_collection("audit_log"):
            db.collection("audit_log").insert(
                {
                    "tenant_id": tenant_id,
                    "finding_key": finding_key,
                    "action": f"status_changed_to_{new_status}",
                    "reason": reason,
                    "timestamp": now,
                }
            )
    except Exception:
        pass  # audit failure must not block the status update

    return get_finding(db, finding_key, tenant_id)
