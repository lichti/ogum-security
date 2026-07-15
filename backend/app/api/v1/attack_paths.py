"""Attack Paths API — list, detail, stats and MITRE intelligence endpoints for Ogum.Graph."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.attack_path_narrative import PathNarrativeSummary
from app.services.admin_service import get_admin_db
from app.services.attack_path_enrichment import enrich_path_rows
from app.services.attack_path_narrative_service import build_path_narrative
from app.services.mitre_service import get_techniques_for_path
from app.services.resource_categories import category_of, resource_types_for_category

router = APIRouter(prefix="/api/v1/attack-paths", tags=["attack-paths"])

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_VALID_CROWN_JEWEL_REASONS = {"internet_facing", "stores_sensitive_data", "high_privilege_identity", "manually_flagged"}

# Mirrors attack_path_enrichment.derive_crown_jewel_reason's priority chain in AQL,
# so `target_crown_jewel_reason` filtering (list) and aggregation (stats) don't need
# to fetch+enrich every row in Python just to filter/group by it. Keep both in lockstep.
_CROWN_JEWEL_REASON_LET = """
    LET reason = (
        target.is_crown_jewel != true ? null :
        (target.is_public == true OR target.exposed_internet == true) ? "internet_facing" :
        (target.contains_credentials == true OR target.contains_secrets == true) ? "stores_sensitive_data" :
        target.has_admin_policy == true ? "high_privilege_identity" :
        "manually_flagged"
    )
"""

_TARGET_ENRICHMENT_RETURN = """
        target_resource_type: target.resource_type,
        target_is_public: target.is_public,
        target_exposed_internet: target.exposed_internet,
        target_is_crown_jewel: target.is_crown_jewel,
        target_has_admin_policy: target.has_admin_policy,
        target_contains_credentials: target.contains_credentials,
        target_contains_secrets: target.contains_secrets
"""


class PagedAttackPaths(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None
    count: int


class AttackPathDetail(BaseModel):
    path: dict[str, Any]
    nodes: list[dict[str, Any]]
    findings: list[dict[str, Any]]


class AttackPathStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    new_24h: int
    by_target_asset_category: dict[str, int] = {}
    by_target_crown_jewel_reason: dict[str, int] = {}


def _encode_cursor(risk_score: float, key: str) -> str:
    payload = json.dumps({"risk_score": risk_score, "_key": key})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _decode_cursor(cursor: str) -> dict[str, Any] | None:
    try:
        result = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        return result if isinstance(result, dict) else None
    except Exception:
        return None


@router.get("", response_model=ApiResponse[PagedAttackPaths])
async def list_attack_paths(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
    severity: str | None = Query(default=None),
    is_toxic_combination: bool | None = Query(default=None),
    provider: str | None = Query(default=None),
    actively_exploited: bool | None = Query(default=None),
    target_asset_category: str | None = Query(default=None),
    target_crown_jewel_reason: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> ApiResponse[PagedAttackPaths]:
    if severity and severity.upper() not in _VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(_VALID_SEVERITIES)}")
    if target_crown_jewel_reason and target_crown_jewel_reason not in _VALID_CROWN_JEWEL_REASONS:
        raise HTTPException(
            status_code=422, detail=f"target_crown_jewel_reason must be one of {sorted(_VALID_CROWN_JEWEL_REASONS)}"
        )

    filters = ["ap.tenant_id == @tenant_id"]
    bind: dict[str, Any] = {"tenant_id": x_tenant_id, "fetch_limit": limit + 1}

    if severity:
        filters.append("ap.severity == @severity")
        bind["severity"] = severity.upper()

    if is_toxic_combination is not None:
        filters.append("ap.is_toxic_combination == @toxic")
        bind["toxic"] = is_toxic_combination

    if provider:
        filters.append("CONTAINS(LOWER(ap.entry_point_type), @provider) OR CONTAINS(LOWER(ap.target_type), @provider)")
        bind["provider"] = provider.lower()

    if actively_exploited is not None:
        filters.append("ap.actively_exploited == @actively_exploited")
        bind["actively_exploited"] = actively_exploited

    if target_asset_category:
        filters.append("target.resource_type IN @target_types")
        bind["target_types"] = resource_types_for_category(target_asset_category)

    if target_crown_jewel_reason:
        filters.append("reason == @crown_jewel_reason")
        bind["crown_jewel_reason"] = target_crown_jewel_reason

    cursor_clause = ""
    if cursor:
        c = _decode_cursor(cursor)
        if c and "risk_score" in c and "_key" in c:
            cursor_clause = (
                "FILTER (ap.risk_score < @cur_score) OR (ap.risk_score == @cur_score AND ap._key < @cur_key)"
            )
            bind["cur_score"] = float(c["risk_score"])
            bind["cur_key"] = str(c["_key"])

    filter_clause = "\n        ".join(f"FILTER {f}" for f in filters)
    aql = f"""
    FOR ap IN attack_paths
        LET target = DOCUMENT(ap.target_id)
        {_CROWN_JEWEL_REASON_LET}
        {filter_clause}
        {cursor_clause}
        SORT ap.risk_score DESC, ap._key DESC
        LIMIT @fetch_limit
        RETURN MERGE(ap, {{{_TARGET_ENRICHMENT_RETURN}}})
    """

    rows: list[dict[str, Any]] = list(db.aql.execute(aql, bind_vars=bind))
    next_cursor: str | None = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_cursor(float(last.get("risk_score", 0)), last["_key"])

    return ApiResponse(data=PagedAttackPaths(items=enrich_path_rows(rows), next_cursor=next_cursor, count=len(rows)))


@router.get("/stats", response_model=ApiResponse[AttackPathStats])
async def get_attack_path_stats(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[AttackPathStats]:
    since_24h = (datetime.now(UTC) - timedelta(hours=24)).isoformat()

    aql = f"""
    LET agg = (
        FOR ap IN attack_paths
            FILTER ap.tenant_id == @tenant_id
            COLLECT severity = ap.severity WITH COUNT INTO cnt
            RETURN {{severity, cnt}}
    )
    LET by_category = (
        FOR ap IN attack_paths
            FILTER ap.tenant_id == @tenant_id
            LET target = DOCUMENT(ap.target_id)
            COLLECT resource_type = target.resource_type WITH COUNT INTO cnt
            RETURN {{resource_type, cnt}}
    )
    LET by_reason = (
        FOR ap IN attack_paths
            FILTER ap.tenant_id == @tenant_id
            LET target = DOCUMENT(ap.target_id)
            {_CROWN_JEWEL_REASON_LET}
            FILTER reason != null
            COLLECT r = reason WITH COUNT INTO cnt
            RETURN {{reason: r, cnt}}
    )
    LET new_24h = LENGTH(
        FOR ap IN attack_paths
            FILTER ap.tenant_id == @tenant_id
            FILTER ap.detected_at >= @since
            RETURN 1
    )
    RETURN {{agg, by_category, by_reason, new_24h}}
    """
    rows = list(db.aql.execute(aql, bind_vars={"tenant_id": x_tenant_id, "since": since_24h}))
    result = rows[0] if rows else {"agg": [], "by_category": [], "by_reason": [], "new_24h": 0}

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = 0
    for item in result.get("agg", []):
        sev = (item.get("severity") or "").upper()
        cnt = int(item.get("cnt", 0))
        if sev in by_severity:
            by_severity[sev] += cnt
        total += cnt

    by_target_asset_category: dict[str, int] = {}
    for item in result.get("by_category", []):
        category = category_of(item.get("resource_type"))
        by_target_asset_category[category] = by_target_asset_category.get(category, 0) + int(item.get("cnt", 0))

    by_target_crown_jewel_reason: dict[str, int] = {
        item["reason"]: int(item.get("cnt", 0)) for item in result.get("by_reason", []) if item.get("reason")
    }

    return ApiResponse(
        data=AttackPathStats(
            total=total,
            by_severity=by_severity,
            new_24h=int(result.get("new_24h", 0)),
            by_target_asset_category=by_target_asset_category,
            by_target_crown_jewel_reason=by_target_crown_jewel_reason,
        )
    )


@router.get("/{path_id}/mitre", response_model=ApiResponse[dict])
async def get_attack_path_mitre(
    path_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    """Return MITRE ATT&CK techniques, tactics and APT groups for an attack path."""
    path_doc: dict[str, Any] | None = None
    try:
        result = db.collection("attack_paths").get(path_id)
        if isinstance(result, dict):
            path_doc = result
    except Exception:
        pass

    if not path_doc or path_doc.get("tenant_id") != x_tenant_id:
        raise HTTPException(status_code=404, detail="Attack path not found")

    try:
        admin_db = get_admin_db()
    except Exception:
        admin_db = None

    mitre_data = get_techniques_for_path(path_doc, admin_db)
    return ApiResponse(data=mitre_data)


def _load_enriched_path_doc(db: StandardDatabase, x_tenant_id: str, path_id: str) -> dict[str, Any] | None:
    path_doc: dict[str, Any] | None = None
    try:
        result = db.collection("attack_paths").get(path_id)
        if isinstance(result, dict):
            path_doc = result
    except Exception:
        pass

    if not path_doc or path_doc.get("tenant_id") != x_tenant_id:
        return None

    target_doc: dict[str, Any] = {}
    try:
        resolved = db.document(path_doc["target_id"])
        target_doc = resolved if isinstance(resolved, dict) else {}
    except Exception:
        pass
    enrichable = dict(path_doc)
    for field, source in (
        ("target_resource_type", "resource_type"),
        ("target_is_public", "is_public"),
        ("target_exposed_internet", "exposed_internet"),
        ("target_is_crown_jewel", "is_crown_jewel"),
        ("target_has_admin_policy", "has_admin_policy"),
        ("target_contains_credentials", "contains_credentials"),
        ("target_contains_secrets", "contains_secrets"),
    ):
        enrichable[field] = target_doc.get(source)
    return enrich_path_rows([enrichable])[0]


def _load_findings_for_path(db: StandardDatabase, x_tenant_id: str, path_vertex_ids: list[str]) -> list[dict[str, Any]]:
    if not path_vertex_ids:
        return []
    find_aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.resource_id IN @vertex_ids
        SORT f.severity ASC
        LIMIT 20
        RETURN f
    """
    return list(db.aql.execute(find_aql, bind_vars={"tenant_id": x_tenant_id, "vertex_ids": path_vertex_ids}))


@router.get("/{path_id}", response_model=ApiResponse[AttackPathDetail])
async def get_attack_path_detail(
    path_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[AttackPathDetail]:
    path_doc = _load_enriched_path_doc(db, x_tenant_id, path_id)
    if not path_doc:
        raise HTTPException(status_code=404, detail="Attack path not found")

    # Load each vertex document in the path
    nodes: list[dict[str, Any]] = []
    path_vertex_ids: list[str] = path_doc.get("path_vertex_ids", [])
    for vid in path_vertex_ids:
        try:
            node = db.document(vid)
            nodes.append(node if isinstance(node, dict) else {"_id": vid, "error": "not_found"})
        except Exception:
            nodes.append({"_id": vid, "error": "not_found"})

    findings = _load_findings_for_path(db, x_tenant_id, path_vertex_ids)

    return ApiResponse(data=AttackPathDetail(path=path_doc, nodes=nodes, findings=findings))


@router.get("/{path_id}/narrative", response_model=ApiResponse[PathNarrativeSummary])
async def get_attack_path_narrative(
    path_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[PathNarrativeSummary]:
    path_doc = _load_enriched_path_doc(db, x_tenant_id, path_id)
    if not path_doc:
        raise HTTPException(status_code=404, detail="Attack path not found")

    findings = _load_findings_for_path(db, x_tenant_id, path_doc.get("path_vertex_ids", []))
    return ApiResponse(data=build_path_narrative(path_doc, findings))
