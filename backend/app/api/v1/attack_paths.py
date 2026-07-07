"""Attack Paths API — list, detail and stats endpoints for Ogum.Graph (Epic 02 Sprint 2)."""

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

router = APIRouter(prefix="/api/v1/attack-paths", tags=["attack-paths"])

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


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
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> ApiResponse[PagedAttackPaths]:
    if severity and severity.upper() not in _VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(_VALID_SEVERITIES)}")

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
        {filter_clause}
        {cursor_clause}
        SORT ap.risk_score DESC, ap._key DESC
        LIMIT @fetch_limit
        RETURN ap
    """

    rows: list[dict[str, Any]] = list(db.aql.execute(aql, bind_vars=bind))
    next_cursor: str | None = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_cursor(float(last.get("risk_score", 0)), last["_key"])

    return ApiResponse(data=PagedAttackPaths(items=rows, next_cursor=next_cursor, count=len(rows)))


@router.get("/stats", response_model=ApiResponse[AttackPathStats])
async def get_attack_path_stats(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[AttackPathStats]:
    since_24h = (datetime.now(UTC) - timedelta(hours=24)).isoformat()

    aql = """
    LET agg = (
        FOR ap IN attack_paths
            FILTER ap.tenant_id == @tenant_id
            COLLECT severity = ap.severity WITH COUNT INTO cnt
            RETURN {severity, cnt}
    )
    LET new_24h = LENGTH(
        FOR ap IN attack_paths
            FILTER ap.tenant_id == @tenant_id
            FILTER ap.detected_at >= @since
            RETURN 1
    )
    RETURN {agg, new_24h}
    """
    rows = list(db.aql.execute(aql, bind_vars={"tenant_id": x_tenant_id, "since": since_24h}))
    result = rows[0] if rows else {"agg": [], "new_24h": 0}

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = 0
    for item in result.get("agg", []):
        sev = (item.get("severity") or "").upper()
        cnt = int(item.get("cnt", 0))
        if sev in by_severity:
            by_severity[sev] += cnt
        total += cnt

    return ApiResponse(
        data=AttackPathStats(total=total, by_severity=by_severity, new_24h=int(result.get("new_24h", 0)))
    )


@router.get("/{path_id}", response_model=ApiResponse[AttackPathDetail])
async def get_attack_path_detail(
    path_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[AttackPathDetail]:
    try:
        path_doc: dict[str, Any] | None = db.collection("attack_paths").get(path_id)
    except Exception:
        path_doc = None

    if not path_doc or path_doc.get("tenant_id") != x_tenant_id:
        raise HTTPException(status_code=404, detail="Attack path not found")

    # Load each vertex document in the path
    nodes: list[dict[str, Any]] = []
    path_vertex_ids: list[str] = path_doc.get("path_vertex_ids", [])
    for vid in path_vertex_ids:
        try:
            node = db.document(vid)
            nodes.append(node)
        except Exception:
            nodes.append({"_id": vid, "error": "not_found"})

    # Load findings associated with resources in the path
    findings: list[dict[str, Any]] = []
    if path_vertex_ids:
        find_aql = """
        FOR f IN findings
            FILTER f.tenant_id == @tenant_id
            FILTER f.resource_id IN @vertex_ids
            SORT f.severity ASC
            LIMIT 20
            RETURN f
        """
        findings = list(db.aql.execute(find_aql, bind_vars={"tenant_id": x_tenant_id, "vertex_ids": path_vertex_ids}))

    return ApiResponse(data=AttackPathDetail(path=path_doc, nodes=nodes, findings=findings))
