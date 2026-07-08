"""
Graph API — Crown Jewels, AQL Console, Saved Queries, Shortest Path.

All endpoints are tenant-scoped via X-Tenant-Id header.
AQL console executes queries in read-only mode — INSERT/UPDATE/REMOVE/REPLACE/UPSERT are blocked.
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import UTC, datetime
from typing import Any

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.services.graph.exposure import get_exposure_summary

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])

# ── AQL read-only validation ─────────────────────────────────────────────────
# Block any statement that modifies data.
_WRITE_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|REMOVE|REPLACE|UPSERT)\b",
    re.IGNORECASE,
)

_MAX_AQL_RESULT_ROWS = 200
_MAX_SAVED_QUERIES = 50


def _validate_read_only(aql: str) -> None:
    if _WRITE_PATTERN.search(aql):
        raise HTTPException(
            status_code=422,
            detail="AQL console is read-only: INSERT/UPDATE/REMOVE/REPLACE/UPSERT are not allowed",
        )


def _inject_tenant_filter(aql: str, tenant_id: str) -> str:
    """Inject @tenant_id bind var that queries can reference as @tenant_id."""
    return aql  # user must use @tenant_id in their query; we supply it as a bind var


# ── Pydantic models ──────────────────────────────────────────────────────────


class CrownJewelRequest(BaseModel):
    is_crown_jewel: bool


class AqlRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=8000)
    bind_vars: dict[str, Any] = Field(default_factory=dict)


class AqlResult(BaseModel):
    rows: list[Any]
    count: int
    truncated: bool
    execution_ms: float | None = None


class SavedQueryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    query: str = Field(..., min_length=1, max_length=8000)
    description: str = Field(default="", max_length=500)


class SavedQuery(BaseModel):
    key: str
    name: str
    query: str
    description: str
    created_at: str
    updated_at: str


class ShortestPathResult(BaseModel):
    found: bool
    hops: int
    vertices: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class ExposureSummary(BaseModel):
    exposed_resources: int
    exposed_data_assets: int
    exposed_endpoints: int
    total: int


# ── Crown Jewels ─────────────────────────────────────────────────────────────


@router.patch("/resources/{resource_id}/crown-jewel", response_model=ApiResponse[dict])
async def set_crown_jewel(
    resource_id: str,
    body: CrownJewelRequest,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    """Mark or unmark a resource as a Crown Jewel."""
    # Try resources first, then data_assets
    updated = False
    for collection in ("resources", "data_assets"):
        try:
            doc = db.collection(collection).get(resource_id)
            if isinstance(doc, dict) and doc.get("tenant_id") == x_tenant_id:
                db.collection(collection).update({"_key": resource_id, "is_crown_jewel": body.is_crown_jewel})
                updated = True
                break
        except Exception:
            continue

    if not updated:
        raise HTTPException(status_code=404, detail="Resource not found")

    return ApiResponse(data={"resource_id": resource_id, "is_crown_jewel": body.is_crown_jewel})


@router.get("/crown-jewels", response_model=ApiResponse[list[dict]])
async def list_crown_jewels(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[dict]]:
    """List all Crown Jewel resources for the tenant."""
    aql = """
    LET cj_resources = (
        FOR r IN resources
            FILTER r.tenant_id == @tid AND r.is_crown_jewel == true
            RETURN MERGE(r, {_collection: "resources"})
    )
    LET cj_data = (
        FOR d IN data_assets
            FILTER d.tenant_id == @tid AND d.is_crown_jewel == true
            RETURN MERGE(d, {_collection: "data_assets"})
    )
    RETURN APPEND(cj_resources, cj_data)
    """
    result = list(db.aql.execute(aql, bind_vars={"tid": x_tenant_id}))
    items: list[dict] = result[0] if result else []
    return ApiResponse(data=items)


# ── AQL Console ──────────────────────────────────────────────────────────────


@router.post("/aql", response_model=ApiResponse[AqlResult])
async def execute_aql(
    body: AqlRequest,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[AqlResult]:
    """Execute a read-only AQL query scoped to the tenant database."""
    _validate_read_only(body.query)

    # Inject @tenant_id only if the query references it — ArangoDB rejects unused bind vars.
    bind_vars = dict(body.bind_vars)
    if "@tenant_id" in body.query or "tenant_id" in body.bind_vars:
        bind_vars["tenant_id"] = x_tenant_id

    start = time.monotonic()
    try:
        cursor = db.aql.execute(
            body.query,
            bind_vars=bind_vars,
            max_runtime=15,
        )
        rows: list[Any] = []
        truncated = False
        for row in cursor:
            if len(rows) >= _MAX_AQL_RESULT_ROWS:
                truncated = True
                break
            rows.append(row)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"AQL error: {exc}") from exc

    elapsed = round((time.monotonic() - start) * 1000, 2)
    return ApiResponse(data=AqlResult(rows=rows, count=len(rows), truncated=truncated, execution_ms=elapsed))


# ── Saved Queries ─────────────────────────────────────────────────────────────


def _query_key(tenant_id: str, name: str) -> str:
    return hashlib.sha256(f"{tenant_id}:{name}".encode()).hexdigest()[:24]


@router.get("/queries", response_model=ApiResponse[list[SavedQuery]])
async def list_saved_queries(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[SavedQuery]]:
    cursor = db.aql.execute(
        "FOR q IN saved_queries FILTER q.tenant_id == @tid SORT q.name ASC RETURN q",
        bind_vars={"tid": x_tenant_id},
    )
    items = [
        SavedQuery(
            key=q["_key"],
            name=q["name"],
            query=q["query"],
            description=q.get("description", ""),
            created_at=q.get("created_at", ""),
            updated_at=q.get("updated_at", ""),
        )
        for q in cursor
    ]
    return ApiResponse(data=items)


@router.post("/queries", response_model=ApiResponse[SavedQuery], status_code=201)
async def create_saved_query(
    body: SavedQueryCreate,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[SavedQuery]:
    _validate_read_only(body.query)

    # Check limit
    count_result = list(
        db.aql.execute(
            "RETURN LENGTH(FOR q IN saved_queries FILTER q.tenant_id == @tid RETURN 1)",
            bind_vars={"tid": x_tenant_id},
        )
    )
    if count_result and int(count_result[0]) >= _MAX_SAVED_QUERIES:
        raise HTTPException(status_code=422, detail=f"Maximum {_MAX_SAVED_QUERIES} saved queries per tenant")

    now = datetime.now(UTC).isoformat()
    key = _query_key(x_tenant_id, body.name)
    doc = {
        "_key": key,
        "tenant_id": x_tenant_id,
        "name": body.name,
        "query": body.query,
        "description": body.description,
        "created_at": now,
        "updated_at": now,
    }
    try:
        db.collection("saved_queries").insert(doc)
    except Exception:
        raise HTTPException(status_code=409, detail="A query with this name already exists")

    return ApiResponse(
        data=SavedQuery(
            key=key,
            name=body.name,
            query=body.query,
            description=body.description,
            created_at=now,
            updated_at=now,
        )
    )


@router.delete("/queries/{query_id}", response_model=ApiResponse[dict])
async def delete_saved_query(
    query_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    try:
        doc = db.collection("saved_queries").get(query_id)
        if not isinstance(doc, dict) or doc.get("tenant_id") != x_tenant_id:
            raise HTTPException(status_code=404, detail="Query not found")
        db.collection("saved_queries").delete(query_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="Query not found")
    return ApiResponse(data={"deleted": query_id})


# ── Shortest Path ─────────────────────────────────────────────────────────────

_GRAPH_EDGES = [
    "EXPOSED_TO",
    "ASSUMES_ROLE",
    "ROUTES_TRAFFIC",
    "BELONGS_TO",
    "ATTACHED_TO",
    "STORES_SENSITIVE_DATA",
    "STS_ASSUMEROLE_ALLOW",
    "ASSUMES",
]


@router.get("/paths/{from_id}/{to_id}", response_model=ApiResponse[ShortestPathResult])
async def shortest_path(
    from_id: str,
    to_id: str,
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    max_depth: int = Query(default=6, ge=1, le=10),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ShortestPathResult]:
    """Find the shortest path between two nodes in the tenant graph."""
    # from_id and to_id are ArangoDB _ids (e.g. "resources/abc123")
    edges_str = ", ".join(_GRAPH_EDGES)
    aql = f"""
    LET from_doc = DOCUMENT(@from_id)
    LET to_doc = DOCUMENT(@to_id)
    FILTER from_doc != null AND to_doc != null
    FILTER from_doc.tenant_id == @tid AND to_doc.tenant_id == @tid
    FOR v, e IN OUTBOUND SHORTEST_PATH @from_id TO @to_id
        {edges_str}
        RETURN {{vertex: v, edge: e}}
    """
    try:
        rows = list(
            db.aql.execute(
                aql,
                bind_vars={"from_id": from_id, "to_id": to_id, "tid": x_tenant_id},
                max_runtime=15,
            )
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Path query failed: {exc}") from exc

    if not rows:
        return ApiResponse(data=ShortestPathResult(found=False, hops=0, vertices=[], edges=[]))

    vertices = [r["vertex"] for r in rows if r.get("vertex")]
    edges = [r["edge"] for r in rows if r.get("edge")]
    return ApiResponse(data=ShortestPathResult(found=True, hops=len(edges), vertices=vertices, edges=edges))


# ── Exposure Summary ──────────────────────────────────────────────────────────


@router.get("/exposure", response_model=ApiResponse[ExposureSummary])
async def exposure_summary(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ExposureSummary]:
    """Return internet exposure summary for the tenant."""
    summary = get_exposure_summary(db, x_tenant_id)
    return ApiResponse(data=ExposureSummary(**summary))
